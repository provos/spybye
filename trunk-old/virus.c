/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <event.h>

#include "virus.h"
#include "spybye.gen.h"

ssize_t atomicio(ssize_t (*f) (), int fd, void *_s, size_t n);

static struct cl_node *engine = NULL;
static struct virusq children;
static struct scanctxq scans;

static struct virus_child *virus_child_new();

#ifndef HAVE_CLAMAV
int virus_init(void) {
	return (-1);
}
static const char *
clamav_scan_buffer(char *data, int length) {
	return "error";
}
#else
#include <clamav.h>

/* 
 * initalize the virus scanning system; this really mixes clamav and our
 * generic frame work but that does not matter for now
 */

int
virus_init(void)
{
	int res = 0, i;
	unsigned int sigs = 0;

	res = cl_loaddbdir(cl_retdbdir(), &engine, &sigs);
	if (res) {
		fprintf(stderr, "[VIRUS] Failed to load clamav: %s\n",
		    cl_strerror(res));
		return (-1);
	}

	res = cl_build(engine);
	if (res) {
		fprintf(stderr, "[VIRUS] Failed to build engine: %s\n",
		    cl_strerror(res));
		return (-1);
	}

	fprintf(stderr, "[VIRUS] Loaded %d signatures\n", sigs);

	TAILQ_INIT(&children);
	TAILQ_INIT(&scans);

	for(i = 0; i < NUM_VIRUS_CHILDREN; ++i)
		virus_child_new();

	return (0);
}

static const char *
clamav_scan_buffer(char *data, int length)
{
	const char *virname;
	struct cl_limits limits;
	int res;

	/* somewhat stupid but here we go */
	FILE *fp = tmpfile();
	if (fp == NULL)
		return ("error");

	if (atomicio(write, fileno(fp), data, length) != length) {
		fclose(fp);
		return ("error");
	}
	rewind(fp);

	memset(&limits, 0, sizeof(limits));
	limits.maxfiles = 1000;
	limits.maxfilesize = 10 * 1048576;
	limits.maxreclevel = 5;
#ifdef HAVE_CLLIMITS_MAXMAILREC
	limits.maxmailrec = 64;
#endif
	limits.maxratio = 200;

	res = cl_scandesc(fileno(fp), &virname, NULL, engine,
	    &limits, CL_SCAN_STDOPT);
	fclose(fp);

	if (res == CL_VIRUS)
		return (virname);
	else if (res == CL_CLEAN)
		return ("clean");

	return ("error");
}
#endif

/* happens in the child */

static void
virus_process(int fd, struct virusscan *vs)
{
	struct virusresult *vr;
	struct evbuffer *data;
	u_int8_t *buffer;
	u_int32_t buflen;
	u_int8_t *context;
	u_int32_t conlen;
	const char *result;
	int res;

	EVTAG_GET(vs, buffer, &buffer, &buflen);
	EVTAG_GET(vs, context, &context, &conlen);

	result = clamav_scan_buffer((char *)buffer, buflen);
	fprintf(stderr, "[VIRUS] Scanned %d bytes; result: %s\n",
	    buflen, result);

	vr = virusresult_new();
	assert(vr != NULL);
	EVTAG_ASSIGN(vr, result, result);
	EVTAG_ASSIGN(vr, context, context, conlen);

	data = evbuffer_new();
	assert(data != NULL);
	evtag_marshal_virusresult(data, VIRUSRESULT_TAG, vr);
	virusresult_free(vr);

	res = atomicio(write, fd, EVBUFFER_DATA(data), EVBUFFER_LENGTH(data));
	if (res != EVBUFFER_LENGTH(data)) {
		fprintf(stderr, "[VIRUS] Write of results failed: %ld got %d\n",
		    EVBUFFER_LENGTH(data), res);
		exit(1);
	}
	
	evbuffer_free(data);
}

static void
virus_child_processing(int fd)
{
	struct evbuffer *data = evbuffer_new();
	assert(data != NULL);

	do {
		u_int32_t length;

		int res = evbuffer_read(data, fd, -1);
		if (res == 0)
			break;
		if (res == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}

		while (evtag_peek_length(data, &length) != -1) {
			struct virusscan *vs;

			if (EVBUFFER_LENGTH(data) < length)
				break;

			if ((vs = virusscan_new()) == NULL)
				err(1, "malloc");
			if (evtag_unmarshal_virusscan(
				    data, VIRUSSCAN_TAG, vs) == -1) {
				fprintf(stderr, "[VIRUS] Corrupt message\n");
				exit(1);
			}

			/* okay - do something here */
			virus_process(fd, vs);

			virusscan_free(vs);
		}
	} while (1);
}

static void
virus_result(struct virusresult *vr)
{
	struct scanctx *ctx;
	struct scanctx *wanted;
	u_char *buf;
	u_int buflen;
	char *result;

	EVTAG_GET(vr, result, &result);
	EVTAG_GET(vr, context, &buf, &buflen);
	assert(buflen == sizeof(wanted));
	memcpy(&wanted, buf, buflen);

	TAILQ_FOREACH(ctx, &scans, next) {
		if ((void *)ctx == (void *)wanted)
			break;
	}

	if ((void *)ctx != (void *)wanted)
		return;

	TAILQ_REMOVE(&scans, ctx, next);

	(*ctx->cb)(result, ctx->cb_arg);

	free(ctx);
}

/* called if we can read scan results */

static void
virus_readcb(struct bufferevent *bev, void *arg)
{
	u_int32_t length;
	while (evtag_peek_length(bev->input, &length) != -1) {
		struct virusresult *vr;

		if (EVBUFFER_LENGTH(bev->input) < length)
			break;

		if ((vr = virusresult_new()) == NULL)
			err(1, "malloc");
		if (evtag_unmarshal_virusresult(
			    bev->input, VIRUSRESULT_TAG, vr) == -1) {
			/* this really means that we need to kill the child */
			fprintf(stderr, "[VIRUS] Corrupt message\n");
			exit(1);
		}

		/* okay - do something here */
		virus_result(vr);

		virusresult_free(vr);
	}
}

/* called if we can write more data */

static void
virus_writecb(struct bufferevent *bev, void *arg)
{
	bufferevent_disable(bev, EV_WRITE);
}

/* let's hope we don't get any errors */

static void
virus_errorcb(struct bufferevent *bev, short what, void *arg)
{
	/* this means that we need to kill the child */
}

static struct virus_child *
virus_child_new()
{
	struct virus_child *child;
	int pair[2];

	if ((child = calloc(1, sizeof(struct virus_child))) == NULL)
		err(1, "calloc");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		err(1, "socketpair");

	/* should make the system automatically reap child processes */
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	if ((child->pid = fork()) == -1)
		err(1, "fork");

	if (child->pid == 0) {
		/* running in the child */
		close(pair[0]);
		virus_child_processing(pair[1]);
		exit(0);
	}

	close(pair[1]);
	child->fd = pair[0];
	child->bev = bufferevent_new(child->fd, 
		virus_readcb, virus_writecb, virus_errorcb,
		child);
	if (child->bev == NULL)
		err(1, "bufferevent_new");
	
	TAILQ_INSERT_TAIL(&children, child, next);

	bufferevent_enable(child->bev, EV_READ);

	return (child);
}

/* 
 * send something to our children; when the scan is done the specified
 * callback is going to be executed.
 */

void
virus_scan_buffer(char *buffer, size_t buflen,
    void (*cb)(const char *, void *), void *cb_arg)
{
	struct scanctx *ctx = calloc(1, sizeof(struct scanctx));
	struct virusscan *vs = virusscan_new();
	struct evbuffer *data = evbuffer_new();
	struct virus_child *child;
	assert(ctx != NULL);
	assert(vs != NULL);
	assert(data != NULL);

	ctx->cb = cb;
	ctx->cb_arg = cb_arg;

	TAILQ_INSERT_TAIL(&scans, ctx, next);

	/* okay now prepare the actual scan job */
	EVTAG_ASSIGN(vs, buffer, (u_char *)buffer, buflen);
	EVTAG_ASSIGN(vs, context, (u_char *)&ctx, sizeof(ctx));

	/* weeh - double copy for our convenience */
	evtag_marshal_virusscan(data, VIRUSSCAN_TAG, vs);

	virusscan_free(vs);

	/* get the first available child */
	child = TAILQ_FIRST(&children);
	assert(child != NULL);
	TAILQ_REMOVE(&children, child, next);
	TAILQ_INSERT_TAIL(&children, child, next);

	bufferevent_write_buffer(child->bev, data);
	bufferevent_enable(child->bev, EV_WRITE);
	evbuffer_free(data);
}
