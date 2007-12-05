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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <md5.h>

#include <event.h>
#include <evhttp.h>

#include "spybye.gen.h"
#include "utils.h"
#include "status.h"
#include "log.h"

ssize_t atomicio(ssize_t (*f) (), int fd, void *_s, size_t n);
static int log_report_direct(int log_fd, struct evhttp_request *request,
    struct dangerousload *dl);

/* for sharing reports of dangerous connections */
struct spybye_share spybye_share;

struct dangerq danger;
static int danger_init;

static void
init_danger(void)
{
	if (!danger_init) {
		danger_init = 1;
		TAILQ_INIT(&danger);
	}
}

int
log_init(const char *filename)
{
	int fd;

	init_danger();

	fd = open(filename, O_RDWR|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
	if (fd == -1)
		return (-1);

	return (fd);
}

void
log_close(int fd)
{
	close(fd);
}

struct dangerousload *
log_dl_from_request(struct evhttp_request *req, struct site *site)
{
	struct dangerousload *dl = dangerousload_new();
	struct timeval tv;

	/* we don't like error handling */
	assert(dl != NULL);

	gettimeofday(&tv, NULL);
	EVTAG_ASSIGN(dl, time_in_seconds, tv.tv_sec);
	EVTAG_ASSIGN(dl, parent_url,
	    evhttp_find_header(req->input_headers, "Referer"));
	EVTAG_ASSIGN(dl, dangerous_url, req->uri);

	if (site->virus_result != NULL)
		EVTAG_ASSIGN(dl, virus_result, site->virus_result);

	if (site->html_data != NULL) {
		unsigned char digest[16];
		MD5_CTX ctx;
		MD5Init(&ctx);
		MD5Update(&ctx,
		    (unsigned char *)site->html_data, site->html_size);
		MD5Final(digest, &ctx);
		EVTAG_ASSIGN(dl, digest, digest);
	}

	return (dl);
}

/*
 * encapsulates the dangerousload into a report object that also
 * contains the IP address of the client who created the report.
 */

void
log_dangerous_report(int log_fd, struct evhttp_request *req, struct site *site)
{
	struct dangerousload *dl = log_dl_from_request(req, site);
	log_report_direct(log_fd, req, dl);
	dangerousload_free(dl);
}

/*
 * logs information only about the parent and the dangerous URL.
 */

void
log_dangerous_request(int log_fd, struct evhttp_request *req, struct site *site)
{
	struct dangerous_container *dc =
	    malloc(sizeof(struct dangerous_container));
	struct dangerousload *dl = log_dl_from_request(req, site);
	struct evbuffer *data = evbuffer_new();

	/* we don't like error handling */
	assert(data != NULL);
	assert(dc != NULL);

	evtag_marshal_dangerousload(data, DANGEROUS_TAG, dl);

	/* let's check if we should share it */
	if (spybye_share.evcon_report != NULL)
		log_share_report(&spybye_share, data);


	atomicio(write, log_fd, EVBUFFER_DATA(data), EVBUFFER_LENGTH(data));
	fsync(log_fd);
	evbuffer_free(data);

	dc->dl = dl;
	TAILQ_INSERT_HEAD(&danger, dc, next);
}

int
log_dangerous_read(const char *filename)
{
	struct evbuffer *data;
	int count = 0;
	
	int fd = open(filename, O_RDONLY, 0);
	if (fd == -1)
		return (-1);

	init_danger();

	if ((data = evbuffer_new()) == NULL)
		err(1, "malloc");

	fprintf(stderr, "[STATE] Reading previous state from %s\n", filename);

	while (evbuffer_read(data, fd, -1) > 0) {
		u_int32_t length;

		while (evtag_peek_length(data, &length) != -1) {
			struct dangerousload *dl;
			struct dangerous_container *dc;

			if (EVBUFFER_LENGTH(data) < length)
				break;

			count++;

			if ((dl = dangerousload_new()) == NULL)
				err(1, "malloc");

			if (evtag_unmarshal_dangerousload(data, DANGEROUS_TAG,
				dl) == -1) {
				dangerousload_free(dl);
				fprintf(stderr, "[STATE] Skipping message %d\n",
				    count);
				continue;
			}
		
			dc = malloc(sizeof(struct dangerous_container));
			if (dc == NULL)
				err(1, "malloc");

			dc->dl = dl;
			TAILQ_INSERT_HEAD(&danger, dc, next);
		}
	}

	fprintf(stderr, "[STATE] ... read %d messages\n", count);

	close(fd);

	evbuffer_free(data);
	return (0);
}

static void
log_share_done(struct evhttp_request *req, void *arg)
{
	/* just ignore */
}

void
log_share_report(struct spybye_share *share, struct evbuffer *data)
{
	struct evhttp_request *request;

	/* queue the request on our sharing connection */
	request = evhttp_request_new(log_share_done, NULL);
	if (request == NULL)
		return;

	evhttp_add_header(request->output_headers,
	    "Host", share->host);
	evhttp_add_header(request->output_headers,
	    "Content-Type", "application/octet-stream");
	evhttp_add_header(request->output_headers,
	    "User-Agent", USER_AGENT);

	evbuffer_add(request->output_buffer,
	    EVBUFFER_DATA(data), EVBUFFER_LENGTH(data));

	evhttp_make_request(share->evcon_report,
	    request, EVHTTP_REQ_POST, share->uri);
}

void
log_establish_sharing(struct spybye_share *share, const char *url)
{
	static char real_host[1024];
	char *host, *uri;
	u_short port;
			
	if (http_hostportfile((char *)url, &host, &port, &uri) == -1)
		goto fail;

	if (port != 80) {
		snprintf(real_host, sizeof(real_host), "%s:%d", host, port);
	} else {
		strlcpy(real_host, host, sizeof(real_host));
	}

	if ((share->host = strdup(real_host)) == NULL)
		err(1, "strdrup");

	if ((share->uri = strdup(uri)) == NULL)
		err(1, "strdup");

	share->evcon_report = evhttp_connection_new(host, port);
	if (share->evcon_report == NULL)
		goto fail;

	fprintf(stderr, "[REPORT] Report sharing enabled.\n");
	return;

fail:
	fprintf(stderr, "[REPORT] Could not create sharing connection to %s\n",
	    url);
	return;
}

/*
 * logs external reports that other users have submitted.
 */

static int
log_report_direct(int log_fd, struct evhttp_request *request,
    struct dangerousload *dl)
{
	struct evbuffer *databuf = NULL;
	struct dangerous_report *dr = NULL;
	struct timeval tv;

	if ((dr = dangerous_report_new()) == NULL)
		goto fail;

	if ((databuf = evbuffer_new()) == NULL)
		goto fail;

	gettimeofday(&tv, NULL);
	EVTAG_ASSIGN(dr, time_in_seconds, tv.tv_sec);
	EVTAG_ASSIGN(dr, remote_ip, request->remote_host);
	EVTAG_ASSIGN(dr, report, dl);

	evtag_marshal_dangerous_report(databuf, DANGEROUS_REPORT_TAG, dr);
	atomicio(write, log_fd,
	    EVBUFFER_DATA(databuf), EVBUFFER_LENGTH(databuf));
	fsync(log_fd);

	dangerous_report_free(dr);
	evbuffer_free(databuf);
	
	return (0);

fail:
	if (databuf)
		evbuffer_free(databuf);
	if (dr)
		dangerous_report_free(dr);

	return (-1);
}

void
log_external_report(int log_fd, struct evhttp_request *request)
{
	struct evbuffer *databuf = NULL;
	struct dangerousload *dl = NULL;

	if (request == NULL)
		return;

	fprintf(stderr, "[REPORT] Received report from %s\n",
	    request->remote_host);

	/* try to parse the report */
	dl = dangerousload_new();
	if (dl == NULL)
		goto fail;

	if (evtag_unmarshal_dangerousload(request->input_buffer,
		DANGEROUS_TAG, dl) == -1) {
		fprintf(stderr, "[REPORT] Malformed message from %s\n",
		    request->remote_host);
		goto fail;
	}

	if (log_report_direct(log_fd, request, dl) == -1)
		goto fail;

	if ((databuf = evbuffer_new()) == NULL)
		goto fail;

	dangerousload_free(dl);
	
	evbuffer_add_printf(databuf, "%s: you are ok", request->remote_host);
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);

	evbuffer_free(databuf);
	return;
fail:
	if (databuf)
		evbuffer_free(databuf);
	if (dl)
		dangerousload_free(dl);
	evhttp_send_error(request, HTTP_BADREQUEST, "Bad Request");
}

/* functions for logging to console or syslog */

static void
_log(int level, const char *fmt, va_list args)
{
	vsyslog(level, fmt, args);
}

static void
log_variable(int level, const char *fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);
	_log(level, fmt, ap);
	va_end(ap);
}

void
log_request(int level, struct evhttp_request *request, struct site *site)
{
	const char *referer, *useragent;
	const char *danger, *virus;
	referer = evhttp_find_header(request->input_headers, "Referer");
	if (referer == NULL)
		referer = "-";
	useragent = evhttp_find_header(request->input_headers, "User-Agent");
	if (useragent == NULL)
		useragent = "-";

	if (site != NULL) {
		danger = danger_to_text(site->danger);
		if (site->virus_result != NULL)
			virus = site->virus_result;
		else
			virus = "-";
	} else {
		danger = "-";
		virus = "-";
	}

	log_variable(LOG_INFO, "%s \"%s\" \"%s\" \"%s\" %s %s",
	    request->remote_host,
	    request->uri,
	    referer, useragent,
	    danger, virus);
}
