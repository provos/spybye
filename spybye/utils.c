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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <event.h>
#include <evhttp.h>

#include "utils.h"

extern int debug;

/* Separated host, port and file from URI */

int
http_hostportfile(const char *url, char **phost, u_short *pport, char **pfile)
{
	static int off;
	static char shost[2][1024];
	static char sfile[2][1024];
	char *p, *p2;
	int len;
	u_short port;

	if (++off > 1) off = 0;

	len = strlen(HTTP_PREFIX);
	if (strncasecmp(url, HTTP_PREFIX, len))
		return (-1);

	url += len;

	/* We might overrun */
	if (strlcpy(shost[off], url, sizeof(shost[off])) >= sizeof(shost[off]))
		return (-1);

	p = strchr(shost[off], '/');
	if (p != NULL) {
		*p = '\0';
		p2 = p + 1;
	} else
		p2 = NULL;

	if (pfile != NULL) {
		/* Generate request file */
		if (p2 == NULL)
			p2 = "";
		snprintf(sfile[off], sizeof(sfile[off]), "/%s", p2);
	}

	p = strchr(shost[off], ':');
	if (p != NULL) {
		*p = '\0';
		port = atoi(p + 1);

		if (port == 0)
			return (-1);
	} else
		port = HTTP_DEFAULTPORT;

	if (phost != NULL)
		*phost = shost[off];
	if (pport != NULL)
		*pport = port;
	if (pfile != NULL)
		*pfile = sfile[off];

	return (0);
}

/* match a url against a pattern */
int
match_url(const char *url, const char *pattern_host, const char *pattern_uri)
{
	char *host, *uri;
	u_short port;

	if (http_hostportfile((char *)url, &host, &port, &uri) == -1)
		return (0);

	if (strlen(pattern_host) > strlen(host))
		return (0);

	if (pattern_uri != NULL && strlen(pattern_uri) > strlen(uri))
		return (0);

	if (strcasecmp(host + strlen(host) - strlen(pattern_host),
		pattern_host))
		return (0);

	if (pattern_uri == NULL)
		return (1);

	return (strncasecmp(uri, pattern_uri, strlen(pattern_uri)) == 0);
}

struct evbuffer *
read_data(const char *filename)
{
	struct stat sb;
	struct evbuffer *data = evbuffer_new();
	int fd;
	assert(data != NULL);
	
	if (stat(filename, &sb) == -1)
		err(1, "stat(%s)", filename);

	fd = open(filename, O_RDONLY, 0);
	if (fd == -1)
		err(1, "open(%s)", filename);

	if (evbuffer_read(data, fd, sb.st_size) != sb.st_size)
		err(1, "read(%s)", filename);
	close(fd);

	return (data);
}

static void
read_from_web_done(struct evhttp_request *req, void *arg)
{
	struct evbuffer *data = *(struct evbuffer **)arg;

	if (req == NULL || req->response_code != HTTP_OK)
		errx(1, "Request failed");

	if (EVBUFFER_LENGTH(req->input_buffer) == 0)
		errx(1, "Empty request");

	/* all the magic is done now */
	evbuffer_add_buffer(data, req->input_buffer);

	event_loopexit(NULL);
}

struct evhttp_connection *
read_from_web_prepare(const char *url,
    void (*cb)(struct evhttp_request *, void *), void *cb_arg)
{
	struct evhttp_connection *evcon;
	struct evhttp_request *request;
	char *host, *uri;
	u_short port;

	if (http_hostportfile((char *)url, &host, &port, &uri) == -1)
		errx(1, "Cannot parse url %s", url);

	evcon = evhttp_connection_new(host, port);
	fprintf(stderr, "[PATTERN] Making connection to %s:%d for %s\n",
	    host, port, uri);
	if (evcon == NULL)
		errx(1, "Cannot establish connection to %s:%d", host, port);

	/* we got the connection now - queue the request */
	request = evhttp_request_new(cb, cb_arg);
	if (request == NULL)
		errx(1, "Failed to make request object");

	evhttp_add_header(request->output_headers, "Connection", "close");
	evhttp_add_header(request->output_headers, "Host", host);
	evhttp_add_header(request->output_headers, "User-Agent", USER_AGENT);
	evhttp_make_request(evcon, request, EVHTTP_REQ_GET, uri);
	
	return (evcon);
}

struct evbuffer *
read_from_web(const char *url)
{
	struct evbuffer *data = evbuffer_new();
	struct evhttp_connection *evcon;

	assert(data != NULL);

	evcon = read_from_web_prepare(url, read_from_web_done, &data);

	event_dispatch();
	
	evhttp_connection_free(evcon);

	fprintf(stderr, "[PATTERN] Received %ld bytes from %s\n",
	    EVBUFFER_LENGTH(data), url);

	return (data);
}

/* some really idiotic tricks to make javascript not escape our iframe */
static struct replacement_ {
	char *src;
	char *replace;
} replacements[] = {
	{ "top.location = self.location",
	  "top-location = self.location" },
	{ "(top == self)",
	  "(top != self)" },
	{ "(self == top)",
	  "(self != top)" },
	{ "(top != self)",
	  "(top == self)" },
	{ "(self != top)",
	  "(self == top)" },
	{ "window.frames.length=0;",
	  "window_frames_length=0;" },
	{ "top.location=self.document.location;",
	  "top_location=self.document.location;" },
	{ "(top.frames.length!=0)",
	  "(top.frames.length==0)" },
	{ "(top.frames.length==0)",
	  "(top.frames.length!=0)" },
	{ "self.parent.location=",
	  "self_parent_location=" },
	{ "(self.parent.frames.length!=0)",
	  "(self.parent.frames.length==0)", },
	{ "(self.parent.frames.length==0)",
	  "(self.parent.frames.length!=0)", },
	{ "document.location.href=",
	  "document_location_href=", },
	{ NULL, NULL }
};

static char *
make_next_replacement(char *start, char *end)
{
	struct replacement_ *p;
	char *next = NULL, *replace = NULL;
	for (p = &replacements[0]; p->src != NULL; ++p) {
		char *found;

		found = strnstr((char *)start, p->src, (int)(end - start));
		if (next == NULL || (found != NULL && found < next)) {
			next = found;
			replace = p->replace;
		}
	}

	if (next == NULL)
		return (NULL);

	/* do the replacement if we have a match */
	memcpy(next, replace, strlen(replace));
	next += strlen(replace);

	if (next >= end)
		return (NULL);

	return (next);
}

void
sanitize_content(struct evhttp_request *req)
{
	struct evbuffer *data = req->input_buffer;
	char *start, *end;

	if (data == NULL || EVBUFFER_DATA(data) == NULL)
		return;

	start = (char *)EVBUFFER_DATA(data);
	end = (char *)EVBUFFER_DATA(data) + EVBUFFER_LENGTH(data);

	while ((start = make_next_replacement(start, end)) != NULL) {
		/* we are doing nothing */
	}
}

static const char *private_prefixes[] = {
	"10.",
	"127.",
	"192.168.",
	NULL
};

int
check_private_ip(void *arg, int count)
{
	struct in_addr *address = (struct in_addr *)arg;

	while (count--) {
		char *ip_addr = inet_ntoa(*address++);
		const char **p;

		/* is this even possible? */
		if (ip_addr == NULL)
			return (1);

		for (p = &private_prefixes[0]; *p != NULL; p++) {
			if (strncmp(ip_addr, *p, strlen(*p)) == 0)
				return (1);
		}
	}

	return (0);
}
