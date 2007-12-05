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
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

#include <event.h>
#include <evhttp.h>

#include "proxy.h"
#include "status.h"

char *strncasestr(const char *s, const char *find, size_t slen);

/*
 * Determines the location at which we want to inject our JavaScript
 */
static char *
find_pointer(char *data, size_t data_len) {
	struct _findp {
		char *what;
		/* 
		 * -1 before,
		 * +1 after
		 * 0 do not inject!
		 */
		int before;
	} findp[] = {
		{ "<head>", 1},
		{ "<body", -1},
		{ "<html>", 1},
		{ "<?xml", 0 },
		{ NULL, 0 }
	};

	struct _findp *where;

	for (where = &findp[0]; where->what != NULL; ++where) {
		char *p = strncasestr(data, where->what, data_len);
		if (p != NULL) {
			if (where->before == 1)
				p += strlen(where->what);
			else if (where->before == 0)
				return (NULL);

			return (p);
		}
	}

	return (data);
}

void
inject_control_javascript(struct evbuffer *buffer)
{
	struct evbuffer *scratch = evbuffer_new();
	char *data, *p;
	size_t data_len, prefix_len;
	assert(scratch != NULL);

	/* simple swap */
	evbuffer_add_buffer(scratch, buffer);
	
	data = (char *)EVBUFFER_DATA(scratch);
	data_len = EVBUFFER_LENGTH(scratch);

	/* try to find the html tag */
	p = find_pointer(data, data_len);
	if (p == NULL) {
		/* 
		 * although, the content typed said text/html, we can't inject
		 * here.  for example, if the response looks like xml data.
		 */
		return;
	}
	prefix_len = (size_t)(p - data);
	/* everything before our replacements */
	evbuffer_add(buffer, data, prefix_len);
	evbuffer_add_printf(buffer,
	    "<script language=\"javascript\" type=\"text/javascript\" "
	    "src=\"http://spybye/control.js\"></script>");
	evbuffer_add(buffer, data + prefix_len, data_len - prefix_len);
	evbuffer_free(scratch);
}

/* here is how we deliver our little control component */
static char *control_js =
#include "sarissa.js.h"
#include "control.js.h"
    ;

void
serve_control_javascript(struct evhttp_request *request, void *arg)
{
	struct evbuffer *databuf = evbuffer_new();
	assert(databuf != NULL);
	evhttp_add_header(request->output_headers,
	    "Content-Type", "text/javascript");
	evbuffer_add(databuf, control_js, strlen(control_js));

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
handle_result_callback(struct site *site, void *arg)
{
	struct evhttp_request *request = arg;
	struct evbuffer *data = evbuffer_new();
	int done = site->flags & ANALYSIS_COMPLETE;

	/* XXX - do the right thing here */
	evhttp_add_header(request->output_headers,
	    "Content-Type", "text/xml");

	evbuffer_add_printf(data,
	    "<xmlresponse>"
	    "<danger>%s</danger>"
	    "<complete>%s</complete>"
	    "</xmlresponse>",
	    danger_to_text(site_analyze_danger(site)),
	    done ? "complete" : "pending"
	    );

	evhttp_send_reply(request, HTTP_OK, "OK", data);
	evbuffer_free(data);
}

void
handle_proxy_callback(struct evhttp_request *request, void *arg)
{
	struct site *site;
	char *data, *url;
	int length;

	fprintf(stderr, "[PROXY] Received control callback from %s\n",
	    request->remote_host);

	data = (char *)evbuffer_find(request->input_buffer,
	    (unsigned char *)"site=", 5);
	if (data == NULL)
		goto error;

	length = EVBUFFER_LENGTH(request->input_buffer) - 5;
	url = malloc(length + 1);
	assert(url != NULL);
	memcpy(url, data + 5, length);
	url[length] = '\0';

	site = site_find(url);
	if (site == NULL) {
		free(url);
		goto error;
	}

	fprintf(stderr, "[PROXY] Control callback for site %s\n", url);

	/* break the link to the parent, as this is a new page */
	site_disassociate_parent(site);

	if (site->danger == DANGEROUS) {
		/* the control callback sometimes arrives later */
		handle_result_callback(site, request);
	} else {
		site_insert_callback(site, handle_result_callback, request);
	}

	free(url);
	return;

error:
	/* no data that we can understand */
	evhttp_send_error(request, HTTP_SERVUNAVAIL, "Unknown error");
	return;
}
