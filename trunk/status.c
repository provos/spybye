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

#include "spybye.gen.h"
#include "status.h"
#include "utils.h"
#include "log.h"
#include "proxy.h"

extern int debug;

struct stats statistics;

static struct pattern_obj good_patterns;
static struct pattern_obj bad_patterns;

static int status_patterns(struct pattern_obj *data, struct evbuffer *databuf);
static void site_print_analysis(struct evbuffer *databuf, struct site *site);
static void inform_cache_notfound(struct evhttp_request *request,
    const char *url);

/* structure where we keep track of sites */

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

int
site_compare(struct site *a, struct site *b)
{
	static char atmp[HTTP_MAX_URL], btmp[HTTP_MAX_URL];
	char *a_url, *b_url;
	char *a_slash, *b_slash;
	int host_len, res;
	assert(strlen(a->url) >= sizeof(HTTP_PREFIX));
	assert(strlen(b->url) >= sizeof(HTTP_PREFIX));

	a_url = a->url;
	b_url = b->url;
	a_slash = strchr(a_url + sizeof(HTTP_PREFIX), '/');
	b_slash = strchr(b_url + sizeof(HTTP_PREFIX), '/');
	if (a_slash == NULL) {
		snprintf(atmp, sizeof(atmp), "%s/", a_url);
		a_url = atmp;
		a_slash = strchr(a_url + sizeof(HTTP_PREFIX), '/');
		assert(a_slash != NULL);
	}

	if (b_slash == NULL) {
		snprintf(btmp, sizeof(btmp), "%s/", b_url);
		b_url = btmp;
		b_slash = strchr(b_url + sizeof(HTTP_PREFIX), '/');
		assert(b_slash != NULL);
	}

	host_len = MIN((int)(a_slash - a_url), (int)(b_slash - b_url));
	res = strncasecmp(a_url, b_url, host_len);
	if (res)
		return (res);

	return strcmp(a_slash, b_slash);
}

static SPLAY_HEAD(site_tree, site) root;

SPLAY_PROTOTYPE(site_tree, site, node, site_compare);
SPLAY_GENERATE(site_tree, site, node, site_compare);

static int
find_url_in_patterns(struct patternq* head, const char *url)
{
	struct pattern *entry;
	TAILQ_FOREACH(entry, head, next) {
		if (match_url(url, entry->pattern_host, entry->pattern_uri))
			return (1);
	}

	return (0);
}

int 
site_same_as_parent(struct site *site)
{
	static char parent_host[1024];
	struct site *parent = site->parent;
	char *host, *uri;
	u_short port;

	if (parent == NULL)
		return (1);

	while (parent) {
		if (parent->parent == NULL)
			break;
		parent = parent->parent;
	}

	if (http_hostportfile(parent->url, &host, &port, &uri) == -1)
		return (0);
	strlcpy(parent_host, host, sizeof(parent_host));

	return (match_url(site->url, parent_host, NULL));
}

/*
 * Returns true if the site itself matches the bad patterns list
 */

int
site_matches_bad_patterns(struct site *site)
{
	return (find_url_in_patterns(&good_patterns.head, site->url));
}

enum DANGER_TYPES
site_child_danger(struct site *site)
{
	enum DANGER_TYPES danger = UNKNOWN;

	if (site_same_as_parent(site))
		danger = HARMLESS;

	if (find_url_in_patterns(&good_patterns.head, site->url))
		danger = HARMLESS;
	if (find_url_in_patterns(&bad_patterns.head, site->url))
		danger = DANGEROUS;

	return (danger);
}

enum DANGER_TYPES
site_recurse_danger(struct site* site)
{
	enum DANGER_TYPES danger = site->danger;
	struct site *child;

	TAILQ_FOREACH(child, &site->children, next) {
		enum DANGER_TYPES cur = site_recurse_danger(child);
		if (cur > danger)
			danger = cur;
	}

	return (danger);
}

enum DANGER_TYPES
site_analyze_danger(struct site *site)
{
	enum DANGER_TYPES danger = HARMLESS;
	struct site *child;

	if (site->parent != NULL)
		return site_child_danger(site);

	if (site->html_size == 0 && TAILQ_FIRST(&site->children) == NULL)
		return (UNKNOWN);

	TAILQ_FOREACH(child, &site->children, next) {
		enum DANGER_TYPES cur = site_recurse_danger(child);
		if (cur > danger)
			danger = cur;
	}

	/* find the highest danger of children for the root */

	return (danger);
}

static void
site_dispatch_callbacks(struct site *site)
{
	struct site_callback *cb;
	while ((cb = TAILQ_FIRST(&site->callbacks)) != NULL) {
		DNFPRINTF(1, (stderr, "[DEBUG] Dispatching callbacks for %s\n",
			site->url));
		TAILQ_REMOVE(&site->callbacks, cb, next);
		(*cb->cb)(site, cb->cb_arg);
		free(cb);
	}
}

/*
 * makes everything up the tree dangerous
 * XXX: is this the right thing to do???
 */

void
site_make_dangerous(struct site *site)
{
	/* trigger the callbacks up the tree */
	while (site) {
		DNFPRINTF(1, (stderr, "[DEBUG] Making %s dangerous\n",
			site->url));
		site->danger = DANGEROUS;

		site_dispatch_callbacks(site);
		site = site->parent;
	}
}

int
site_count_dangerous(struct site *site)
{
	struct site *child;
	int total = 0;

	TAILQ_FOREACH(child, &site->children, next) {
		total += site_count_dangerous(child);
	}

	if (site->danger == DANGEROUS)
		total += 1;

	return (total);
}

void
site_complete(int fd, short what, void *arg)
{
	struct site *site = arg;
	struct timeval tv;

	site->danger = site_analyze_danger(site);

	gettimeofday(&tv, NULL);
	timersub(&tv, &site->tv_change, &tv);
	assert(site->tv_change.tv_sec);
	if (tv.tv_sec >= IDLE_TIME) {
		DNFPRINTF(1, (stderr, "[DEBUG] Analysis for %s complete\n",
			site->url));
		site->flags |= ANALYSIS_COMPLETE;
		site_dispatch_callbacks(site);
	} else {
		timerclear(&tv);
		tv.tv_sec = 1;
		evtimer_add(&site->ev_complete, &tv);
	}
}

void
site_expire(int fd, short what, void *arg)
{
	struct site *site = arg;

	fprintf(stderr, "[STATE] Expiring %s\n", site->url);
	site_free(site);
}

void
site_change_time(struct site *parent, struct timeval *tv)
{
	while (parent != NULL) {
		/* only expire from the top */
		if (parent->parent == NULL) {
			struct timeval tv_timeout;
			/* update the expiration time */
			timerclear(&tv_timeout);
			tv_timeout.tv_sec = STATE_EXPIRATION_TIME;

			evtimer_add(&parent->ev_timeout, &tv_timeout);
		}

		parent->tv_change = *tv;
		parent = parent->parent;
	}
}

void
site_disassociate_parent(struct site *site)
{
	struct timeval tv;
	struct site *parent = site->parent;
	extern int behave_as_proxy;

	if (parent == NULL)
		return;

	TAILQ_REMOVE(&parent->children, site, next);
	site->parent = NULL;
	
	/* make sure that we get an expiration time for this site */
	gettimeofday(&tv, NULL);
	site_change_time(site, &tv);

	/* if we are not a proxy, we want a completion time on every page */
	if (!behave_as_proxy &&
	    (site->flags & ANALYSIS_COMPLETE) == 0 &&
	    !event_pending(&site->ev_complete, EV_TIMEOUT, NULL)) {
		site_complete(-1, 0, site);
	}

}

struct site *
site_find(const char *url)
{
	struct site tmp;

	tmp.url = (char *)url;
	return (SPLAY_FIND(site_tree, &root, &tmp));
}

struct site *
site_new(const char *url, const char *parent_url)
{
	struct site *site, tmp, *parent = NULL;
	struct timeval tv;

	tmp.url = (char *)url;
	if ((site = SPLAY_FIND(site_tree, &root, &tmp)) != NULL) {
		/* we already got a match - what now? */
		goto done;
	}

	if (parent_url != NULL) {
		tmp.url = (char *)parent_url;
		parent = SPLAY_FIND(site_tree, &root, &tmp);

		/* nobody should be able to fake a request */
		if (parent == NULL)
			return (NULL);
	}

	if ((site = calloc(1, sizeof(struct site))) == NULL)
		err(1, "calloc");

	TAILQ_INIT(&site->callbacks);

	TAILQ_INIT(&site->children);
	if (parent != NULL) {
		site->parent = parent;
		TAILQ_INSERT_TAIL(&parent->children, site, next);
	}

	if ((site->url = strdup(url)) == NULL)
		err(1, "strdup");

	site->danger = site_analyze_danger(site);
	if (site->danger == DANGEROUS) {
		/* allows us to find callbacks */
		site_make_dangerous(site);
	}
	SPLAY_INSERT(site_tree, &root, site);

	evtimer_set(&site->ev_timeout, site_expire, site);
	evtimer_set(&site->ev_complete, site_complete, site);

done:
	/* update the last time a tree was updated */
	gettimeofday(&tv, NULL);
	site_change_time(site, &tv);

	return (site);
}

void
site_free(struct site *site)
{
	struct site *child;
	struct site_callback *cb;

	SPLAY_REMOVE(site_tree, &root, site);

	event_del(&site->ev_timeout);
	event_del(&site->ev_complete);

	while ((child = TAILQ_FIRST(&site->children)) != NULL) {
		TAILQ_REMOVE(&site->children, child, next);
		child->parent = NULL;
		site_free(child);
	}

	while ((cb = TAILQ_FIRST(&site->callbacks)) != NULL) {
		TAILQ_REMOVE(&site->callbacks, cb, next);
		(*cb->cb)(site, cb->cb_arg);
		free(cb);
	}

	if (site->parent) {
		TAILQ_REMOVE(&site->parent->children, site, next);
	}

	if (site->virus_result != NULL)
		free(site->virus_result);
	if (site->firstline != NULL)
		free(site->firstline);
	if (site->html_data != NULL)
		free(site->html_data);
	free(site->url);
	free(site);
}

void
site_insert_callback(struct site *site,
    void (*cb)(struct site *, void *), void *cb_arg)
{
	struct site_callback *ctx = malloc(sizeof(struct site_callback));
	assert(ctx != NULL);

	ctx->cb = cb;
	ctx->cb_arg = cb_arg;
	TAILQ_INSERT_TAIL(&site->callbacks, ctx, next);
}

#define HTML_PRINT(...) evbuffer_add_printf(databuf, __VA_ARGS__)

/* stores the data associated with this site */

void
site_cache_data(struct site *site, const struct evhttp_request *req)
{
	static char firstline[128];

	if (site->firstline != NULL)
		free(site->firstline);
	if (site->html_data != NULL)
		free(site->html_data);

	fprintf(stderr, "[CACHE] Caching %ld bytes for %s (%s)\n",
	    EVBUFFER_LENGTH(req->input_buffer),
	    site->url, danger_to_text(site->danger));

	site->html_size = EVBUFFER_LENGTH(req->input_buffer);
	site->html_data = malloc(site->html_size);
	if (site->html_data == NULL)
		err(1, "malloc");

	memcpy(site->html_data, EVBUFFER_DATA(req->input_buffer),
	    site->html_size);

	snprintf(firstline, sizeof(firstline), "HTTP/1.%d %d %s",
	    req->minor, req->response_code, req->response_code_line);
	if ((site->firstline = strdup(firstline)) == NULL)
		err(1, "strdup");
}


const char *
danger_to_text(enum DANGER_TYPES danger)
{
	switch (danger) {
	case HARMLESS:
		return "harmless";
	case DANGEROUS:
		return "dangerous";
	case UNKNOWN:
	default:
		return "unknown";
	}
}

static void
site_print_children(struct evbuffer *databuf, struct site *site,
    enum DANGER_TYPES desired_level)
{
	struct site *child;
	TAILQ_FOREACH(child, &site->children, next) {
		if (child->danger != desired_level)
			continue;

		HTML_PRINT("<li>");
		site_print_analysis(databuf, child);
		HTML_PRINT("</li>");
	}
}

static void
site_print_analysis(struct evbuffer *databuf, struct site *site)
{
	char *uri_escaped = evhttp_encode_uri(site->url);
	char *html_escaped = evhttp_htmlescape(site->url);
	HTML_PRINT("<span class=%s>%s</span> ", 
	    danger_to_text(site->danger),
	    danger_to_text(site->danger));

	HTML_PRINT(
		"<a href=\"/cache/?url=%s\" target=\"_blank\">%s</a>"
		" <span class=firstline>%s</span>"
		" <span class=virus>%s</span>",
		uri_escaped, html_escaped,
		site->firstline,
		site->virus_result != NULL ? site->virus_result : "unknown");

	free(uri_escaped);
	free(html_escaped);
	if (TAILQ_FIRST(&site->children) != NULL) {
		HTML_PRINT("<ul>");
		site_print_children(databuf, site, DANGEROUS);
		site_print_children(databuf, site, UNKNOWN);
		site_print_children(databuf, site, HARMLESS);
		HTML_PRINT("</ul>");
	}
}

/* code to display status related html */

static const char *css_style =
    ".tiny {\n"
    "  color: #bbbbcc;\n"
    "  padding: 2px 0px 0px 2px;"
    "  margin-bottom: -10em;"
    "  font-size: 0.5em;\n"
    "  font-family: Verdana, Arial;\n"
    "}\n"
    ".version {\n"
    "  width: 100%;"
    "  color: #8888bb;\n"
    "  padding: 0px 4px 2px 0px;"
    "  margin-top: -1em;"
    "  font-size: 0.5em;\n"
    "  text-align: right;\n"
    "  font-family: Verdana, Arial;\n"
    "}\n"
    ".statistics h1 {\n"
    "  padding: 3px;"
    "  font-size: small;\n"
    "  background-color: #ccccee;\n"
    "  border: 1px solid;\n"
    "}\n"
    ".about {\n"
    "  width: 90%;\n"
    "  margin: 10px;\n"
    "  background-color: #dcdcee;\n"
    "  font-family: Verdana, Arial;\n"
    "  border: 1px solid;\n"
    "  padding: 1em;\n"
    "}\n"
    ".about h1 {\n"
    "  width: 60%;\n"
    "  background-color: #ddaa66;\n"
    "  border: 1px solid;\n"
    "  margin-top: 1em;\n"
    "  padding-left: 0.5em;\n"
    "  font-size: 1em;\n"
    "}\n"
    ".about p {\n"
    "  font-size: 0.9em;\n"
    "  margin-left: 2em;\n"
    "}\n"
    ".statistics {\n"
    "  width: 80%;\n"
    "  margin: 10px;\n"
    "  background-color: #dcdcee;\n"
    "  font-family: Verdana, Arial;\n"
    "  font-size: 0.8em;\n"
    "  padding: 1em;\n"
    "}\n"
    "table.traffic {"
    "  width: 300px;"
    "  border-width: 0px 0px 1px 1px;"
    "  border-spacing: 2px;"
    "  border-style: inset;"
    "  border-color: black;"
    "  border-collapse: collapse;"
    "}"
    "table.traffic td {"
    "  border-width: 1px 1px 0px 0px;"
    "  padding: 2px;"
    "  border-style: inset;"
    "  border-color: black;"
    "  background-color: rgb(255, 250, 220);"
    "  font-family: Verdana, Arial;\n"
    "  font-size: small;\n"
    "}\n"
    "table.sites {"
    "  border-width: 0px 0px 1px 1px;"
    "  border-spacing: 2px;"
    "  border-style: inset;"
    "  border-color: black;"
    "  border-collapse: collapse;"
    "}"
    "table.sites td {"
    "  border-width: 1px 1px 0px 0px;"
    "  padding: 2px;"
    "  border-style: inset;"
    "  border-color: black;"
    "  background-color: rgb(255, 250, 220);"
    "  font-family: Verdana, Arial;\n"
    "  font-size: small;\n"
    "}\n"
    ".analysis {\n"
    "  font-family: Verdana, Arial;\n"
    "  font-size: small;\n"
    "}\n"
    ".harmless { color: green }\n"
    ".unknown { color: orange }\n"
    ".firstline {\n"
    "  font-size: 0.9em;\n"
    "  font-family: Verdana, Arial;\n"
    "  font-weight: bold }\n"
    ".virus {\n"
    "  font-size: 0.9em;\n"
    "  font-family: Verdana, Arial;\n"
    "}\n"
    ".dangerous { color: red }\n"
    ".banner {\n"
    "  background: #ddddff;\n"
    "  font-family: Verdana, Arial;\n"
    "  border: 1px solid;\n"
    "}\n"
    ".banner h1 {\n"
    "  margin-top: 0em;\n"
    "  margin-bottom: -0.7em;\n"
    "  text-align: center;\n"
    "}\n"
    ".banner ul {\n"
    "  margin-bottom: -0.7em;\n"
    "}\n"
    ".banner li {\n"
    "  display: inline;\n"
    "}\n"
    "\n"
    ".footer {\n"
    "  font-family: Verdana, Arial;\n"
    "  font-size: 0.7em;\n"
    "  text-align: center;\n"
    "}\n";

void
css_server(struct evhttp_request *request, void *arg)
{
	struct evbuffer *databuf = evbuffer_new();
	assert(databuf != NULL);
	evhttp_add_header(request->output_headers, "Content-Type", "text/css");
	evbuffer_add(databuf, css_style, strlen(css_style));

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
print_blurb(struct evbuffer *databuf)
{
	HTML_PRINT("<div class=footer><hr />\n");
	HTML_PRINT("<center>"
	    "Copyright (c) 2007 <a href=http://www.citi.umich.edu/u/provos/>"
	    "Niels Provos</a>.  All Rights Reserved."
	    "</center>\n");
	HTML_PRINT("</div>\n");
}

static void
print_footer(struct evbuffer *databuf)
{
	HTML_PRINT("</body></html>");
}

static void
print_header(struct evbuffer *databuf)
{
	extern struct spybye_share spybye_share;
	extern int behave_as_proxy;

	HTML_PRINT(
		"<html><head><title>"
		"SpyBye: At Your Service"
		"</title></head>");
	HTML_PRINT("<link rel=stylesheet type=text/css href=/styles/css>\n");

	HTML_PRINT(
		"<body><div class=banner>\n"
		"<span class=tiny>sharing %s</span> "
		"<span class=tiny>proxy %s</span>"
		"<h1>SpyBye</h1>\n"
		"<ul>"
		"<li><a href=\"/\">Main</a> </li>"
		"<li><a href=\"/stats\">Statistics</a> </li>"
		"<li><a href=\"/about\">About</a> </li>"
		"</ul>\n"
		"<div class=version>Version %s</div>"
		"</div>\n",
		spybye_share.evcon_report == NULL ? 
		"disabled" : "enabled",
		behave_as_proxy ?
		"on" : "off",
		VERSION
	    );
}

static void
print_form(struct evbuffer *databuf)
{
	HTML_PRINT(
		"<p><center>\n"
		"<form name=\"input\" action=\"/\" method=\"get\">\n"
		"Url: <input type=\"text\" name=\"url\" size=100>\n"
		"<input type=\"submit\" value=\"Submit\">\n"
		"</form></center>");
}

static void
print_done_sites(struct evbuffer *databuf)
{
	struct site *site;
	extern int behave_as_proxy;

	if (SPLAY_ROOT(&root) == NULL)
		return;

	HTML_PRINT(
		"<hr><div class=statistics>\n"
		"<h1>Recent Site Analysis</h1>\n"
		"<ul>\n");

	for (site = SPLAY_MIN(site_tree, &root); 
	    site != NULL; site = SPLAY_NEXT(site_tree, &root, site)) {
		int done;
		char *uri_escaped, *html_escaped;
		if (site->parent != NULL)
			continue;

		/* 
		 * if we behave as proxy then all sites are done all
		 * the time
		 */
		done = behave_as_proxy || (site->flags & ANALYSIS_COMPLETE);

		uri_escaped = evhttp_encode_uri(site->url);
		html_escaped = evhttp_htmlescape(site->url);
		HTML_PRINT(
			"<li>"
			"<span class=%s>%s</span> "
			"<a href=\"/?url=%s&noiframe=1\">%s</a>"
			"</li>\n",
			done ? danger_to_text(site->danger) : "unknown",
			done ? danger_to_text(site->danger) : "pending",
			uri_escaped,
			html_escaped);
		free(uri_escaped);
		free(html_escaped);
	}

	HTML_PRINT("</ul></div>");
}

static void
main_server(struct evhttp_request *request, void *arg)
{
	struct evbuffer *databuf = evbuffer_new();
	assert(databuf != NULL);

	print_header(databuf);

	if (request->uri[0] != '/')
		print_form(databuf);

	print_done_sites(databuf);

	print_blurb(databuf);

	print_footer(databuf);

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
format_dangerousload(struct evhttp_request *request,
    struct evbuffer *databuf, struct dangerousload *dl)
{
	char output[64];
	struct tm *tm;
	u_int tmp;
	time_t seconds;
	char *parent_url, *danger_url, *escaped;
	char *virus_scan = "unknown";

	EVTAG_GET(dl, time_in_seconds, &tmp);
	EVTAG_GET(dl, parent_url, &parent_url);
	EVTAG_GET(dl, dangerous_url, &danger_url);
	if (EVTAG_HAS(dl, virus_result))
		EVTAG_GET(dl, virus_result, &virus_scan);

	seconds = tmp;
	tm = localtime(&seconds);
	strftime(output, sizeof(output), "%Y-%m-%d %H:%M:%S", tm);

	escaped = evhttp_encode_uri(parent_url);

	HTML_PRINT(
		"<tr><td><span class=time>%s</span></td>"
		"<td><span class=harmless>"
		"<a href=\"/?url=%s\">%s</a></span></td>"
		"<td><span class=dangerous>%s</span></li></td>"
		"<td><span class=harmless>%s</span></li></td>"
		"</tr>",
		output, escaped, parent_url, danger_url, virus_scan);

	free(escaped);
}

static void
stats_server(struct evhttp_request *request, void *arg)
{
	extern struct dangerq danger;
	struct dangerous_container *entry;
	struct evbuffer *databuf = evbuffer_new();
	char good_time[30], bad_time[30];
	struct tm *tm;
	int count = 0;
	assert(databuf != NULL);

	print_header(databuf);

	if (request->uri[0] != '/')
		print_form(databuf);

	HTML_PRINT("<hr />");

	/* some basic statistics */
	HTML_PRINT(
		"<div class=statistics>\n"
		"<h1>Traffic Statistics</h1>\n"
		"<table><tr><td valign=top>"
		"<table class=traffic>"
		"<tr><td>Requests</td><td>%d</td></tr>\n"
		"<tr><td>Harmless</td><td>%d</td></tr>\n"
		"<tr><td>Unknown</td><td>%d</td></tr>\n"
		"<tr><td>Dangerous</td><td>%d</td></tr>\n"
		"</table></td><td valign=top>",
		statistics.num_requests,
		statistics.num_harmless,
		statistics.num_unknown,
		statistics.num_dangerous);

	tm = localtime((time_t *)&good_patterns.tv_load.tv_sec);
	strftime(good_time, sizeof(good_time), "%Y-%m-%d %H:%M:%S", tm);
	tm = localtime((time_t *)&bad_patterns.tv_load.tv_sec);
	strftime(bad_time, sizeof(bad_time), "%Y-%m-%d %H:%M:%S", tm);

	HTML_PRINT(
		"<table class=traffic>"
		"<tr><td>Bad Patterns</td><td>%d</td><td>%s</td></tr>\n"
		"<tr><td>Good Patterns</td><td>%d</td><td>%s</td></tr>\n"
		"</table></td></tr></table>",
		bad_patterns.count,
		bad_time,
		good_patterns.count,
		good_time
	    );

	HTML_PRINT("</div><div style=\"clear:both;\"></div>\n");

	HTML_PRINT(
		"<div class=statistics>\n"
		"<h1>Dangerous Sites</h1>\n"
		"<table class=sites>");

	TAILQ_FOREACH(entry, &danger, next) {
		if (count++ > MAX_RECENT_RESULTS)
			break;

		format_dangerousload(request, databuf, entry->dl);
	}

	HTML_PRINT("</table></div>\n");
	print_blurb(databuf);

	print_footer(databuf);

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
about_server(struct evhttp_request *request, void *arg)
{
	struct evbuffer *databuf = evbuffer_new();
	assert(databuf != NULL);

	print_header(databuf);

	if (request->uri[0] != '/')
		print_form(databuf);
	
	HTML_PRINT("<hr>"
	    "<div class=about>"
	    "<h1>What is SpyBye?</h1>"
	    "<p>SpyBye is a tool to help web masters determine if their web "
	    "pages are hosting browser exploits that can infect visiting "
	    "users with malware.  It functions as an HTTP proxy server and "
	    "intercepts all browser requests.  SpyBye uses a few simple rules "
	    "to determine if embedded links on your web page are harmlesss, "
	    "unknown or maybe even dangerous.</p>"
	    "<h1>Why did you write SpyBye?</h1>"
	    "<p>It has become increasingly common for web sites to get "
	    "compromised.  This can happen either due to vulnerable "
	    "web applications that you run or due to compromised servers "
	    "via vectors completely out of your control.  Nonetheless, it "
	    "is important for web masters to be able to tell if their pages "
	    "are dangerous to their users.  SpyBye provides a very simple "
	    "mechanism to determine how a site works on the HTTP level. "
	    "This often gives us clues about potentially dangerous content. "
	    "I hope that SpyBye can be of use to anyone who wants to verify "
	    "if their web site could be compromised and dangerous.</p>"
	    "<p>The unoffical explanation is that I needed some code to "
	    "test <a href=http://www.monkey.org/~provos/libevent>"
	    "libevent</a>'s HTTP layer; writing a proxy exercises most "
	    "of the code paths.</p>"
	    "<h1>How does SpyBye work?</h1>"
	    "<p>SpyBye operates as a proxy server and gets to see all the "
	    "web fetches that your browser makes.   It applies very simple "
	    "rules to each URL that is fetched as a result of loading a "
	    "web page.  These rules allows us to classify a URL into three "
	    "categories: harmless, unknown or dangerous.  Although, there is "
	    "great margin of error, the categories allow a web master to "
	    "look at the URLs and determine if they should be there or not. "
	    "If you see that a URL is being fetched that you would not "
	    "expect, it's a good indication you have been copromised.</p>"
	    "<h1>Disclaimer</h1>"
	    "<p>SpyBye does not protect you from getting exploited yourself. "
	    "It tries to take reasonable precautions to avoid infection while "
	    "using it.  However, ideally, you would run your browser in a "
	    "virtual machine and revert to a clean snapshot when done. "
	    "You have been warned.  Today's malware is capable of rendering "
	    "your computer unusable - and empty your bank accounts! "
	    "<span style=\"font-size: 0.25em\">"
	    "THIS SOFTWARE IS PROVIDED BY THE AUTHOR "
	    "``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, "
	    "BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY "
	    "AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO "
	    "EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, "
	    "INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES "
	    "(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE "
	    "GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS "
	    "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, "
	    "WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING "
	    "NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF "
	    "THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
	    "</span>"
	    "</p>"
	    "</div>");

	print_blurb(databuf);

	print_footer(databuf);

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
results_content(struct evbuffer *databuf, struct site *site)
{
	int done = site == NULL ||
	    (site->flags & ANALYSIS_COMPLETE) ||
	    !event_pending(&site->ev_complete, EV_TIMEOUT, NULL);

	if (site != NULL) {
		char *url_escaped = evhttp_htmlescape(site->url);
		HTML_PRINT("%s %s found %d dangerous links.<p>\n",
		    done ? "<span class=harmless>Complete</span>" :
		    "<span class=unknown>Pending</span>",
		    url_escaped, site_count_dangerous(site));
		free(url_escaped);

		HTML_PRINT("<div class=analysis>\n");
		site_print_analysis(databuf, site);
		HTML_PRINT("</div>\n");
	}

	if (done) {
		HTML_PRINT("<p>The analysis of this URL is complete. "
		    "Take a look at all URLs that have been marked "
		    "either <b>unknown</b> or <b>dangerous</b>");
	} else {
		/* completion timers fire only in non-proxy mode */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		timersub(&tv, &site->tv_change, &tv);
	
		HTML_PRINT("<p>Analysis is going to take %d more seconds.",
		    IDLE_TIME - tv.tv_sec);
	}
}

void
results_server(struct evhttp_request *request, void *arg)
{
	struct site *site, tmp;
	struct evkeyvalq args;
	struct evbuffer *databuf = evbuffer_new();
	const char *url = NULL;
	int done = 0;
	assert(databuf != NULL);

	TAILQ_INIT(&args);

	evhttp_parse_query(request->uri, &args);

	url = evhttp_find_header(&args, "url");

	if (url == NULL)
		goto fail;

	tmp.url = (char *)url;
	site = SPLAY_FIND(site_tree, &root, &tmp);

	HTML_PRINT(
		"<html><head><title>"
		"SpyBye: Results</title>\n");
	done = site == NULL ||
	    (site->flags & ANALYSIS_COMPLETE) ||
	    !event_pending(&site->ev_complete, EV_TIMEOUT, NULL);
	if (!done)
		HTML_PRINT("<meta http-equiv=\"refresh\" content=\"2\">\n");

	HTML_PRINT("</head>");
	HTML_PRINT("<link rel=stylesheet type=text/css href=/styles/css>\n");

	HTML_PRINT("<body>");

	results_content(databuf, site);
	
	HTML_PRINT("</body></html>");

	evhttp_clear_headers(&args);

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
	return;

fail:
	evhttp_clear_headers(&args);
	evhttp_send_error(request, HTTP_BADREQUEST, "You must be kidding.");
}

void
query_server(struct evhttp_request *request, void *arg)
{
	extern int use_iframes;
	static char fixed_url[PATH_MAX];
	struct evkeyvalq args;
	struct evbuffer *databuf = evbuffer_new();
	struct site *site = NULL;
	char *url_relative = NULL;
	const char *no_iframe_arg = NULL;
	const char *url = NULL;
	int no_iframe = 0, redirect = 0, done = 0;
	assert(databuf != NULL);

	TAILQ_INIT(&args);

	evhttp_parse_query(request->uri, &args);

	url = evhttp_find_header(&args, "url");
	no_iframe_arg = evhttp_find_header(&args, "noiframe");
	no_iframe = no_iframe_arg != NULL && strcmp(no_iframe_arg, "1") == 0;

	print_header(databuf);

	if (request->uri[0] != '/' && !no_iframe)
		print_form(databuf);

	print_blurb(databuf);

	if (url == NULL) {
		HTML_PRINT("Did not receive a URL.  You loose.");
		goto done;
	}

	if (http_hostportfile(url, NULL, NULL, NULL) == -1) {
		/* if they did not prefix with http://, try to fix for them */
		strlcpy(fixed_url, HTTP_PREFIX, sizeof(fixed_url));
		strlcat(fixed_url, url, sizeof(fixed_url));
		url = fixed_url;
		if (http_hostportfile(url, NULL, NULL, NULL) == -1) {
			HTML_PRINT("Did not receive a URL.  You loose.");
			goto done;
		}
	}

	site = site_new(url, NULL);
	url_relative = evhttp_encode_uri(url);
		
	if (site == NULL)
		goto fail;

	done = (site->flags & ANALYSIS_COMPLETE) || no_iframe;
	if (done) {
		HTML_PRINT("<hr />\n");
		results_content(databuf, site);
		goto done;
	}

	/* start the completion timer */
	site_complete(-1, 0, site);

	if (use_iframes) {
		HTML_PRINT(
			"<iframe src=\"/results/?url=%s\" "
			"width=100%% height=50%%>\n"
			"Missing iframe support</iframe><p>\n",
			url_relative);
		free(url_relative);

		/*
		 * do not inject an iframe for the site to be tested
		 * if the analysis is complete; or if the user
		 * directly requested that no iframe be displayed.
		 */
		if (!done) {
			char *url_escaped = evhttp_htmlescape(url);
			HTML_PRINT(
				"<iframe src=\"%s\" width=100%%"
				"security=restricted>\n"
				"Missing iframe support"
				"</iframe>\n",
				url_escaped);
			free(url_escaped);
		}
	} else {
		/*
		 * Instead of providing an inframe based UI, we just redirect
		 * the user and use js injection.
		 */
		redirect = 1;
	}

done:
	print_footer(databuf);

	if (redirect) {
		evhttp_add_header(request->output_headers,
		    "Location", url);
		evhttp_send_reply(request, HTTP_MOVETEMP, "Moved", NULL);
	} else {
		/* send along our data */
		evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	}

	evhttp_clear_headers(&args);
	evbuffer_free(databuf);
	return;

fail:
	evhttp_clear_headers(&args);
	evhttp_send_error(request, HTTP_SERVUNAVAIL, "Another eval is on");
}

void
cache_server(struct evhttp_request *request, void *arg)
{
	struct timeval tv;
	struct evkeyvalq args;
	struct evbuffer *databuf = evbuffer_new();
	struct site *site;
	const char *url = NULL;
	char *escaped;
	assert(databuf != NULL);

	TAILQ_INIT(&args);

	evhttp_parse_query(request->uri, &args);

	url = evhttp_find_header(&args, "url");
	site = site_find(url);

	if (site == NULL || site->html_data == NULL)
		goto fail;

	evhttp_clear_headers(&args);

	/* somebody showed interst in this page - let it not expire yet */
	gettimeofday(&tv, NULL);
	site_change_time(site, &tv);

	/* NUL terminate */
	evbuffer_add(databuf, site->html_data, site->html_size);
	evbuffer_add(databuf, "", 1);

	escaped = evhttp_htmlescape((char *)EVBUFFER_DATA(databuf));

	evbuffer_drain(databuf, -1);

	HTML_PRINT("<html><head><title>raw dump</title></head><body>");
	HTML_PRINT("<pre>%s</pre>", escaped);
	free(escaped);
	HTML_PRINT("</body></html>");

	/* send along our data */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
	return;

fail:
	inform_cache_notfound(request, url);
	evhttp_clear_headers(&args);
}

int
spybye_handle_request(struct evhttp_request *request, void *arg)
{
	char *host, *uri;
	u_short port;

	if (http_hostportfile(request->uri, &host, &port, &uri) == -1) {
		/* if it's not fully qualified assume we can just use the uri */
		uri = request->uri;
	}

	/*
	 * this is a little bit silly, we are not taking advantage of
	 * the http layer dispatch support.
	 */
	if (strcmp(uri, "/styles/css") == 0) {
		css_server(request, arg);
		return (0);
	} else if (strcmp(uri, "/control.js") == 0) {
		serve_control_javascript(request, arg);
		return (0);
	} else if (strcmp(uri, "/") == 0) {
		main_server(request, arg);
		return (0);
	} else if (strcmp(uri, "/stats") == 0) {
		stats_server(request, arg);
		return (0);
	} else if (strcmp(uri, "/about") == 0) {
		about_server(request, arg);
		return (0);
	} else if (strncmp(uri, "/?", 2) == 0) {
		query_server(request, arg);
		return (0);
	} else if (strncmp(uri, "/results/", 9) == 0) {
		results_server(request, arg);
		return (0);
	} else if (strncmp(uri, "/cache/", 7) == 0) {
		cache_server(request, arg);
		return (0);
	}

	return (-1);
}

static void
status_free_patterns(struct patternq *head)
{
	struct pattern *entry;

	while ((entry = TAILQ_FIRST(head)) != NULL) {
		TAILQ_REMOVE(head, entry, next);
		if (entry->pattern_host != NULL)
			free(entry->pattern_host);
		if (entry->pattern_uri != NULL)
			free(entry->pattern_uri);
		free(entry);
	}
}

static void
patterns_web_done(struct evhttp_request *request, void *arg)
{
	struct pattern_obj *patterns = arg;
	if (request == NULL || request->response_code != HTTP_OK ||
	    EVBUFFER_LENGTH(request->input_buffer) == 0) {
		fprintf(stderr, "[PATTERN] Failed to read patterns from %s\n",
		    patterns->location);
		return;
	}

	status_free_patterns(&patterns->head);
	status_patterns(patterns, request->input_buffer);
}

static void
patterns_refresh(int fd, short what, void *arg)
{
	struct timeval tv;
	struct pattern_obj *patterns = arg;

	timerclear(&tv);
	tv.tv_sec = PATTERN_REFRESH_SECONDS;
	evtimer_add(&patterns->ev_refresh, &tv);

	fprintf(stderr, "[PATTERN] Refreshing patterns from %s\n",
	    patterns->location);

	if (strncasecmp(HTTP_PREFIX, patterns->location,
		strlen(HTTP_PREFIX))) {
		/* from file */
		struct evbuffer *data = read_data(patterns->location);
		/* xxx - need to check successful read */
		status_free_patterns(&patterns->head);
		status_patterns(patterns, data);
		evbuffer_free(data);
	} else {
		if (patterns->evcon != NULL)
			evhttp_connection_free(patterns->evcon);
		patterns->evcon = read_from_web_prepare(patterns->location,
		    patterns_web_done, patterns);
	}
}

void
status_init(const char *goodness, const char *badness)
{
	struct timeval tv;
	struct evbuffer *data;
	SPLAY_INIT(&root);

	good_patterns.location = goodness;
	bad_patterns.location = badness;

	evtimer_set(&good_patterns.ev_refresh,
	    patterns_refresh, &good_patterns);
	evtimer_set(&bad_patterns.ev_refresh,
	    patterns_refresh, &bad_patterns);

	timerclear(&tv);
	tv.tv_sec = PATTERN_REFRESH_SECONDS;
	evtimer_add(&good_patterns.ev_refresh, &tv);
	evtimer_add(&bad_patterns.ev_refresh, &tv);

	/* initial setup of the contents */
	if (strlen(goodness)) {
		data = 
		    strncasecmp(HTTP_PREFIX, goodness, strlen(HTTP_PREFIX)) ?
		    read_data(goodness) : read_from_web(goodness);
		status_good_patterns(data);
		evbuffer_free(data);
	}

	if (strlen(badness)) {
		data =
		    strncasecmp(HTTP_PREFIX, badness, strlen(HTTP_PREFIX)) ?
		    read_data(badness) : read_from_web(badness);
		status_bad_patterns(data);
		evbuffer_free(data);
	}
}

static int
status_patterns(struct pattern_obj *data, struct evbuffer *databuf)
{
	char *line;
	int count = 0;

	while ((line = evbuffer_readline(databuf)) != NULL) {
		struct pattern *pattern;
		char *host = line, *uri;
		if (line[0] == '#' || !strlen(line))
			continue;

		uri = strchr(line, ' ');
		if (uri != NULL)
			*uri++ = '\0';

		pattern = malloc(sizeof(struct pattern));
		if (pattern == NULL)
			err(1, "malloc");
		pattern->pattern_host = strdup(host);
		if (uri != NULL)
			pattern->pattern_uri = strdup(uri);
		else
			pattern->pattern_uri = NULL;

		if (pattern->pattern_host == NULL ||
		    (uri != NULL && pattern->pattern_uri == NULL))
			err(1, "strdup");

		TAILQ_INSERT_TAIL(&data->head, pattern, next);
		DNFPRINTF(2,(stderr, "[PATTERN] Adding pattern: %s/%s\n",
			host, uri));
		count++;

		free(line);
	}
	data->count = count;
	gettimeofday(&data->tv_load, NULL);

	return (count);
}

void
status_good_patterns(struct evbuffer *data)
{
	int count;
	TAILQ_INIT(&good_patterns.head);
	count = status_patterns(&good_patterns, data);

	fprintf(stderr, "[PATTERN] Added %d good patterns\n", count);
}

void
status_bad_patterns(struct evbuffer *data)
{
	int count;
	TAILQ_INIT(&bad_patterns.head);
	count = status_patterns(&bad_patterns, data);

	fprintf(stderr, "[PATTERN] Added %d bad patterns\n", count);
}


/* error messaging */

static void
inform_cache_notfound(struct evhttp_request *request, const char *url)
{
	struct evbuffer *databuf = evbuffer_new();
	char *html_escaped = evhttp_htmlescape(url != NULL ? url : "<unknown>");
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Cache Not Found</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 40%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>Cache Not Found</h2>\n"
	    "The URL %s that you requested could not be found in the cache. "
	    "It's possible that it could not be fetched from its web "
	    "server.</div></body></html>",
	    html_escaped);
	free(html_escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request, HTTP_NOTFOUND, "Not Found", databuf);
	evbuffer_free(databuf);
}
