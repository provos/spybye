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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <syslog.h>

#include <event.h>
#include <evdns.h>
#include <evhttp.h>

#include "spybye.h"
#include "utils.h"
#include "status.h"
#include "log.h"
#include "virus.h"
#include "proxy.h"

/* tell our callers that the name could not be resolved */
static struct request_holder *request_holder_new(struct evhttp_request *req);
static void spybye_traffic_stats(struct site *site);
static void spybye_remove_traffic_stats(struct site *site);
static void request_holder_free(struct request_holder *rh);
static void http_virusscan_done(const char *result, void *arg);
static void dns_dispatch_error(struct dns_cache *);
static void dns_dispatch_requests(struct dns_cache *dns_entry);
static void inform_domain_notfound(struct evhttp_request *request);
static void inform_proxy_settings(struct evhttp_request *request);
static void inform_no_referer(struct evhttp_request *request);

int debug = 0;

/* globals */

static int log_fd = -1;
static int log_report_fd = -1;
static int allow_private_ip = 0;
static short http_port = 8080;	/* port on which the server runs */
static int virus_enabled = 0;
int behave_as_proxy = 0;
int sanitize_js = 0;		/* needed if running within frame */
int use_iframes = 0;		/* use the iframe ui, rather than the js ui */

static int
dns_compare(struct dns_cache *a, struct dns_cache *b)
{
	return strcasecmp(a->name, b->name);
}

static SPLAY_HEAD(dns_tree, dns_cache) root;

SPLAY_PROTOTYPE(dns_tree, dns_cache, node, dns_compare);
SPLAY_GENERATE(dns_tree, dns_cache, node, dns_compare);

static void
dns_ttl_expired(int result, short what, void *arg)
{
	struct dns_cache *dns = arg;
	
	fprintf(stderr, "[DNS] Expire entry for %s\n", dns->name);

	assert(TAILQ_FIRST(&dns->entries) == NULL);
	dns_free(dns);
}

static void
dns_resolv_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct dns_cache *entry = arg;
	struct timeval tv;

	DNFPRINTF(1, (stderr, "[DNS] Received response for %s: %d\n",
		entry->name, result));

	if (result != DNS_ERR_NONE) {
		/* we were not able to resolve the name */
		dns_dispatch_error(entry);
		return;
	}

	if (!allow_private_ip && check_private_ip(addresses, count)) {
		/* we can't go here - it might be our own machine! */
		dns_dispatch_error(entry);
		return;
	}

	/* copy the addresses */
	entry->addresses = calloc(count, sizeof(struct in_addr));
	if (entry->addresses == NULL)
		err(1, "calloc");
	entry->address_count = count;
	memcpy(entry->addresses, addresses, count * sizeof(struct in_addr));

	dns_dispatch_requests(entry);

	/* expire it after its time-to-live is over */
	evtimer_set(&entry->ev_timeout, dns_ttl_expired, entry);
	timerclear(&tv);
	tv.tv_sec = ttl;
	evtimer_add(&entry->ev_timeout, &tv);
}

static void
http_copy_headers(struct evkeyvalq *dst, struct evkeyvalq *src)
{
	struct evkeyval *kv;
	TAILQ_FOREACH(kv, src, next) {
		/* we cannot inject javascript into an encoded data stream */
		if (strcasecmp(kv->key, "Transfer-Encoding") == 0 ||
		    strcasecmp(kv->key, "Accept-Encoding") == 0 ||
		    strcasecmp(kv->key, "Connection") == 0 ||
		    strcasecmp(kv->key, "Keep-Alive") == 0 ||
		    strcasecmp(kv->key, "Proxy-Connection") == 0) {
			DNFPRINTF(2, (stderr, "[HEADER] Ignoring %s: %s\n",
				kv->key, kv->value));
			continue;
		}
		/* we might want to do some filtering here */
		DNFPRINTF(2, (stderr, "[DEBUG] Header %s: %s\n",
			kv->key, kv->value));
		evhttp_add_header(dst, kv->key, kv->value);
	}
}

static void
map_location_header(struct evhttp_request *req, const char *location)
{
	static char path[1024];
	char *host, *uri;
	u_short port;
			
	if (http_hostportfile(location, NULL, NULL, NULL) == -1) {
		if (http_hostportfile(req->uri, &host, &port, &uri) == -1)
			return;
		if (location[0] == '/') {
			snprintf(path, sizeof(path), "http://%s%s",
			    host, location);
		} else {
			snprintf(path, sizeof(path), "http://%s%s%s",
			    host, uri, location);
		}
	} else {
		strlcpy(path, location, sizeof(path));
	}
	fprintf(stderr, "[MAP] %s -> %s\n", path, req->uri);
	site_new(path, req->uri);
}

static void
inform_dangerous(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	char *escaped = evhttp_htmlescape(request->uri);
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Dangerous Request</title></head>"
	    "<body>Possibly dangerous load of %s</body></html>",
	    escaped);
	free(escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request,
	    HTTP_NOTFOUND, "Disallowing dangerous request.",
	    databuf);
	evbuffer_free(databuf);
}

static void
inform_domain_notfound(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	char *escaped = evhttp_htmlescape(request->uri);
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Domain not found</title></head>"
	    "<body><h1>Domain not found</h1>\n"
	    "Cannot find an IP address for %s</body></html>",
	    escaped);
	free(escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request,
	    HTTP_BADREQUEST, "Disallowing dangerous request.",
	    databuf);
	evbuffer_free(databuf);
}

static void
inform_error(struct evhttp_request *request,
    int error_code, const char *error_text)
{
	struct evbuffer *databuf = evbuffer_new();
	const char *error_title = "Unknown Error";
	const char *error_add_text = "";
	assert(databuf != NULL);

	switch (error_code) {
	case HTTP_SERVUNAVAIL:
		error_title = "Internal Service Error";
		error_add_text = error_text;
		break;
	case HTTP_BADREQUEST:
		error_title = "Invalid Request";
		error_add_text =
		    "The proxy received a request that contained invalid or "
		    "badly formatted HTTP, or a request for a private IP "
		    "address that has been forbidden by configuration.";
		break;
	case HTTP_NOTFOUND:
		error_title = "Document Not Found";
		error_add_text =
		    "The document could not be found at the specified "
		    "location.";
		break;
	}

	evbuffer_add_printf(databuf,
	    "<html><head><title>%s</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 60%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>%s</h2>\n"
	    "Could not complete request to <b>http://%s/</b>."
	    "%s"
	    "<p>"
	    "You are using SpyBye %s."
	    "</div>"
	    "</body></html>",
	    error_title, error_title,
	    evhttp_find_header(request->input_headers, "Host"),
	    error_add_text, VERSION);

	/* we cannot allow this request */
	evhttp_send_reply(request, error_code, error_text, databuf);
	evbuffer_free(databuf);
}

static void
inform_proxy_settings(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Proxy Configuration</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 40%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>Proxy Configuration</h2>\n"
	    "To use <i>SpyBye</i>, you need to configure your browser to "
	    "use the following proxy <b>http://%s/</b></div><p>"
	    "<iframe src=\"http://www.spybye.org/\" width=100%% height=85%%>"
	    "</body></html>",
	    evhttp_find_header(request->input_headers, "Host"));

	/* we cannot allow this request */
	evhttp_send_reply(request, HTTP_OK, "OK", databuf);
	evbuffer_free(databuf);
}

static void
inform_no_referer(struct evhttp_request *request)
{
	struct evbuffer *databuf = evbuffer_new();
	char *escaped = evhttp_encode_uri(request->uri);
	char *html_escaped = evhttp_htmlescape(request->uri);
	assert(databuf != NULL);

	evbuffer_add_printf(databuf,
	    "<html><head><title>Request Denied</title></head>"
	    "<body><div style=\"border: solid 1px; padding: 2px; "
	    "width: 40%%; "
	    "background-color: #dcdcee; font-family: Verdana, Arial;\">"
	    "<h2>Request Denied</h2>\n"
	    "To use <i>SpyBye</i>, visit "
	    "<a href=\"http://spybye.org/\">http://spybye.org/</a> "
	    "or go to <a href=\"http://spybye.org/?url=%s\">%s</a> "
	    "using SpyBye.</div><p>"
	    "</body></html>",
	    escaped, html_escaped);
	free(escaped);
	free(html_escaped);

	/* we cannot allow this request */
	evhttp_send_reply(request, HTTP_NOTFOUND, "Not Found", databuf);
	evbuffer_free(databuf);
}

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	struct site *site = NULL;
	struct proxy_request *pr = arg;

	if ((site = site_find(pr->req->uri)) == NULL) {
		inform_error(pr->req,
		    HTTP_SERVUNAVAIL, "Unknown error");
		proxy_request_free(pr);
		return;
	}

	if (req == NULL || req->response_code == 0) {
		/* potential request timeout; unreachable machine, etc. */
		pr->holder = NULL;
		http_virusscan_done("error", pr);
		return;
	}

	/* store the data that we received */
	site_cache_data(site, req);

	if (sanitize_js) {
		/* now sanitize some stupid javascript */
		sanitize_content(req);
	}

	pr->holder = request_holder_new(req);

	if (virus_enabled == 0 || EVBUFFER_LENGTH(req->input_buffer) == 0) {
		http_virusscan_done("clean", pr);
	} else {
		char *data = (char *)EVBUFFER_DATA(req->input_buffer);
		int len = EVBUFFER_LENGTH(req->input_buffer);
		virus_scan_buffer(data, len, http_virusscan_done, pr);
	}
}

static void
http_add_uncache_headers(struct evhttp_request *request)
{
	/* make everything we do no-cacheable */
	evhttp_remove_header(request->output_headers, "Pragma");
	evhttp_add_header(request->output_headers,
	    "Pragma", "no-cache, no-store");

	evhttp_remove_header(request->output_headers, "Cache-Control");
	evhttp_add_header(request->output_headers,
	    "Cache-Control",
	    "no-cache, no-store, must-revalidate, max-age=-1");
}

static void
http_virusscan_done(const char *result, void *arg)
{
	struct proxy_request *pr = arg;
	struct request_holder *rh = pr->holder;
	struct site *site = site_find(pr->req->uri);
	const char *location = NULL;
	const char *content_type = NULL;
	int isvirus, wasdangerous = 0, ishtml = 0;
	assert(site != NULL);

	/* to avoid double logging */
	wasdangerous = site->danger == DANGEROUS;

	/* need to store the result somewhere else */
	site->virus_result = strdup(result);

	/* set if it's neither ok nor error */
	isvirus = strcmp(result, "clean") && strcmp(result, "error");
	if (isvirus) {
		spybye_remove_traffic_stats(site);
		site_make_dangerous(site);
		spybye_traffic_stats(site);
	}

	log_request(LOG_INFO, pr->req, site);

	/*
	 * make requests to dangerous sites just to keep track of the content.
	 */
	if (site->danger == DANGEROUS && site->parent != NULL) {
		struct site *parent = site->parent;
		/* 
		 * log only if we did not log already and the parent
		 * is not matched
		 */
		if (!wasdangerous && !site_matches_bad_patterns(parent)) {
			if (log_fd != -1)
				log_dangerous_request(log_fd, pr->req, site);
			if (log_report_fd != -1)
				log_dangerous_report(log_report_fd, pr->req,
				    site);
		}

		if (behave_as_proxy) {
			/* 
			 * in proxy mode, we face the dilemma that
			 * allowing the browser to cache content will
			 * hide requests from us.  Ideally, we would
			 * not allow the caching of anything.
			 * However, as this would seriously harm
			 * performance, we disallow caching only for
			 * URLs on the bad patterns list.
			 */
			if (wasdangerous) {
				/* it was not detected by virus scanners */
				http_add_uncache_headers(pr->req);
			}
		}

		inform_dangerous(pr->req);
		proxy_request_free(pr);
		return;
	}

	if (rh == NULL) {
		/* we have nothing to serve */
		inform_error(pr->req, HTTP_SERVUNAVAIL,
		    "Could not reach remote location.");
		goto done;
	}

	location = evhttp_find_header(rh->headers, "Location");
	/* keep track of the redirect so that we can tie it together */
	if (location != NULL)
		map_location_header(pr->req, location);

	http_copy_headers(pr->req->output_headers, rh->headers);

	/*
	 * if not running as proxy or if we inject control js into HTML,
	 * we need to make the resulting response uncachable, otherwise
	 * we face situations where the js gets executed without SpyBye
	 * having the corresponding state.
	 */
	content_type = evhttp_find_header(rh->headers, "Content-Type");
	ishtml = content_type != NULL &&
	    strncasecmp(content_type, "text/html", 9) == 0;
	if (!behave_as_proxy || ishtml) {
		/*
		 * make everything we do uncacheable, so that we
		 * always get all requests 
		 */
		http_add_uncache_headers(pr->req);
	}

	/* inject our control code here */
	if (!use_iframes && ishtml) {
		inject_control_javascript(rh->buffer);
		/* fix up the content length */
		evhttp_remove_header(pr->req->output_headers,
		    "Content-Length");
	}

	evhttp_send_reply(pr->req, rh->response_code, rh->response_line,
	    rh->buffer);

done:
	proxy_request_free(pr);
}


static void
dispatch_single_request(struct dns_cache *dns, struct proxy_request *pr)
{
	struct evhttp_request *request;
	char *address = inet_ntoa(dns->addresses[0]);

	assert(pr->evcon == NULL);
	pr->evcon = evhttp_connection_new(address, pr->port);
	fprintf(stderr, "[NET] Connecting %s:%d\n", address, pr->port);
	if (pr->evcon == NULL)
		goto fail;

	evhttp_connection_set_timeout(pr->evcon, SPYBYE_CONNECTION_TIMEOUT);

	/* we got the connection now - queue the request */
	request = evhttp_request_new(http_request_done, pr);
	if (request == NULL)
		goto fail;

	http_copy_headers(request->output_headers, pr->req->input_headers);
	evhttp_add_header(request->output_headers,
	    "X-Forwarded-For", pr->req->remote_host);

	/* for post requests, we might have to add the buffer */
	if (pr->req->type == EVHTTP_REQ_POST)
		evbuffer_add_buffer(request->output_buffer,
		    pr->req->output_buffer);

	evhttp_add_header(request->output_headers, "Connection", "close");
	evhttp_make_request(pr->evcon, request, pr->req->type, pr->uri);
	return;

fail:
	inform_error(pr->req, HTTP_SERVUNAVAIL, "Out of resources");
	proxy_request_free(pr);
	return;
}

static void
dns_dispatch_requests(struct dns_cache *dns)
{
	struct proxy_request *entry;
	while ((entry = TAILQ_FIRST(&dns->entries)) != NULL) {
		TAILQ_REMOVE(&dns->entries, entry, next);
		
		dispatch_single_request(dns, entry);
	}
}

static void
dns_dispatch_error(struct dns_cache *dns_entry)
{
	struct proxy_request *entry;
	while ((entry = TAILQ_FIRST(&dns_entry->entries)) != NULL) {
		TAILQ_REMOVE(&dns_entry->entries, entry, next);

		inform_domain_notfound(entry->req);
		proxy_request_free(entry);
	}

	/* no negative caching */
	dns_free(dns_entry);
}

struct dns_cache *
dns_new(const char *name)
{
	struct dns_cache *entry, tmp;
	struct in_addr address;


	tmp.name = (char *)name;
	if ((entry = SPLAY_FIND(dns_tree, &root, &tmp)) != NULL)
		return (entry);

	entry = calloc(1, sizeof(struct dns_cache));
	if (entry == NULL)
		err(1, "calloc");

	entry->name = strdup(name);
	if (entry->name == NULL)
		err(1, "strdup");

	TAILQ_INIT(&entry->entries);
	SPLAY_INSERT(dns_tree, &root, entry);

	if (inet_aton(entry->name, &address) != 1) {
		DNFPRINTF(1, (stderr, "[DNS] Resolving IPv4 for %s\n",
			entry->name));
		evdns_resolve_ipv4(entry->name, 0,
		    dns_resolv_cb, entry);
	} else {
		/* this request is dangerous */
		if (!allow_private_ip && check_private_ip(&address, 1)) {
			dns_free(entry);
			return (NULL);
		}

		/* we already have an address - no dns necessary */
		dns_resolv_cb(DNS_ERR_NONE, DNS_IPv4_A,
		    1, 3600, &address, entry);
	}

	return (entry);
}

void
dns_free(struct dns_cache *entry)
{
	SPLAY_REMOVE(dns_tree, &root, entry);
	free(entry->addresses);
	free(entry->name);
	free(entry);
}

void
request_add_dns(struct dns_cache *entry, struct proxy_request *pr)
{
	TAILQ_INSERT_TAIL(&entry->entries, pr, next);

	/* still waiting for resolution */
	if (entry->address_count == 0)
		return;

	dns_dispatch_requests(entry);
}

/* keep some simple stats */
static void
spybye_traffic_stats(struct site *site)
{
	extern struct stats statistics;

	statistics.num_requests++;
	switch (site->danger) {
	case HARMLESS:
		statistics.num_harmless++;
		break;
	case DANGEROUS:
		statistics.num_dangerous++;
		break;
	case UNKNOWN:
	default:
		statistics.num_unknown++;
		break;
	}
}

static void
spybye_remove_traffic_stats(struct site *site)
{
	extern struct stats statistics;

	statistics.num_requests--;
	switch (site->danger) {
	case HARMLESS:
		statistics.num_harmless--;
		break;
	case DANGEROUS:
		statistics.num_dangerous--;
		break;
	case UNKNOWN:
	default:
		statistics.num_unknown--;
		break;
	}
}

/*
 * Receive all possible requests - analyze them for doing stuff
 */

void
request_handler(struct evhttp_request *request, void *arg)
{
	char *host, *uri;
	const char *referer;
	u_short port;
	struct site *site;
	struct dns_cache *entry;
	struct proxy_request *pr;
	int ctrl_len, req_len;

	if (request->uri != NULL && request->uri[0] == '/') {
		if (strcmp(request->uri, "/reports") == 0) {
			/* save the report somewhere on disk */
			if (log_report_fd != -1)
				log_external_report(log_report_fd, request);
			evhttp_send_reply(request, HTTP_OK, "OK", NULL);
			return;
		}

		/* serve statistics */
		if (spybye_handle_request(request, arg) == -1)
			inform_proxy_settings(request);
		return;
	}

	if (http_hostportfile(request->uri, &host, &port, &uri) == -1) {
		inform_error(request, HTTP_BADREQUEST, "Illegal request.");
		return;
	}

	if (strncasecmp(host, "spybye", 6) == 0) {
		fprintf(stderr, "[URL] Request for %s\n", request->uri);
		if (spybye_handle_request(request, arg) == -1) {
			inform_error(request, HTTP_NOTFOUND, "Data not found.");
		}
		return;
	}


	/* recognize our magic XMLRPC */
	ctrl_len = strlen(CONTROL_CALLBACK_URI);
	req_len = strlen(request->uri);
	if (req_len > ctrl_len  &&
	    strcmp(request->uri + req_len - ctrl_len,
		CONTROL_CALLBACK_URI) == 0) {
		handle_proxy_callback(request, arg);
		return;
	}

	/* now insert the request into our status object */
	referer = evhttp_find_header(request->input_headers, "Referer");
	fprintf(stderr, "[URL] Request for %s (%s) from %s\n",
	    request->uri, referer, request->remote_host);
	if (referer == NULL && !behave_as_proxy) {
		log_request(LOG_INFO, request, NULL);
		inform_no_referer(request);
		return;
	}
	
	/* 
	 * if we behave like a proxy then it's okay for the referer to be
	 * NULL, we will automatically create the right state
	 */
	if (behave_as_proxy) {
		site = site_find(request->uri);
		/* new site state may be created */
		if (site == NULL) {
			site = site_new(request->uri, referer);
			if (site == NULL)
				site = site_new(request->uri, NULL);
			assert(site != NULL);
			/* we never start completion timers as proxy */
		}
	} else {
		site = site_new(request->uri, referer);

		/* we do not allow the creation of new site state */
		if (site == NULL) {
			/* some evil sites are tricky */
			char *decode = evhttp_decode_uri(referer);
			site = site_new(request->uri, decode);
			free(decode);
		}
		if (site == NULL) {
			log_request(LOG_INFO, request, NULL);
			fprintf(stderr, "[STATE] Missing site state for %s\n",
			    request->uri);
			inform_no_referer(request);
			return;
		}
	}

	spybye_traffic_stats(site);
	if (site->danger == DANGEROUS && site->parent != NULL) {
		struct site *parent = site->parent;
		if (!site_matches_bad_patterns(parent)) {
			if (log_fd != -1)
				log_dangerous_request(log_fd, request, site);
			if (log_report_fd != -1)
				log_dangerous_report(log_report_fd, request,
				    site);
		}
	}

	/* make sure that we do not send a referer if this is a root URL */
	if (site->parent == NULL)
		evhttp_remove_header(request->input_headers, "Referer");

	if ((entry = dns_new(host)) == NULL) {
		fprintf(stderr, "[PRIVATE] Attempt to visit private IP: %s\n",
		    request->uri);
		log_request(LOG_INFO, request, site);
		inform_error(request,
		    HTTP_BADREQUEST, "Access to private IP disallowed.");
		return;
	}
	pr = proxy_request_new(request, port, uri);
	request_add_dns(entry, pr);
}

struct proxy_request *
proxy_request_new(struct evhttp_request *req, u_short port, char *uri)
{
	struct proxy_request *pr;

	if ((pr = calloc(1, sizeof(struct proxy_request))) == NULL)
		err(1, "calloc");

	pr->uri = strdup(uri);
	if (pr->uri == NULL)
		err(1, "strdup");

	pr->req = req;
	pr->port = port;

	return (pr);
}

static void
proxy_request_free_evcon(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	evhttp_connection_free(evcon);
}

void
proxy_request_free(struct proxy_request *pr)
{
	if (pr->evcon != NULL) {
		struct timeval tv;
		
		timerclear(&tv);
		event_once(-1, EV_TIMEOUT, proxy_request_free_evcon,
		    pr->evcon, &tv);
	}

	if (pr->holder != NULL) {
		request_holder_free(pr->holder);
	}

	free(pr->uri);
	free(pr);
}

static struct request_holder *
request_holder_new(struct evhttp_request *req)
{
	struct request_holder *rh = calloc(1, sizeof(struct request_holder));
	assert(rh != NULL);
	rh->headers = malloc(sizeof(struct evkeyvalq *));
	assert(rh->headers != NULL);
	TAILQ_INIT(rh->headers);

	http_copy_headers(rh->headers, req->input_headers);

	/* copy all the data that we need to make the reply */
	rh->buffer = evbuffer_new();
	assert(rh->buffer != NULL);
	evbuffer_add(rh->buffer,
	    EVBUFFER_DATA(req->input_buffer),
	    EVBUFFER_LENGTH(req->input_buffer));
	rh->response_code = req->response_code;
	rh->response_line = strdup(req->response_code_line);
	assert(rh->response_line != NULL);

	return (rh);
}

static void
request_holder_free(struct request_holder *rh)
{
	evhttp_clear_headers(rh->headers);
	free(rh->headers);
	free(rh->response_line);
	evbuffer_free(rh->buffer);
	free(rh);
}

void
usage(const char *progname)
{
	fprintf(stderr,
	    "%s: [-P] [-p port] [-g good] [-b bad] [-l logfile] [-S shareurl] "
	    "[-x]\n"
	    "\t -P disable private IP check; allows the proxy to fetch 127/8\n"
	    "\t -p port port number to create proxy server on\n"
	    "\t -g good_patterns a file or url containing the good patterns\n"
	    "\t -b bad_patterns a file or url containing the danger patterns\n"
	    "\t -l logfile a file to log dangerous site interactions to\n"
	    "\t -S shareurl host to log dangerous site interactions to\n"
	    "\t -x enable proxy mode\n"
	    "\t -I use iframes UI instead of injecting javascript\n"
	    "\t -v enable debug output\n"
	    "\t for documentation of all options consult the man page\n",
	    progname);
}

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	struct evhttp *http_server = NULL;
	char *reports = "http://www.spybye.org:8080/reports";
	char *goodness = "http://www.monkey.org/~provos/good_patterns";
	char *badness = "http://www.monkey.org/~provos/bad_patterns";
	char *log_file = "spybye.log";
	char *log_report_file = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "IPvxp:g:b:l:S:R:")) != -1)
		switch(ch) {
		case 'I':
			use_iframes = 1;
			sanitize_js = 1;
			break;
		case 'v':
			debug++;
			break;
		case 'R':
			log_report_file = optarg;
			break;
		case 'S':
			reports = optarg;
			break;
		case 'P':
			allow_private_ip = 1;
			break;
		case 'x':
			behave_as_proxy = 1;
			break;
		case 'p':
			http_port = atoi(optarg);
			if (!http_port) {
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'l':
			if (!strlen(optarg))
				log_file = NULL;
			else
				log_file = optarg;
			break;
		case 'g':
			goodness = optarg;
			break;
		case 'b':
			badness = optarg;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	event_init();
	evtag_init();
	evdns_init();

	openlog("spybye", LOG_PID|LOG_CONS, LOG_DAEMON);

	fprintf(stderr, "[MAIN] SpyBye %s starting up ...\n", VERSION);

	virus_enabled = virus_init() == 0;
	if (virus_enabled)
		fprintf(stderr, "[VIRUS] Virus scanning enabled\n");

	if (behave_as_proxy)
		fprintf(stderr, "[PROXY] Operating in proxy mode\n");

	if (strlen(reports)) {
		extern struct spybye_share spybye_share;
		log_establish_sharing(&spybye_share, reports);
	}

	status_init(goodness, badness);

	/* open the log file if needed */
	if (log_file != NULL) {
		log_dangerous_read(log_file);
		log_fd = log_init(log_file);
	}

	if (log_report_file != NULL) {
		log_report_fd = log_init(log_report_file);
	}

	http_server = evhttp_start("0.0.0.0", http_port);
	if (http_server == NULL) {
		fprintf(stderr, "[MAIN] Cannot run web server on port %d\n",
		    http_port);
		exit(1);
	}
	evhttp_set_gencb(http_server, request_handler, NULL);

	fprintf(stderr, "[MAIN] Starting web server on port %d\n"
	    "[MAIN] Configure your browser to use this server as proxy.\n",
	    http_port);

	SPLAY_INIT(&root);

	event_dispatch();

	if (log_fd != -1)
		log_close(log_fd);

	exit (0);
}
