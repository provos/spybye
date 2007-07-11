/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef STATUS_H_
#define STATUS_H_

#ifndef HTTP_SERVUNAVAIL
#define	HTTP_SERVUNAVAIL	503
#endif

#define MAX_RECENT_RESULTS	50
#define IDLE_TIME	10

struct pattern {
	TAILQ_ENTRY(pattern) next;

	char *pattern_host;
	char *pattern_uri;
};

TAILQ_HEAD(patternq, pattern);

/* structure where we keep track of patterns */
struct pattern_obj {
	const char *location;
	struct patternq head;
	int count;
	struct timeval tv_load;

	struct evhttp_connection *evcon;
	struct event ev_refresh;
};

#define PATTERN_REFRESH_SECONDS	3600	/* once an hour - is that too often */

struct site;
struct site_callback {
	TAILQ_ENTRY(site_callback) (next);

        void (*cb)(struct site *, void *);
	void *cb_arg;
};

#define STATE_EXPIRATION_TIME	500

struct site {
	SPLAY_ENTRY(site) (node);
	TAILQ_ENTRY(site) (next);
	
	char *url;
	struct site *parent;

	int flags;
#define ANALYSIS_COMPLETE	0x01

	TAILQ_HEAD(siteq, site) (children);
	TAILQ_HEAD(callbackq, site_callback) callbacks;

	enum DANGER_TYPES {
		HARMLESS = 0,
		UNKNOWN = 1,
		DANGEROUS = 2
	} danger;

	char *firstline;	/* first line from http server */
	char *html_data;	/* delivered data */
	size_t html_size;

	char *virus_result;

	struct timeval tv_change;

	struct event ev_timeout;
	struct event ev_complete;
};

struct stats {
	int num_requests;
	int num_harmless;
	int num_unknown;
	int num_dangerous;
};

int spybye_handle_request(struct evhttp_request *request, void *arg);

void status_init(const char *goodness, const char *badness);
struct site *site_new(const char *url, const char *parent_url);
void site_free(struct site *site);
struct site *site_find(const char *url);
void site_complete(int fd, short what, void *arg);

void site_cache_data(struct site *site, const struct evhttp_request *req);

int site_matches_bad_patterns(struct site *site);

void status_good_patterns(struct evbuffer *data);
void status_bad_patterns(struct evbuffer *data);

enum DANGER_TYPES site_analyze_danger(struct site *site);
const char *danger_to_text(enum DANGER_TYPES danger);

void site_make_dangerous(struct site *site);

void site_disassociate_parent(struct site *site);

void site_insert_callback(struct site *site,
    void (*cb)(struct site *, void *), void *cb_arg);

#endif /* STATUS_H_ */
