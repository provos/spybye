/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef SPYBYE_H_
#define SPYBYE_H_

#define SPYBYE_HOST "spybye"

#define SPYBYE_CONNECTION_TIMEOUT	120

struct request_holder {
	struct evkeyvalq *headers;
	int response_code;
	char *response_line;
	struct evbuffer *buffer;
};

struct proxy_request {
	TAILQ_ENTRY(proxy_request) (next);

	struct evhttp_request *req;
        struct evhttp_connection *evcon;			  

	struct request_holder *holder;

	u_short port;			   
        char *uri;
};

struct dns_cache {
	SPLAY_ENTRY(dns_cache) node;

	char *name;

        TAILQ_HEAD(requestqueue, proxy_request) entries;

	struct in_addr *addresses;					
	int address_count;

        struct event ev_timeout;
};

struct dns_cache *dns_new(const char *name);
void dns_free(struct dns_cache *entry);

struct proxy_request *proxy_request_new(
	struct evhttp_request *req, u_short port, char *uri);
void proxy_request_free(struct proxy_request *);

#endif /* SPYBYE_H_ */
