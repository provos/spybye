/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef UTILS_H_
#define UTILS_H_

#define USER_AGENT		"SpyBye/"VERSION
#define HTTP_PREFIX		"http://"
#define HTTP_DEFAULTPORT	80
#define HTTP_MAX_URL		2048

int http_hostportfile(const char *url,
    char **phost, u_short *pport, char **pfile);
int match_url(
	const char *url, const char *pattern_host, const char *pattern_uri);

struct evbuffer *read_data(const char *filename);
struct evbuffer *read_from_web(const char *url);

/* low-level function to read the contents of the specified url */
struct evhttp_connection *read_from_web_prepare(const char *url,
    void (*cb)(struct evhttp_request *, void *), void *cb_arg);

/* sanitizies some stupid javascript - this is not meant to be secure */
void sanitize_content(struct evhttp_request *req);

int check_private_ip(void *addresses, int count);

#endif /* UTILS_H_ */
