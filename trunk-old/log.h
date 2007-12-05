/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef LOG_H_
#define LOG_H_

/* simple debugging help */
extern int debug;
#define DNFPRINTF(x, y) if (debug >= x) fprintf y;

struct spybye_share {
	struct evhttp_connection *evcon_report;
	char *host;
	char *uri;
};

struct evhttp_request;
struct site;
void log_request(int level, struct evhttp_request *req, struct site *site);

void log_establish_sharing(struct spybye_share *share, const char *url);
void log_share_report(struct spybye_share *share, struct evbuffer *data);

int log_init(const char *filename);
void log_close(int fd);

void log_dangerous_request(int log_fd,
    struct evhttp_request *req, struct site *site);

/*
 * creates a dangerous load object from the request and also stores
 * information about the client itself
 */
void log_dangerous_report(int log_fd,
    struct evhttp_request *req, struct site *site);

/* a report from a remote client */
void log_external_report(int log_fd, struct evhttp_request *req);

/* reads all instances from the log */
int log_dangerous_read(const char *filename);

#define DANGEROUS_TAG		0x01
#define DANGEROUS_REPORT_TAG	0x02

struct dangerous_container {
	TAILQ_ENTRY(dangerous_container) (next);
	struct dangerousload *dl;
};

TAILQ_HEAD(dangerq, dangerous_container);

#endif /* LOG_H_ */
