/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef VIRUS_H_
#define VIRUS_H_

/* very simple - no timeout nothing */
struct scanctx {
	TAILQ_ENTRY(scanctx) next;

	void (*cb)(const char *, void *);
	void *cb_arg;

	struct event ev_timeout;
};
TAILQ_HEAD(scanctxq, scanctx);

struct virus_child {
	TAILQ_ENTRY(virus_child) next;

	pid_t pid;

	struct bufferevent *bev;
	int fd;
};

TAILQ_HEAD(virusq, virus_child);

#define NUM_VIRUS_CHILDREN	2

int virus_init();

void virus_scan_buffer(char *buffer, size_t buflen,
    void (*cb)(const char *, void *), void *cb_arg);

#endif /* VIRUS_H_ */
