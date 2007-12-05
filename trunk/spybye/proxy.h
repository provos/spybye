/*
 * Copyright 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 */

#ifndef PROXY_H_
#define PROXY_H_

#define CONTROL_CALLBACK_URI	"/_spybye_control_callback"

struct evbuffer;
/* inject javascript that allows us to control what's going on on the page */
void inject_control_javascript(struct evbuffer *buffer);

/* serves the javascript which we control the spybye interaction */
void serve_control_javascript(struct evhttp_request *request, void *arg);

void handle_proxy_callback(struct evhttp_request *request, void *arg);
#endif /* PROXY_H_ */
