/*
 * Processing data from the SDWN controller.
 * Copyright (c) 2017 liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CONTROLLER_EVENT_H
#define CONTROLLER_EVENT_H

#include <event2/bufferevent.h>
#include <event2/listener.h>

#define PUSH_PORT 2819
#define CONTROL_PORT 6777


int controller_event_init(struct hostapd_data *hapd, char *controller_ip);

/**
 * The function is called when listening a connection request 
 * from the SDWN controller.
 *
 */
void controller_listener_cb(struct evconnlistener *listener, 
        evutil_socket_t fd,
        struct sockaddr *sa, 
        int socklen, void *user_data);

#endif

