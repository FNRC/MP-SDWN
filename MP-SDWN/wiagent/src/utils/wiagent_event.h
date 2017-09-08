/*
 * Wrapper libevent2 function.
 * Copyright (c) 2017 liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef wiagent_EVENT_H
#define wiagent_EVENT_H

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

/**
 * Wrapper function - event_new.
 */
struct event *wiagent_event_new(evutil_socket_t fd, short events, 
        void (*cb)(evutil_socket_t, short, void *), void *arg);

/**
 * Wrapper function - evconnlistenner_new_bind
 */
struct evconnlistener *wiagent_evconnlistener_new_bind(evconnlistener_cb cb, 
        void *ptr, unsigned flags, int backlog, 
        const struct sockaddr *sa, int socklen);

/**
 * Wrapper function - bufferevent_socket_new
 */
struct bufferevent *wiagent_bufferevent_socket_new(evutil_socket_t fd, int options);

/**
 * Wrapper function - event_add
 */
int wiagent_event_add(struct event *ev, const struct timeval *timeout);

/**
 * To run the event loop
 */
int wiagent_event_dispatch(void);

#endif
