/*
 * Wrapper libevent2 function.
 * Copyright (c) 2017 liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "common.h"
#include "wiagent_event.h"

static struct event_base *base = NULL;

static inline void check_event_base(void)
{
    if(!base) {
        base = event_base_new();
        if(!base) {
            wpa_printf(MSG_ERROR, "Could not initialize libevent!\n");
            exit(1);
        }
    }
}

struct event *wiagent_event_new(evutil_socket_t fd, short events, 
        void (*cb)(evutil_socket_t, short, void *), void *arg)
{
    check_event_base();
    return event_new(base, fd, events, cb, arg);
}

struct evconnlistener *wiagent_evconnlistener_new_bind(evconnlistener_cb cb, 
        void *ptr, unsigned flags, int backlog, 
        const struct sockaddr *sa, int socklen)
{
    check_event_base();

    return evconnlistener_new_bind(base, cb, ptr, flags, backlog, sa, socklen);
}

struct bufferevent *wiagent_bufferevent_socket_new(evutil_socket_t fd, int options)
{
    check_event_base();
    return bufferevent_socket_new(base, fd, options);
}

int wiagent_event_add(struct event *ev, const struct timeval *timeout)
{
    return event_add(ev, timeout);
}

int wiagent_event_dispatch(void)
{
    event_base_dispatch(base);
    event_base_free(base);
}
