/*
 * wiagent - processe 802.11 management frames.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef wiagent_80211_H
#define wiagent_80211_H

#include "../utils/common.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <event2/util.h>

/**
 * This function is the first function to process
 * the received management frame, the previous function
 * mainly passes the frame.
 */
void wiagent_wpa_event(void *ctx, enum wpa_event_type event,
		       union wpa_event_data *data);

/**
 * This function would be called when send beacon frames at the set time.
 */
void wiagent_send_beacon(evutil_socket_t fd, short what, void *arg);

#endif
