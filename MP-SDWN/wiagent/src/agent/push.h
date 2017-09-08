/*
 * Push string data to controller.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef PUSH_H
#define PUSH_H

#include "../ap/hostapd.h"

/**
 * Libevent timed callback function, which send ping 
 * data to inform controller the presence of agent.
 */
void ping_timer(int fd, short what, void *address);

void push_subscription(const u8 *addr, int count, int sub_id, int value);

void push_disassoc(const u8 *addr, const char *ssid);

void push_deauth(const u8 *addr, const int reason_code);

void wiagent_probe(const u8 *addr, const char *ssid);

void push_stainfo(const u8 *addr, const char *stainfo);

#endif
