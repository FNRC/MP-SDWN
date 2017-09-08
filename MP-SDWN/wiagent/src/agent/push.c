/*
 * Push string data to controller.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/stat.h>
#include <netinet/in.h>                         // for sockaddr_in  
#include <sys/types.h>                          // for socket  
#include <sys/socket.h>                         // for socket 

#include <stdio.h>
#include <stdlib.h>                     
#include <string.h>                             // for memset
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

#include "../utils/common.h"
#include "vap.h"
#include "push.h"

static int udp_fd;

static int push(const char *data)
{
    if (data != NULL && udp_fd > 0) {
       if (write(udp_fd, data, strlen(data)) < 0) {
            return -1;
       }
       wpa_printf(MSG_DEBUG, "Push to the controller: %s", data);
       return 0;
    }
    return -1;
}

#define MAC_STR_LEN 17

#define PING "ping"
#define PROBE "probe"
#define STATION "station"
#define PUBLISH "publish"
#define DISASSOC "disassoc"
#define DEAUTH "deauth"

static void push_ping(void) 
{
    if (push(PING) > 0) {
        printf("ping controller.\n");
    }
}

void ping_timer(evutil_socket_t fd, short what, void *address)
{
    static bool first = true;

    if (first) {
        assert(fd > 0);
        udp_fd = fd;
        first = false;
    }
    else {
        push_ping(); 
    }
}

void push_subscription(const u8 *addr, 
        int count, int sub_id, int value)
{
    char str[256];
    sprintf(str, PUBLISH" "MACSTR" %d %d:%d", MAC2STR(addr), count, sub_id, value);
    push(str);
}

void push_disassoc(const u8 *addr, const char *ssid)
{
    char str[256];
    sprintf(str, DISASSOC" "MACSTR" %s", 
                    MAC2STR(addr), ssid);
    push(str);
}

void push_deauth(const u8 *addr, const int reason_code)
{
    char str[256];
    sprintf(str, DEAUTH" "MACSTR" %d", MAC2STR(addr), reason_code);
    push(str);
}

void wiagent_probe(const u8 *addr, const char *ssid)
{
    char str[128];

    if (ssid == NULL) 
        sprintf(str, PROBE" "MACSTR, MAC2STR(addr));
    else 
        sprintf(str, PROBE" "MACSTR" %s", MAC2STR(addr), ssid);
    
    push(str);
}

void push_stainfo(const u8 *addr, const char *stainfo)
{
    char *str;

    if (stainfo) {
        str = (char *)os_zalloc(strlen(STATION) + 1 + MAC_STR_LEN + 1 
                        + strlen(stainfo) + 1);
        sprintf(str, STATION" "MACSTR" %s", MAC2STR(addr), stainfo);
        push(str);
        os_free(str);
    }
    else {
        wpa_printf(MSG_INFO, "The "MACSTR" sta_info is null, unable to push to controller.", MAC2STR(addr));
    }
}

