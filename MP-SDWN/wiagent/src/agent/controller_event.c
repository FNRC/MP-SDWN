/*
 * Processing data from the controller.
 * Copyright (c) 2017 liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include <stdio.h>
#include <stdlib.h>                     
#include <string.h>                 // for memset
#include <assert.h>

#include <sys/socket.h>             //for inet_aton(...)
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../utils/common.h"
#include "../utils/wiagent_event.h"
#include "../ap/hostapd.h"
#include "../ap/config_file.h"
#include "../ap/beacon.h"
#include "vap.h"
#include "push.h"
#include "stainfo_handler.h"
#include "subscription.h"
#include "controller_event.h"

#define CONTROLLER_READ "READ"
#define CONTROLLER_WRITE "WRITE"

static struct bufferevent *bev;

int controller_event_init(struct hostapd_data *hapd, char *controller_ip)
{
    /**
     * libevent event.
     */
    struct event *ev_ping;
	struct timeval tv_ping;
    struct event *ev_vap_cleaner;
    struct timeval tv_vap_cleaner;
    struct evconnlistener *controller_listener;
	struct sockaddr_in sin;
    struct sockaddr_in push_addr;
    int push_sock;

    /**
     * Listening controller connection, which is 
     * used to send its control commands.
     */
    memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(CONTROL_PORT);
    controller_listener = wiagent_evconnlistener_new_bind(controller_listener_cb, hapd,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
	    (struct sockaddr*)&sin, sizeof(sin));
    
    if (!controller_listener) {
		wpa_printf(MSG_ERROR, "Could not create a controller's listener.");
		return -1;
	}
    
    /*
     * Timing send a ping message to controller.
     */
	memset(&push_addr, 0, sizeof(push_addr));
	push_addr.sin_family = AF_INET;
	if(inet_pton(push_addr.sin_family, controller_ip, &push_addr.sin_addr) != 1)
	{
		wpa_printf(MSG_ERROR, "Controller's ip address error.");
		return -1;
	}
	push_addr.sin_port = htons(PUSH_PORT);

    push_sock = socket(AF_INET, SOCK_DGRAM, 0);   //Using UDP socket.
    if (push_sock < 0) {
        wpa_printf(MSG_ERROR, "Failed to create Ping udp socket.");  
        return -1;
    }
    if(connect(push_sock, (struct sockaddr*)&push_addr, sizeof(push_addr) ) < 0) {
		wpa_printf(MSG_ERROR, "Error on connecting the controller with udp socket.");
		return -1;
	}
    
    /**
     * Add push_sock to event, send heartbeat packet regularly.
     */
    ev_ping = wiagent_event_new(push_sock, EV_TIMEOUT | EV_PERSIST, 
            ping_timer, NULL);
	tv_ping.tv_sec = 2;
    tv_ping.tv_usec = 0;
	wiagent_event_add(ev_ping, &tv_ping);

    ev_vap_cleaner = wiagent_event_new(push_sock, EV_TIMEOUT | EV_PERSIST, 
            wiagent_vap_cleaner, hapd->own_addr);
	tv_vap_cleaner.tv_sec = CLEANER_SECONDS;
    tv_vap_cleaner.tv_usec = 0;
	wiagent_event_add(ev_vap_cleaner, &tv_vap_cleaner);

    return 0;
}

static void controller_add_vap(struct hostapd_data *hapd, char *data[], int size)
{
    struct vap_data *vap;
    u8 addr[6];
    u8 bssid[6];

    if (hwaddr_aton(data[0], addr) < 0) {
        wpa_printf(MSG_WARN, "%s - convert string %s to MAC address failed.", __func__, data[0]);
        return;
    }
    if (hwaddr_aton(data[2], bssid) < 0) {
        wpa_printf(MSG_WARN, "%s - convert string %s to MAC address failed!", __func__, data[2]);
        return;
    }

    vap = wiagent_vap_add(hapd->own_addr, addr, bssid, data[3]);
    if(vap == NULL) {
        wpa_printf(MSG_WARN, "handler_add_vap cannot add vap!");
        return;
    }
    inet_aton(data[1], &vap->ipv4);
    vap->is_beacon = atoi(data[4]);
    wpa_printf(MSG_DEBUG, "%s - add vap %s success!", __func__, data[0]);

}

static void controller_remove_vap(struct hostapd_data *hapd, char *data[], int size)
{
    u8 addr[6];

    if (hwaddr_aton(data[0], addr) < 0) {
        wpa_printf(MSG_WARN, "%s - convert string %s to MAC address failed.", __func__, data[0]);
        return;
    }

    if (wiagent_vap_remove(hapd->own_addr, addr) == 0) {

        if (wiagent_remove_stainfo(hapd, addr) == 0)
            wpa_printf(MSG_DEBUG, "%s - remove (%s) vap and sta_info success!", __func__, data[0]);
    }
}

static void controller_action_csa(struct hostapd_data *hapd,
        char *data[], int size)
{
    u8 addr[6];
    u8 block_tx, new_channel, cs_count;
    struct vap_data *vap;
    int i;

    if (hwaddr_aton(data[0], addr) < 0) {
        wpa_printf(MSG_WARN, "%s - convert string %s to MAC address failed.", __func__, data[0]);
        return;
    }

    vap = wiagent_get_vap(addr);
    if (!vap) {
        wpa_printf(MSG_WARN, "There is no "MACSTR" vap data on wiagent!", MAC2STR(addr));
        return;
    }

    block_tx = (u8)atoi(data[1]);
    new_channel = (u8)atoi(data[2]);
    cs_count = (u8)atoi(data[3]);

    if (hostapd_send_csa_action_frame(hapd, addr, 
                vap->bssid, block_tx, new_channel, cs_count) < 0) {
        wpa_printf(MSG_WARN, "Failed to send CSA Action Frame.");
        return;
    }
}

static void controller_switch_channel(struct hostapd_data *hapd,
        char *data[], int size)
{
    u8 addr[6];
    struct vap_data *vap;
    u8 *beacon_data;
	struct wpa_driver_ap_params params;
    struct channel_switch_params cs_params;
	int beacon_len = 0;

    if (hwaddr_aton(data[0], addr) < 0) {
        wpa_printf(MSG_WARN, "%s - convert string %s to MAC address failed.", __func__, data[0]);
        return;
    }

    vap = wiagent_get_vap(addr);
    if (!vap) {
        wpa_printf(MSG_WARN, "There is no "MACSTR" vap data on wiagent!", MAC2STR(addr));
        return;
    }

    cs_params.cs_mode = (u8)atoi(data[1]);
    cs_params.channel = (u8)atoi(data[2]);
    cs_params.cs_count = (u8)atoi(data[3]);

    struct beacon_settings bs = {
        .da = vap->addr,
        .bssid = vap->bssid,
        .ssid = vap->ssid,
        .ssid_len = vap->ssid_len,
        .is_probe = 0,
        .is_csa = 1,
        .cs_params = cs_params
    };
	
    /**
     * Rebuild the vap's beacon frame, which containing the CSA element.
     */
    if (ieee802_11_build_ap_beacon(hapd, &bs, &params) < 0)
        return;
	
    beacon_len = params.head_len + params.tail_len;
	beacon_data = (u8 *)os_zalloc(beacon_len);
	os_memcpy(beacon_data, params.head, params.head_len);
    os_memcpy(beacon_data + params.head_len, params.tail, params.tail_len);
	os_free(params.head);
	os_free(params.tail);
    if (vap->beacon_data)
        os_free(vap->beacon_data);
    vap->beacon_data = beacon_data;
    vap->beacon_len = beacon_len;
}



static void controller_add_stainfo(struct hostapd_data *hapd,
        char *data[], int size)
{
    u8 addr[6];
    if (hwaddr_aton(data[0], addr) < 0) {
        wpa_printf(MSG_WARN, "%s: convert string %s to MAC address failed!n", __func__, data[0]);
        return;
    }

    if (wiagent_add_stainfo(hapd, addr, data[1]) < 0) {
        wpa_printf(MSG_WARN, "Fail to add sta_info %s.", data[0]);
        return;
    }
    wpa_printf(MSG_DEBUG, "Add sta_info %s successfully.", data[0]);

}

#define SUBSCRIPTION_PARAMS_NUM 6

static void controller_subscriptions(struct hostapd_data *hapd, 
        char *data[], int size)
{
    struct subscription *sub;
    int num_rows;
    int index = 0;
    
    if (size < SUBSCRIPTION_PARAMS_NUM) {
        wpa_printf(MSG_WARN, "The number of subscription parameters %d \
                is insufficient.", size);
        return;
    }
    //WRITE odinagent.subscriptions 1 1 00:00:00:00:00:00 signal 2 -30.0
    num_rows = atoi(data[index++]);

    /**
     * FIXME: Only one row of data is processed.
     */
    if (num_rows > 0) {
        sub = (struct subscription *)os_zalloc(sizeof(struct subscription));
        sub->id = atoi(data[index++]);
       
        if (strcmp(data[index], "*") == 0) {
            int i = 0;
            for(; i < 6; i++) 
                sub->sta_addr[i] = 0x0;
        }
        else if (hwaddr_aton(data[index], sub->sta_addr) < 0)
            goto fail;

        index++;
        strcpy(sub->statistic, data[index++]);
        sub->rel = atoi(data[index++]);
        sub->val = strtod(data[index++], NULL);
        add_subscription(hapd, sub);
    }
    return;

fail:
    os_free(sub);
    wpa_printf(MSG_WARN, "subscription data format error.");
    return;
}

static void handle_read(struct bufferevent *bev, 
                struct hostapd_data *hapd, char* arg) 
{
    char *write_str = "DATA 0\n";
    bufferevent_write(bev, write_str, strlen(write_str));
}


#define WRITE_ARGS_MAX 12

/**
 * Parsing write_handler string, 
 * the format is: "module.action station_mac others"
 * for example: 
 * "odinagent.add_vap 58:7F:66:DA:81:7C 0.0.0.0 00:1B:B3:DA:81:7C wiagent"
 */
void handle_write(struct hostapd_data *hapd, char* data)
{
    char *delim = ".";
    char *command;
    char *array[WRITE_ARGS_MAX];
    int size = 0; 
    
    command = strsep(&data, delim);
    if (strcmp(command, "odinagent") != 0) 
        return;

    delim = " ";
    for (command = strsep(&data, delim); command != NULL;
            command = strsep(&data, delim)) {

        if (strcmp(command, "") == 0)
            continue;

        array[size] = (char *)os_zalloc(strlen(command) + 1);
        strcpy(array[size], command);
        if (size == 1 && strcmp(array[0], "add_station") == 0) {
            array[++size] = (char *)os_zalloc(strlen(data) + 1);
            strcpy(array[size], data);
            break;
        }
        size++;
    }

    if (strcmp(array[0], "add_vap") == 0)
        controller_add_vap(hapd, &array[1], size);
    else if (strcmp(array[0], "remove_vap") == 0)
        controller_remove_vap(hapd, &array[1], size);
    else if (strcmp(array[0], "subscriptions") == 0)
        controller_subscriptions(hapd, &array[1], size);
    else if (strcmp(array[0], "add_station") == 0)
        controller_add_stainfo(hapd, &array[1], size);
    else if (strcmp(array[0], "switch_channel") == 0)
        controller_switch_channel(hapd, &array[1], size);

    for(;size > 0; size--) {
        os_free(array[size - 1]);
    }
}

void controller_readcb_line(struct bufferevent *bev, struct hostapd_data *hapd, 
                            char* data)
{
    char *command;
    char *delim = " ";

    command = strsep(&data, delim);  
    if (strcmp(command, CONTROLLER_READ) == 0) {
        handle_read(bev, hapd, data);
    }
    else if (strcmp(command, CONTROLLER_WRITE) == 0) {
        handle_write(hapd, data);
    }
}

/**
 * Callback function that handles the data received from controller.
 */
void controller_readcb(struct bufferevent *bev, struct hostapd_data *hapd)
{
    char *delim;
    char *line;
    char *cur;
    char read_buf[2048]={0};

    bufferevent_read(bev,read_buf,sizeof(read_buf));

    wpa_printf(MSG_DEBUG, "Received controller command: %s", read_buf);

    /**
     * Read and process every row of data.
     */
    cur = read_buf;
    delim = "\r\n";
    for (line = strsep(&cur, delim); line != NULL;
            line = strsep(&cur, delim)) {
        if (strcmp(line, "") == 0)
            continue;

        controller_readcb_line(bev, hapd, line);
    }
}

/**
 * Callback function that handles errors of 
 * the socket connection with controller.
 */
static void controller_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	if (events & BEV_EVENT_EOF) {
		wpa_printf(MSG_INFO, "Controller event callback, connection closed");
	} else if (events & BEV_EVENT_ERROR) {
		wpa_printf(MSG_INFO, "Controller event callback, got an error on the connection");
	}
	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
	bufferevent_free(bev);
}

/**
 * News a socket to receive the data from controller,
 * and sets the callback function for handling received data or 
 * errors of the socket connection.
 */
void controller_listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    struct hostapd_data *hapd = (struct hostapd_data *)user_data;

	bev = wiagent_bufferevent_socket_new(fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		wpa_printf(MSG_ERROR, "Error constructing bufferevent");
		return;
	}

	bufferevent_setcb(bev, controller_readcb, NULL, controller_eventcb, hapd);
	bufferevent_enable(bev, EV_READ);
}

