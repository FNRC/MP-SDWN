/*
 * Controller's subscription
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "../utils/common.h"
#include "../ap/hostapd.h"
#include "../drivers/driver.h"
#include "../utils/wiagent_event.h"
#include "push.h"
#include "subscription.h"

static struct subscription *list_head = NULL;
static struct subscription *list_tail = NULL;

static void list_subscription(void)
{
    struct subscription *list = list_head;
    int num = 0;

    wpa_printf(MSG_DEBUG, "wiagent subscriptions list:");
    while (list) {
        wpa_printf(MSG_DEBUG, "%d. %d "MACSTR" %s %d %lf", 
                    ++num, list->id, MAC2STR(list->sta_addr), list->statistic, 
                    list->rel, list->val);
        list = list->next;
    }

}

static void handle_subscription(struct hostap_sta_list *sta_list)
{
    /* FIXME: subscription count and id */
    int count = 0;
    while (sta_list) {
        if (sta_list->sta_addr) {
            push_subscription(sta_list->sta_addr, 1, 1, sta_list->sta_data->last_rssi+100);
        }
        sta_list = sta_list->next;
    }
}

static void get_signal_strength(evutil_socket_t fd, short what, void *arg)
{
    struct hostap_sta_list sta_list_head;
    struct hostap_sta_list *list_temp;
    struct hostap_sta_list *list_temp_prev;
    struct hostapd_data *hapd = (struct hostapd_data *)arg;
    sta_list_head.next = NULL;
    
    hostapd_read_all_sta_data(hapd, &sta_list_head);

    handle_subscription(sta_list_head.next);
    
    list_temp = sta_list_head.next;
    while(list_temp) {
        list_temp_prev = list_temp;
        list_temp = list_temp->next;
        os_free(list_temp_prev->sta_data);
        os_free(list_temp_prev);
        list_temp_prev = NULL;
    }
}

void handle_signal_strength(struct hostapd_data *hapd)
{
    struct event *ev_signal;
    struct timeval tv_signal;

    /**
     * Add a timed event that get station's rssi value from 
     * struct station_info in kernel.
     */
    ev_signal = wiagent_event_new(-1, EV_TIMEOUT | EV_PERSIST, 
            get_signal_strength, hapd);
	tv_signal.tv_sec = 1;
    tv_signal.tv_usec = 0;
	wiagent_event_add(ev_signal, &tv_signal);
}

void add_subscription(struct hostapd_data *hapd, struct subscription *sub)
{
    if (list_tail) {
        list_tail->next = sub;
        list_tail = sub;
        sub->next = NULL;
    }
    else {
        list_tail = list_head = sub;
        sub->next = NULL;
    }

    /* FIXME: the code is not good. */
    handle_signal_strength(hapd);
}

