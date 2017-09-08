/*
 * Controller's subscription 
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SUBSCRIPTION_H
#define SUBSCRIPTION_H

enum relation_t {
    EQUALS, GREATER_THAN, LESSER_THAN
};

struct subscription {
    int id;
    u8 sta_addr[6];
    char statistic[32];
    int rel;
    double val;

    struct subscription *next;
};

void add_subscription(struct hostapd_data *hapd, struct subscription *sub);

void remove_subscription(int sub_id);

void clear_subscriptions(void);

struct subscription * get_subscription(int sub_id);

#endif
