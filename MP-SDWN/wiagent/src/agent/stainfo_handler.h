/*
 * Handling the sta_info with controller oriented. 
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef STAINFO_HANDLER_H
#define STAINFO_HANDLER_H

#include "../utils/common.h"
#include "../ap/hostapd.h"

int wiagent_push_stainfo(struct hostapd_data *hapd, const u8 *addr);

int wiagent_add_stainfo(struct hostapd_data *hapd, 
        const u8 *addr, const char *stainfo);

int wiagent_remove_stainfo(struct hostapd_data *hapd, 
        const u8 *addr);

#endif
