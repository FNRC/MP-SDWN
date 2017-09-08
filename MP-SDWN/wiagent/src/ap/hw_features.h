/*
 * hostapd / Hardware feature query and different modes
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HW_FEATURES_H
#define HW_FEATURES_H

#include "hostapd.h"

char * dfs_info(struct hostapd_channel_data *chan);

void hostapd_free_hw_features(struct hostapd_hw_modes *hw_features,
			      size_t num_hw_features);
struct hostapd_hw_modes *
hostapd_get_hw_feature_data(struct hostapd_data *hapd, u16 *num_modes,
			    u16 *flags);
int hostapd_select_hw_mode(struct hostapd_iface *iface);

int hostapd_get_hw_features(struct hostapd_iface *iface);

int hostapd_hw_get_freq(struct hostapd_data *hapd, int chan);
//drv_ops
int hostapd_set_freq_params(struct hostapd_freq_params *data, int mode,
			    int freq, int channel, int ht_enabled,
			    int vht_enabled, int sec_channel_offset,
			    int vht_oper_chwidth, int center_segment0,
			    int center_segment1, u32 vht_caps);
int hostapd_set_freq(struct hostapd_data *hapd, int mode, int freq,
		     int channel, int ht_enabled, int vht_enabled,
		     int sec_channel_offset, int vht_oper_chwidth,
		     int center_segment0, int center_segment1);
int hostapd_rate_found(int *list, int rate);
int hostapd_prepare_rates(struct hostapd_iface *iface,
			  struct hostapd_hw_modes *mode);
const char * hostapd_hw_mode_txt(int mode);			  
int hostapd_setup_interface_complete(struct hostapd_iface *iface, int err);

#endif

