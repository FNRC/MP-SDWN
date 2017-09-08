/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef BEACON_H
#define BEACON_H

#include "hostapd.h"

struct channel_switch_params {
    u8 cs_mode;
    u8 channel;
    u8 cs_count;
};

struct beacon_settings {
    u8 *da;
    u8 *bssid;
    char *ssid;
    int ssid_len;
    int is_probe;
    int is_csa;
    struct channel_switch_params cs_params;
};

u16 hostapd_own_capab_info(struct hostapd_data *hapd, struct sta_info *sta,
			   int probe);
u8 * hostapd_eid_supp_rates(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_ext_supp_rates(struct hostapd_data *hapd, u8 *eid);
const u8 * wpa_auth_get_wpa_ie(struct wpa_authenticator *wpa_auth, size_t *len);
u8 * hostapd_eid_ht_capabilities(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_ext_capab(struct hostapd_data *hapd, u8 *eid);

int ieee802_11_build_ap_beacon(struct hostapd_data *hapd, struct beacon_settings *bs,
        struct wpa_driver_ap_params *params);

u8 * hostapd_eid_bss_max_idle_period(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_qos_map_set(struct hostapd_data *hapd, u8 *eid);					
u8 * generate_assoc_resp(struct hostapd_data *hapd, struct sta_info *sta, u8 *vbssid,
			    u16 status_code, int reassoc,int *frame_len);
				   
#endif
