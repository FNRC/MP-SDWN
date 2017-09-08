/*
 * wiagent - processe 802.11 management frames.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include "../drivers/nl80211_copy.h"
#include "beacon.h"
#include "../agent/stainfo_handler.h"
#include "../agent/vap.h"
#include "../agent/push.h"
#include "hostapd.h"
#include "wiagent_80211.h"

static int wiagent_handle_probe_req(struct hostapd_data *_hapd,u8 *da,u8 *bssid,
					const char *ssid,int ssid_len)
{
    u8 *packet;
    struct hostapd_data *hapd = _hapd;
	struct wpa_driver_ap_params params;
	int beacon_len = 0;


    struct vap_data *vap = wiagent_get_vap(da);
    if (vap == NULL) {
        wiagent_probe(da, ssid);
        return -1;
    }
    
    
    struct beacon_settings bs = {
        .da = vap->addr,
        .bssid = vap->bssid,
        .ssid = vap->ssid,
        .ssid_len = ssid_len,
        .is_probe = 1,
        .is_csa = 0
    };

    /**
     * Generating probe response frame.
     */
	ieee802_11_build_ap_beacon(hapd, &bs, &params);
	
    beacon_len = params.head_len + params.tail_len;
	packet = (u8 *)os_zalloc(beacon_len);//为beacon分配内存
	if (!packet)
		goto free_params;

	os_memcpy(packet, params.head, params.head_len);//复制beacon的头部
	os_memcpy(packet+params.head_len, params.tail, params.tail_len);//复制beacon的尾部

    if (hostapd_drv_send_mlme(hapd, packet, beacon_len, 1) < 0) {
		wpa_printf(MSG_DEBUG, "%s: send frame failed.", __func__);
        return -1;
    }
    
	os_free(params.head);
	os_free(params.tail);
	os_free(packet);

	return 0;

free_params:
	os_free(params.head);
	os_free(params.tail);
	os_free(packet);
	
    return -1;
}

static void
send_auth_reply(struct hostapd_data *hapd,
			    const u8 *dst, const u8 *bssid,
			    u16 auth_alg, u16 auth_transaction, u16 resp)
{
	struct ieee80211_mgmt *reply;
	u8 *buf;
	size_t rlen;

	rlen = IEEE80211_HDRLEN + sizeof(reply->u.auth);
	buf = os_zalloc(rlen);
	if (buf == NULL)
		return;

	reply = (struct ieee80211_mgmt *) buf;
	reply->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					    WLAN_FC_STYPE_AUTH);
	os_memcpy(reply->da, dst, ETH_ALEN);
	os_memcpy(reply->sa, bssid, ETH_ALEN);
	os_memcpy(reply->bssid, bssid, ETH_ALEN);

	reply->u.auth.auth_alg = host_to_le16(auth_alg);
	reply->u.auth.auth_transaction = host_to_le16(auth_transaction);
	reply->u.auth.status_code = host_to_le16(resp);

	if (hostapd_drv_send_mlme(hapd, (u8 *)reply, rlen, 0) < 0)
		wpa_printf(MSG_DEBUG, "%s: send frame failed.", __func__);

	os_free(buf);
}

static void wiagent_handle_auth(struct hostapd_data *hapd,
			const struct ieee80211_mgmt *mgmt, const char *ssid)
{
	u16 auth_alg, auth_transaction, status_code;
	u16 resp = WLAN_STATUS_SUCCESS;
	struct sta_info *sta = NULL;

    struct vap_data *vap = wiagent_get_vap(mgmt->sa);
    if (vap == NULL) {
        wiagent_probe(mgmt->sa, ssid);
        return;
    }
    vap->is_beacon = 1;

	auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
	auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	status_code = le_to_host16(mgmt->u.auth.status_code);

	sta = ap_sta_add(hapd, mgmt->sa);
	if (!sta) {
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		wpa_printf(MSG_INFO, "Fail to add "MACSTR" sta_info.", MAC2STR(mgmt->sa));
		return;
	}

	switch (auth_alg) {
	case WLAN_AUTH_OPEN:
		sta->flags |= WLAN_STA_AUTH;
		sta->auth_alg = WLAN_AUTH_OPEN;
		break;
	case WLAN_AUTH_SHARED_KEY:
		break;
	}

	send_auth_reply(hapd, mgmt->sa, mgmt->bssid, auth_alg,
			auth_transaction + 1, resp);
}

/***
 * probe response construct
 */
static int send_assoc_resp(struct hostapd_data *hapd, struct sta_info *sta, u16 status_code, int reassoc, u8 *vbssid)
{
    int send_len;
	u8 buf[sizeof(struct ieee80211_mgmt) + 1024];
	struct ieee80211_mgmt *reply;
	u8 *p;

	os_memset(buf, 0, sizeof(buf));
	reply = (struct ieee80211_mgmt *) buf;
	reply->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT,
			     (reassoc ? WLAN_FC_STYPE_REASSOC_RESP :
			      WLAN_FC_STYPE_ASSOC_RESP));

	os_memcpy(reply->da, sta->addr, ETH_ALEN);
	os_memcpy(reply->sa, vbssid, ETH_ALEN);
	os_memcpy(reply->bssid, vbssid, ETH_ALEN);//virtual bssid --nm
	
	send_len = IEEE80211_HDRLEN;
	send_len += sizeof(reply->u.assoc_resp);	
	reply->u.assoc_resp.capab_info =
		host_to_le16(hostapd_own_capab_info(hapd, sta, 0));
		
	reply->u.assoc_resp.status_code = host_to_le16(status_code);
	reply->u.assoc_resp.aid = host_to_le16(sta->aid | BIT(14) | BIT(15));
	
	/* Supported rates */
	p = hostapd_eid_supp_rates(hapd, reply->u.assoc_resp.variable);

	/* Extended supported rates */
	p = hostapd_eid_ext_supp_rates(hapd, p);

	p = hostapd_eid_ht_capabilities(hapd, p);
	p = hostapd_eid_ht_operation(hapd, p);

	p = hostapd_eid_ext_capab(hapd, p);
	//p = hostapd_eid_bss_max_idle_period(hapd, p);
	if (sta->qos_map_enabled)
		p = hostapd_eid_qos_map_set(hapd, p);
	//TODO:SDWN --nm 
	sta->flags |= WLAN_STA_WMM;
	if (sta->flags & WLAN_STA_WMM)
		p = hostapd_eid_wmm(hapd, p);
#ifdef CONFIG_WPS
	if ((sta->flags & WLAN_STA_WPS) ||
	    ((sta->flags & WLAN_STA_MAYBE_WPS) && hapd->conf->wpa)) {
		struct wpabuf *wps = wps_build_assoc_resp_ie();
		if (wps) {
			os_memcpy(p, wpabuf_head(wps), wpabuf_len(wps));
			p += wpabuf_len(wps);
			wpabuf_free(wps);
		}
	}
#endif /* CONFIG_WPS */

	send_len += p - reply->u.assoc_resp.variable;

	return hostapd_drv_send_mlme(hapd, reply, send_len, 0);
}

static void wiagent_handle_assoc(struct hostapd_data *hapd,
			 const struct ieee80211_mgmt *mgmt, size_t len,
			 int reassoc, u8 *vbssid)
{
	u16 capab_info, listen_interval;
	u16 resp = WLAN_STATUS_SUCCESS;
	const u8 *pos;
	int left, i;
	struct sta_info *sta;
    struct vap_data *vap;

	//头部检验:帧的总长度不小于头部的长度
	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req)) {
		wpa_printf(MSG_INFO, "handle_assoc(reassoc=%d) - too short payload (len=%lu)",
			   reassoc, (unsigned long) len);
		return;
	}
	if (reassoc) {
		capab_info = le_to_host16(mgmt->u.reassoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.reassoc_req.listen_interval);
		wpa_printf(MSG_DEBUG, "reassociation request: STA=" MACSTR
			   " capab_info=0x%02x listen_interval=%d current_ap="
			   MACSTR,
			   MAC2STR(mgmt->sa), capab_info, listen_interval,
			   MAC2STR(mgmt->u.reassoc_req.current_ap));
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req));
		pos = mgmt->u.reassoc_req.variable;
	} else {
		capab_info = le_to_host16(mgmt->u.assoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.assoc_req.listen_interval);
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
		pos = mgmt->u.assoc_req.variable;
	}
    
    vap = wiagent_get_vap(mgmt->sa);
    if (vap == NULL) {
        wpa_printf(MSG_DEBUG, MACSTR" vap is null, error on association.", MAC2STR(mgmt->sa));
        return;
    }

	sta = ap_get_sta(hapd, mgmt->sa);
	if (sta == NULL || (sta->flags & WLAN_STA_AUTH) == 0) {
		//send_deauth(hapd, mgmt->sa,
		//	    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
        wpa_printf(MSG_DEBUG, "staion is null or association has not authriened.");
		return;
	}

	if (listen_interval > hapd->conf->max_listen_interval) {
		wpa_printf(MSG_DEBUG, "Too large Listen Interval (%d)",
			       listen_interval);
		resp = WLAN_STATUS_ASSOC_DENIED_LISTEN_INT_TOO_LARGE;
		goto fail;
	}

	/* followed by SSID and Supported rates; and HT capabilities if 802.11n
	 * is used */
	resp = check_assoc_ies(hapd, sta, pos, left, reassoc);
	if (resp != WLAN_STATUS_SUCCESS) {
        wpa_printf(MSG_DEBUG,"resp != WLAN_STATUS_SUCCESS.");
		goto fail;
    }

	if (hostapd_get_aid(hapd, sta) < 0) {
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
        wpa_printf(MSG_DEBUG,"hostapd_get_aid failed");
		goto fail;
	}

	sta->capability = capab_info;
	sta->listen_interval = listen_interval;

	if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G)
		sta->flags |= WLAN_STA_NONERP;
	for (i = 0; i < sta->supported_rates_len; i++) {
		if ((sta->supported_rates[i] & 0x7f) > 22) {
			sta->flags &= ~WLAN_STA_NONERP;
			break;
		}
	}

    /* 重新设置beacon帧
	if (sta->flags & WLAN_STA_NONERP && !sta->nonerp_set) {
		sta->nonerp_set = 1;
		hapd->iface->num_sta_non_erp++;
		if (hapd->iface->num_sta_non_erp == 1)
			ieee802_11_set_beacons(hapd->iface);
	}
    */

    /*如果不使用短间隔，则重新设置beacon帧
	if (!(sta->capability & WLAN_CAPABILITY_SHORT_SLOT_TIME) &&
	    !sta->no_short_slot_time_set) {
		sta->no_short_slot_time_set = 1;
		hapd->iface->num_sta_no_short_slot_time++;
		if (hapd->iface->current_mode->mode ==
		    HOSTAPD_MODE_IEEE80211G &&
		    hapd->iface->num_sta_no_short_slot_time == 1)
			ieee802_11_set_beacons(hapd->iface);
	}
    */

	if (sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE)
		sta->flags |= WLAN_STA_SHORT_PREAMBLE;
	else
		sta->flags &= ~WLAN_STA_SHORT_PREAMBLE;

    /* 如果不支持短前导码，则重新设置beacon帧
	if (!(sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE) &&
	    !sta->no_short_preamble_set) {
		sta->no_short_preamble_set = 1;
		hapd->iface->num_sta_no_short_preamble++;
		if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G
		    && hapd->iface->num_sta_no_short_preamble == 1)
			ieee802_11_set_beacons(hapd->iface);
	}
    */

	/* Station will be marked associated, after it acknowledges AssocResp
	 */
	sta->flags |= WLAN_STA_ASSOC_REQ_OK;
    sta->flags |= WLAN_STA_AUTHORIZED;  //kernel will use --nm

	/* Make sure that the previously registered inactivity timer will not
	 * remove the STA immediately. */
	sta->timeout_next = STA_NULLFUNC;

	if (send_assoc_resp(hapd, sta, resp, reassoc, vbssid) < 0) {
	   wpa_printf(MSG_DEBUG, "Failed to send assoc resp: %s",
			   strerror(errno)); 
       return;
    }

    hostapd_handle_assoc_cb(hapd, mgmt->sa);//通知内核添加sta_info

    /**
     * Convert struct sta_info to a json string format,
     * then push this json to controller.
     */
    wiagent_push_stainfo(hapd, mgmt->sa);

    return;

fail:
    wpa_printf(MSG_DEBUG,"handle_assoc failed\n");
	return;
}

static void wiagent_handle_disassoc(struct hostapd_data *hapd,
			const struct ieee80211_mgmt *mgmt, const char *ssid)
{
    struct vap_data *vap = wiagent_get_vap(mgmt->sa);
    if (vap == NULL)
        return;
    
    push_disassoc(vap->addr, vap->ssid);

}

static void wiagent_handle_deauth(struct hostapd_data *hapd,
			const struct ieee80211_mgmt *mgmt)
{
    int reason_code;
    struct vap_data *vap = wiagent_get_vap(mgmt->sa);
    if (vap == NULL)
        return;

    reason_code = le_to_host16(mgmt->u.deauth.reason_code);
    wpa_printf(MSG_DEBUG, "The station "MACSTR" deauthentication, reason_code=%d.", 
            MAC2STR(mgmt->sa), reason_code);
 
    push_deauth(vap->addr, reason_code);
}

static int wiagent_handle_beacon(struct hostapd_data *hapd, struct vap_data *vap)
{
	u8 *packet;
	struct wpa_driver_ap_params params;
	int packet_len = 0;
    struct beacon_settings bs = {
        .da = vap->addr,
        .bssid = vap->bssid,
        .ssid = vap->ssid,
        .ssid_len = vap->ssid_len,
        .is_probe = 0,
        .is_csa = 0
    };

	if (ieee802_11_build_ap_beacon(hapd, &bs, &params) < 0)
        return -1;
	
    packet_len = params.head_len + params.tail_len;
	packet = (u8 *)os_zalloc(packet_len);//为beacon分配内存
	os_memcpy(packet, params.head, params.head_len);//复制beacon的头部
    os_memcpy(packet+params.head_len, params.tail, params.tail_len);//复制beacon的尾部
	os_free(params.head);
	os_free(params.tail);

    vap->beacon_data = packet;
    vap->beacon_len = packet_len;
    return 0;
}


static void vap_send_beacon_cb(struct vap_data *vap, void *ctx)
{
    struct hostapd_data *hapd = (struct hostapd_data *)ctx;

    if (vap->is_beacon) {
        if (!vap->beacon_data) {
           if (wiagent_handle_beacon(hapd, vap) < 0) {
                wpa_printf(MSG_DEBUG, "Unable to handle ("MACSTR") beacon, send failed.", 
                        MAC2STR(vap->addr));
                return;
           }
        }

        if (hostapd_drv_send_mlme(hapd, vap->beacon_data, vap->beacon_len, 1) < 0) {
            wpa_printf(MSG_DEBUG, "%s: send frame failed.", __func__);
            return;
        }
    }
}

void wiagent_send_beacon(evutil_socket_t fd, short what, void *arg)
{
    struct hostapd_data *hapd = (struct hostapd_data *)arg;
    
    wiagent_for_each_vap(vap_send_beacon_cb, hapd);

    return;
}

static int wiagent_mgmt_rx(struct hostapd_data *hapd, struct rx_mgmt *rx_mgmt)
{
    struct ieee80211_mgmt *mgmt;
	u16 fc, stype;
    int len; 
    char *ssid = "wiagent";
 
    mgmt = (struct ieee80211_mgmt *)rx_mgmt->frame;
    len = rx_mgmt->frame_len;
	if (len < 24)
		return 0;

	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

    push_subscription(mgmt->sa, 1, 1, rx_mgmt->ssi_signal + 100);

    switch (stype) {
        case WLAN_FC_STYPE_PROBE_REQ:
            wiagent_handle_probe_req(hapd, mgmt->sa, hapd->own_addr,
                    ssid, strlen(ssid));
            break;
        case WLAN_FC_STYPE_AUTH:
            wiagent_handle_auth(hapd, mgmt, ssid);
            break;
        case WLAN_FC_STYPE_DEAUTH:
            wiagent_handle_deauth(hapd, mgmt);
            break;
        case WLAN_FC_STYPE_ASSOC_REQ:
            wiagent_handle_assoc(hapd, mgmt, len, 0, mgmt->bssid);
            break;
        case WLAN_FC_STYPE_DISASSOC:
            break;
        case WLAN_FC_STYPE_REASSOC_RESP:
            wiagent_handle_assoc(hapd, mgmt, len, 1, mgmt->bssid);
            break;
        case WLAN_FC_STYPE_ACTION:
            break;
    }

    return 0;

}

void wiagent_wpa_event(void *ctx, enum wpa_event_type event,
		       union wpa_event_data *data)
{
	struct hostapd_data *hapd = ctx;

	switch (event) {
	case EVENT_TX_STATUS:
		switch (data->tx_status.type) {
		case WLAN_FC_TYPE_MGMT:
			break;
		case WLAN_FC_TYPE_DATA:
			break;
		}
		break;
	case EVENT_RX_FROM_UNKNOWN:
		break;
	case EVENT_RX_MGMT:
		if (!data->rx_mgmt.frame)
			break;
		if (wiagent_mgmt_rx(hapd, &data->rx_mgmt) > 0)
			break;
    }
}

