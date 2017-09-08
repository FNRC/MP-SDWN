/*
 * hostapd / IEEE 802.11 Management: Beacon and Probe Request/Response
 * Copyright (c) 2002-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008-2012, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2017, niming
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "beacon.h"
#include "wpabuf.h"



//ieee802_11.c get beacon info filed
u16 hostapd_own_capab_info(struct hostapd_data *hapd, struct sta_info *sta,
			   int probe)
{
	int capab = WLAN_CAPABILITY_ESS;
	int privacy;
	int dfs;

	/* Check if any of configured channels require DFS 
	dfs = hostapd_is_dfs_required(hapd->iface);
	if (dfs < 0) {
		wpa_printf(MSG_WARNING, "Failed to check if DFS is required; ret=%d",
			   dfs);
		dfs = 0;
	}
    */
	if (hapd->iface->num_sta_no_short_preamble == 0 &&
	    hapd->iconf->preamble == SHORT_PREAMBLE)
		capab |= WLAN_CAPABILITY_SHORT_PREAMBLE;

	privacy = hapd->conf->ssid.wep.keys_set;

	if (hapd->conf->ieee802_1x &&
	    (hapd->conf->default_wep_key_len ||
	     hapd->conf->individual_wep_key_len))
		privacy = 1;

	if (hapd->conf->wpa)
		privacy = 1;

#ifdef CONFIG_HS20
	if (hapd->conf->osen)
		privacy = 1;
#endif /* CONFIG_HS20 */

	//����beacon��ʱ��sta��NULL��,sta->ssid->����δ��ʼ������NULL���׳���
	/*
	if (sta) {

		int policy, def_klen;
		if (probe && sta->ssid_probe) {
			policy = sta->ssid_probe->security_policy;
			def_klen = sta->ssid_probe->wep.default_len;
		} else {
			policy = sta->ssid->security_policy;
			def_klen = sta->ssid->wep.default_len;
		}
		privacy = policy != SECURITY_PLAINTEXT;
		if (policy == SECURITY_IEEE_802_1X && def_klen == 0)
			privacy = 0;
	}
	*/
	
	if (privacy)
		capab |= WLAN_CAPABILITY_PRIVACY;

	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G &&
	    hapd->iface->num_sta_no_short_slot_time == 0)
		capab |= WLAN_CAPABILITY_SHORT_SLOT_TIME;

	/*
	 * Currently, Spectrum Management capability bit is set when directly
	 * requested in configuration by spectrum_mgmt_required or when AP is
	 * running on DFS channel.
	 * TODO: Also consider driver support for TPC to set Spectrum Mgmt bit
	 */
	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211A &&
	    (hapd->iconf->spectrum_mgmt_required || dfs))
		capab |= WLAN_CAPABILITY_SPECTRUM_MGMT;
	return capab;
}
//ieee802_11.c
u8 * hostapd_eid_supp_rates(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	int i, num, count;

	if (hapd->iface->current_rates == NULL)
		return eid;

	*pos++ = WLAN_EID_SUPP_RATES;
	num = hapd->iface->num_rates;
	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht)
		num++;
	if (hapd->iconf->ieee80211ac && hapd->iconf->require_vht)
		num++;
	if (num > 8) {
		/* rest of the rates are encoded in Extended supported
		 * rates element */
		num = 8;
	}

	*pos++ = num;
	for (i = 0, count = 0; i < hapd->iface->num_rates && count < num;
	     i++) {
		count++;
		*pos = hapd->iface->current_rates[i].rate / 5;
		if (hapd->iface->current_rates[i].flags & HOSTAPD_RATE_BASIC)
			*pos |= 0x80;
		pos++;
	}
	//require_ht�²�Ĭ�ϵ�Ϊ�� 
	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht && count < 8) {
		count++;
		*pos++ = 0x80 | BSS_MEMBERSHIP_SELECTOR_HT_PHY;
	}

	if (hapd->iconf->ieee80211ac && hapd->iconf->require_vht && count < 8) {
		count++;
		*pos++ = 0x80 | BSS_MEMBERSHIP_SELECTOR_VHT_PHY;
	}

	return pos;
}

//beacon.c
static u8 * hostapd_eid_ds_params(struct hostapd_data *hapd, u8 *eid)
{
	*eid++ = WLAN_EID_DS_PARAMS;
	*eid++ = 1;
	*eid++ = hapd->iconf->channel;
	return eid;
}

/***country*   beacon.c **/

static u8 * hostapd_eid_country_add(u8 *pos, u8 *end, int chan_spacing,
				    struct hostapd_channel_data *start,
				    struct hostapd_channel_data *prev)
{
	if (end - pos < 3)
		return pos;

	/* first channel number */
	*pos++ = start->chan;
	/* number of channels */
	*pos++ = (prev->chan - start->chan) / chan_spacing + 1;
	/* maximum transmit power level */
	*pos++ = start->max_tx_power;

	return pos;
}


static u8 * hostapd_eid_country(struct hostapd_data *hapd, u8 *eid,
				int max_len)
{
	u8 *pos = eid;
	u8 *end = eid + max_len;
	int i;
	struct hostapd_hw_modes *mode;
	struct hostapd_channel_data *start, *prev;
	int chan_spacing = 1;

	if (!hapd->iconf->ieee80211d || max_len < 6 ||
	    hapd->iface->current_mode == NULL)
		return eid;

	*pos++ = WLAN_EID_COUNTRY;
	pos++; /* length will be set later */
	os_memcpy(pos, hapd->iconf->country, 3); /* e.g., 'US ' */
	pos += 3;

	mode = hapd->iface->current_mode;
	if (mode->mode == HOSTAPD_MODE_IEEE80211A)
		chan_spacing = 4;

	start = prev = NULL;
	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan = &mode->channels[i];
		if (chan->flag & HOSTAPD_CHAN_DISABLED)
			continue;
		if (start && prev &&
		    prev->chan + chan_spacing == chan->chan &&
		    start->max_tx_power == chan->max_tx_power) {
			prev = chan;
			continue; /* can use same entry */
		}

		if (start) {
			pos = hostapd_eid_country_add(pos, end, chan_spacing,
						      start, prev);
			start = NULL;
		}

		/* Start new group */
		start = prev = chan;
	}

	if (start) {
		pos = hostapd_eid_country_add(pos, end, chan_spacing,
					      start, prev);
	}

	if ((pos - eid) & 1) {
		if (end - pos < 1)
			return eid;
		*pos++ = 0; /* pad for 16-bit alignment */
	}

	eid[1] = (pos - eid) - 2;

	return pos;
}

/**/


/******poewr **/
static u8 * hostapd_eid_pwr_constraint(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	u8 local_pwr_constraint = 0;
	int dfs;

	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211A)
		return eid;

	/*
	 * There is no DFS support and power constraint was not directly
	 * requested by config option.
	 */
	if (!hapd->iconf->ieee80211h &&
	    hapd->iconf->local_pwr_constraint == -1)
		return eid;

	/* Check if DFS is required by regulatory. 
	dfs = hostapd_is_dfs_required(hapd->iface);
	if (dfs < 0) {
		wpa_printf(MSG_WARNING, "Failed to check if DFS is required; ret=%d",
			   dfs);
		dfs = 0;
	}

	if (dfs == 0 && hapd->iconf->local_pwr_constraint == -1)
		return eid;
	*/
	/*
	 * ieee80211h (DFS) is enabled so Power Constraint element shall
	 * be added when running on DFS channel whenever local_pwr_constraint
	 * is configured or not. In order to meet regulations when TPC is not
	 * implemented using a transmit power that is below the legal maximum
	 * (including any mitigation factor) should help. In this case,
	 * indicate 3 dB below maximum allowed transmit power.
	 */
	if (hapd->iconf->local_pwr_constraint == -1)
		local_pwr_constraint = 3;

	/*
	 * A STA that is not an AP shall use a transmit power less than or
	 * equal to the local maximum transmit power level for the channel.
	 * The local maximum transmit power can be calculated from the formula:
	 * local max TX pwr = max TX pwr - local pwr constraint
	 * Where max TX pwr is maximum transmit power level specified for
	 * channel in Country element and local pwr constraint is specified
	 * for channel in this Power Constraint element.
	 */

	/* Element ID */
	*pos++ = WLAN_EID_PWR_CONSTRAINT;
	/* Length */
	*pos++ = 1;
	/* Local Power Constraint */
	if (local_pwr_constraint)
		*pos++ = local_pwr_constraint;
	else
		*pos++ = hapd->iconf->local_pwr_constraint;

	return pos;
}

/***/


/****erp*** beacon.c****/
static u8 ieee802_11_erp_info(struct hostapd_data *hapd)
{
	u8 erp = 0;

	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211G)
		return 0;

	if (hapd->iface->olbc)
		erp |= ERP_INFO_USE_PROTECTION;
	if (hapd->iface->num_sta_non_erp > 0) {
		erp |= ERP_INFO_NON_ERP_PRESENT |
			ERP_INFO_USE_PROTECTION;
	}
	if (hapd->iface->num_sta_no_short_preamble > 0 ||
	    hapd->iconf->preamble == LONG_PREAMBLE)
		erp |= ERP_INFO_BARKER_PREAMBLE_MODE;

	return erp;
}

static u8 * hostapd_eid_erp_info(struct hostapd_data *hapd, u8 *eid)
{
	if (hapd->iface->current_mode == NULL ||
	    hapd->iface->current_mode->mode != HOSTAPD_MODE_IEEE80211G)
		return eid;

	/* Set NonERP_present and use_protection bits if there
	 * are any associated NonERP stations. */
	/* TODO: use_protection bit can be set to zero even if
	 * there are NonERP stations present. This optimization
	 * might be useful if NonERP stations are "quiet".
	 * See 802.11g/D6 E-1 for recommended practice.
	 * In addition, Non ERP present might be set, if AP detects Non ERP
	 * operation on other APs. */

	/* Add ERP Information element */
	*eid++ = WLAN_EID_ERP_INFO;
	*eid++ = 1;
	*eid++ = ieee802_11_erp_info(hapd);

	return eid;
}

/****/


/***ex rate** ieee80211.c**/

u8 * hostapd_eid_ext_supp_rates(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	int i, num, count;

	if (hapd->iface->current_rates == NULL)
		return eid;

	num = hapd->iface->num_rates;
	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht)
		num++;
	if (hapd->iconf->ieee80211ac && hapd->iconf->require_vht)
		num++;
	if (num <= 8)
		return eid;
	num -= 8;

	*pos++ = WLAN_EID_EXT_SUPP_RATES;
	*pos++ = num;
	for (i = 0, count = 0; i < hapd->iface->num_rates && count < num + 8;
	     i++) {
		count++;
		if (count <= 8)
			continue; /* already in SuppRates IE */
		*pos = hapd->iface->current_rates[i].rate / 5;
		if (hapd->iface->current_rates[i].flags & HOSTAPD_RATE_BASIC)
			*pos |= 0x80;
		pos++;
	}

	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht) {
		count++;
		if (count > 8)
			*pos++ = 0x80 | BSS_MEMBERSHIP_SELECTOR_HT_PHY;
	}

	if (hapd->iconf->ieee80211ac && hapd->iconf->require_vht) {
		count++;
		if (count > 8)
			*pos++ = 0x80 | BSS_MEMBERSHIP_SELECTOR_VHT_PHY;
	}

	return pos;
}

/****/



/**wpa**/

/*
const u8 * wpa_auth_get_wpa_ie(struct wpa_authenticator *wpa_auth, size_t *len)
{
	if (wpa_auth == NULL)
		return NULL;
	*len = wpa_auth->wpa_ie_len;
	return wpa_auth->wpa_ie;
}
static u8 * hostapd_eid_wpa(struct hostapd_data *hapd, u8 *eid, size_t len)
{
	const u8 *ie;
	size_t ielen;

	ie = wpa_auth_get_wpa_ie(hapd->wpa_auth, &ielen);
	if (ie == NULL || ielen > len)
		return eid;

	os_memcpy(eid, ie, ielen);
	return eid + ielen;
}
*/
/**/

/***802111n *ieee802_11_ht.c**/

u8 * hostapd_eid_ht_capabilities(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_ht_capabilities *cap;
	u8 *pos = eid;

	if (!hapd->iconf->ieee80211n || !hapd->iface->current_mode ||
	    hapd->conf->disable_11n){
		fprintf(stderr,"hostapd_eid_ht_capabilities return\n");
		return eid;
		}

	*pos++ = WLAN_EID_HT_CAP;
	*pos++ = sizeof(*cap);
	cap = (struct ieee80211_ht_capabilities *) pos;

	os_memset(cap, 0, sizeof(*cap));
	cap->ht_capabilities_info = host_to_le16(hapd->iconf->ht_capab);
	cap->a_mpdu_params = hapd->iface->current_mode->a_mpdu_params;//�ۺ�֡����
	os_memcpy(cap->supported_mcs_set, hapd->iface->current_mode->mcs_set,
		  16);//������������Ϣ16�ֽ�

	/* TODO: ht_extended_capabilities (now fully disabled) */
	/* TODO: tx_bf_capability_info (now fully disabled) */
	/* TODO: asel_capabilities (now fully disabled) */

 	pos += sizeof(*cap);

	if (hapd->iconf->obss_interval) {
		struct ieee80211_obss_scan_parameters *scan_params;

		*pos++ = WLAN_EID_OVERLAPPING_BSS_SCAN_PARAMS;
		*pos++ = sizeof(*scan_params);

		scan_params = (struct ieee80211_obss_scan_parameters *) pos;
		os_memset(scan_params, 0, sizeof(*scan_params));
		scan_params->width_trigger_scan_interval =
			host_to_le16(hapd->iconf->obss_interval);

		/* Fill in default values for remaining parameters
		 * (IEEE Std 802.11-2012, 8.4.2.61 and MIB defval) */
		scan_params->scan_passive_dwell =
			host_to_le16(20);
		scan_params->scan_active_dwell =
			host_to_le16(10);
		scan_params->scan_passive_total_per_channel =
			host_to_le16(200);
		scan_params->scan_active_total_per_channel =
			host_to_le16(20);
		scan_params->channel_transition_delay_factor =
			host_to_le16(5);
		scan_params->scan_activity_threshold =
			host_to_le16(25);

		pos += sizeof(*scan_params);
	}
	return pos;
}
u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid)
{
	struct ieee80211_ht_operation *oper;
	u8 *pos = eid;

	if (!hapd->iconf->ieee80211n || hapd->conf->disable_11n)
		return eid;

	*pos++ = WLAN_EID_HT_OPERATION;
	*pos++ = sizeof(*oper);

	oper = (struct ieee80211_ht_operation *) pos;
	os_memset(oper, 0, sizeof(*oper));
	//�������ļ��л�ȡ����
	oper->primary_chan = hapd->iconf->channel;
	oper->operation_mode = host_to_le16(hapd->iface->ht_op_mode);
	if (hapd->iconf->secondary_channel == 1)
		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_ABOVE |
			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;
	if (hapd->iconf->secondary_channel == -1)
		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_BELOW |
			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;

	pos += sizeof(*oper);

	return pos;
}


/***/
static void hostapd_ext_capab_byte(struct hostapd_data *hapd, u8 *pos, int idx)
{
	*pos = 0x00;

	switch (idx) {
	case 0: /* Bits 0-7 */
		if (hapd->iconf->obss_interval)
			*pos |= 0x01; /* Bit 0 - Coexistence management */
		break;
	case 1: /* Bits 8-15 */
		break;
	case 2: /* Bits 16-23 */
		if (hapd->conf->wnm_sleep_mode)
			*pos |= 0x02; /* Bit 17 - WNM-Sleep Mode */
		if (hapd->conf->bss_transition)
			*pos |= 0x08; /* Bit 19 - BSS Transition */
		break;
	case 3: /* Bits 24-31 */
//#ifdef CONFIG_WNM
		*pos |= 0x02; /* Bit 25 - SSID List */
//#endif /* CONFIG_WNM */
		if (hapd->conf->time_advertisement == 2)
			*pos |= 0x08; /* Bit 27 - UTC TSF Offset */
		if (hapd->conf->interworking)
			*pos |= 0x80; /* Bit 31 - Interworking */
		break;
	case 4: /* Bits 32-39 */
		if (hapd->conf->qos_map_set_len)
			*pos |= 0x01; /* Bit 32 - QoS Map */
		if (hapd->conf->tdls & TDLS_PROHIBIT)
			*pos |= 0x40; /* Bit 38 - TDLS Prohibited */
		if (hapd->conf->tdls & TDLS_PROHIBIT_CHAN_SWITCH) {
			/* Bit 39 - TDLS Channel Switching Prohibited */
			*pos |= 0x80;
		}
		break;
	case 5: /* Bits 40-47 */
#ifdef CONFIG_HS20
		if (hapd->conf->hs20)
			*pos |= 0x40; /* Bit 46 - WNM-Notification */
#endif /* CONFIG_HS20 */
		break;
	case 6: /* Bits 48-55 */
		if (hapd->conf->ssid.utf8_ssid)
			*pos |= 0x01; /* Bit 48 - UTF-8 SSID */
		break;
	}
}


u8 * hostapd_eid_ext_capab(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	u8 len = 0, i;

	if (hapd->conf->tdls & (TDLS_PROHIBIT | TDLS_PROHIBIT_CHAN_SWITCH))
		len = 5;
	if (len < 4 && hapd->conf->interworking)
		len = 4;
	if (len < 3 && hapd->conf->wnm_sleep_mode)
		len = 3;
	if (len < 1 && hapd->iconf->obss_interval)
		len = 1;
	if (len < 7 && hapd->conf->ssid.utf8_ssid)
		len = 7;
//#ifdef CONFIG_WNM
	if (len < 4)
		len = 4;
//#endif /* CONFIG_WNM */
#ifdef CONFIG_HS20
	if (hapd->conf->hs20 && len < 6)
		len = 6;
#endif /* CONFIG_HS20 */
	if (len < hapd->iface->extended_capa_len)
		len = hapd->iface->extended_capa_len;
	if (len == 0)
		return eid;

	*pos++ = WLAN_EID_EXT_CAPAB;
	*pos++ = len;
	for (i = 0; i < len; i++, pos++) {
		hostapd_ext_capab_byte(hapd, pos, i);

		if (i < hapd->iface->extended_capa_len) {
			*pos &= ~hapd->iface->extended_capa_mask[i];
			*pos |= hapd->iface->extended_capa[i];
		}
	}

	while (len > 0 && eid[1 + len] == 0) {
		len--;
		eid[1] = len;
	}
	if (len == 0)
		return eid;

	return eid + 2 + len;
}

/**WMM /
/*
 * Add WMM Parameter Element to Beacon, Probe Response, and (Re)Association
 * Response frames.
 */
 
 

/* TODO: maintain separate sequence and fragment numbers for each AC
 * TODO: IGMP snooping to track which multicasts to forward - and use QOS-DATA
 * if only WMM stations are receiving a certain group */


static u8 wmm_aci_aifsn(int aifsn, int acm, int aci)
{
	u8 ret;
	ret = (aifsn << WMM_AC_AIFNS_SHIFT) & WMM_AC_AIFSN_MASK;
	if (acm)
		ret |= WMM_AC_ACM;
	ret |= (aci << WMM_AC_ACI_SHIFT) & WMM_AC_ACI_MASK;
	return ret;
}
static u8 wmm_ecw(int ecwmin, int ecwmax)
{
	return ((ecwmin << WMM_AC_ECWMIN_SHIFT) & WMM_AC_ECWMIN_MASK) |
		((ecwmax << WMM_AC_ECWMAX_SHIFT) & WMM_AC_ECWMAX_MASK);
}

u8 * hostapd_eid_wmm(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	struct wmm_parameter_element *wmm =
		(struct wmm_parameter_element *) (pos + 2);
	int e;

	if (!hapd->conf->wmm_enabled)
		return eid;
	eid[0] = WLAN_EID_VENDOR_SPECIFIC;
	wmm->oui[0] = 0x00;
	wmm->oui[1] = 0x50;
	wmm->oui[2] = 0xf2;
	wmm->oui_type = WMM_OUI_TYPE;
	wmm->oui_subtype = WMM_OUI_SUBTYPE_PARAMETER_ELEMENT;
	wmm->version = WMM_VERSION;
	wmm->qos_info = hapd->parameter_set_count & 0xf;

	if (hapd->conf->wmm_uapsd &&
	    (hapd->iface->drv_flags & WPA_DRIVER_FLAGS_AP_UAPSD))
		wmm->qos_info |= 0x80;

	wmm->reserved = 0;

	/* fill in a parameter set record for each AC */
	for (e = 0; e < 4; e++) {
		struct wmm_ac_parameter *ac = &wmm->ac[e];
		struct hostapd_wmm_ac_params *acp =
			&hapd->iconf->wmm_ac_params[e];

		ac->aci_aifsn = wmm_aci_aifsn(acp->aifs,
					      acp->admission_control_mandatory,
					      e);
		ac->cw = wmm_ecw(acp->cwmin, acp->cwmax);
		ac->txop_limit = host_to_le16(acp->txop_limit);
	}

	pos = (u8 *) (wmm + 1);
	eid[1] = pos - eid - 2; /* element length */

	return pos;
}

static u8 * wimaster_eid_channel_switch(struct hostapd_data *hapd, u8 *eid, 
        struct channel_switch_params cs_params)
{
	u8 *pos = eid;

	*pos++ = WLAN_EID_CHANNEL_SWITCH;
	*pos++ = 3;
	*pos++ = cs_params.cs_mode;
	*pos++ = cs_params.channel;
	*pos++ = cs_params.cs_count;
	
	return pos;
}


/**/

//���ղ�����proberesponse
/*
static u8 * hostapd_probe_resp_offloads(struct hostapd_data *hapd,
					size_t *resp_len)
{
	// check probe response offloading caps and print warnings 
	if (!(hapd->iface->drv_flags & WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD))
		return NULL;

	if (hapd->conf->interworking &&
	    !(hapd->iface->probe_resp_offloads &
	      WPA_DRIVER_PROBE_RESP_OFFLOAD_INTERWORKING))
		wpa_printf(MSG_WARNING, "Device is trying to offload "
			   "Interworking Probe Response while not supporting "
			   "this");

	// Generate a Probe Response template for the non-P2P case 
	return hostapd_gen_probe_resp(hapd, NULL, NULL, 0, resp_len);
}
*/

int ieee802_11_build_ap_beacon(struct hostapd_data *hapd, struct beacon_settings *bs, 
        struct wpa_driver_ap_params *params){
	struct ieee80211_mgmt *head = NULL;
	u8 *tail = NULL;
	size_t head_len = 0, tail_len = 0;
	u8 *resp = NULL;
	size_t resp_len = 0;
	u16 capab_info;
	u8 *pos, *tailpos;
	
#define BEACON_HEAD_BUF_SIZE 256
#define BEACON_TAIL_BUF_SIZE 512
	head = (struct ieee80211_mgmt*)os_zalloc(BEACON_HEAD_BUF_SIZE);
	tail_len = BEACON_TAIL_BUF_SIZE;

	if (hapd->conf->vendor_elements)
		tail_len += wpabuf_len(hapd->conf->vendor_elements);
	
	tailpos = tail = (u8 *)os_malloc(tail_len);
	if (head == NULL || tail == NULL) {
		wpa_printf(MSG_ERROR, "Failed to set beacon data");
		os_free(head);
		os_free(tail);
		return -1;
	}
	
	//is beacon or proberesp,then set header
	if(bs->is_probe){
		head->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
						   WLAN_FC_STYPE_PROBE_RESP);		
	}else
		head->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_BEACON);
	head->duration = host_to_le16(0);
	
    //sdwn: specify the address
	os_memcpy(head->da, bs->da, ETH_ALEN);
	os_memcpy(head->sa, bs->bssid, ETH_ALEN);
	os_memcpy(head->bssid, bs->bssid, ETH_ALEN);

    //wpa_printf(MSG_DEBUG, "da:"MACSTR", sa:"MACSTR", bssid:"MACSTR"\n",
    //          MAC2STR(head->da), MAC2STR(head->sa), MAC2STR(head->bssid));

	head->u.beacon.beacon_int =host_to_le16(1000);
		//host_to_le16(hapd->iconf->beacon_int);
    
	/* hardware or low-level driver will setup seq_ctrl and timestamp */
	capab_info = hostapd_own_capab_info(hapd, NULL, 0);//��ȡhostapd�б������߲���
	head->u.beacon.capab_info = cpu_to_le16(capab_info);//host_to_le16(capab_info);
	pos = &head->u.beacon.variable[0];
	/* SSID */
	*pos++ = WLAN_EID_SSID;
	if (hapd->conf->ignore_broadcast_ssid == 2) {
		/* clear the data, but keep the correct length of the SSID */
		*pos++ = hapd->conf->ssid.ssid_len;
		os_memset(pos, 0, hapd->conf->ssid.ssid_len);
		pos += hapd->conf->ssid.ssid_len;
	} else if (hapd->conf->ignore_broadcast_ssid) {
		*pos++ = 0; /* empty SSID */
	} else {
	
	/***hostapd Ĭ�ϵ����������
		*pos++ = hapd->conf->ssid.ssid_len;
		os_memcpy(pos, hapd->conf->ssid.ssid,
			  hapd->conf->ssid.ssid_len);
		pos += hapd->conf->ssid.ssid_len;
		*/
		//for SDWN
		*pos++ = bs->ssid_len;
		os_memcpy(pos, bs->ssid, bs->ssid_len);
		pos += bs->ssid_len;	
	}

	/* Supported rates */
	pos = hostapd_eid_supp_rates(hapd, pos);

	/* DS Params */
	pos = hostapd_eid_ds_params(hapd, pos);

	head_len = pos - (u8 *) head;

	tailpos = hostapd_eid_country(hapd, tailpos,
				      tail + BEACON_TAIL_BUF_SIZE - tailpos);

	/* Power Constraint element */
	tailpos = hostapd_eid_pwr_constraint(hapd, tailpos);

	/* ERP Information element */
	tailpos = hostapd_eid_erp_info(hapd, tailpos);

	/* Extended supported rates */
	tailpos = hostapd_eid_ext_supp_rates(hapd, tailpos);

	/* RSN, MDIE, WPA */
	//tailpos = hostapd_eid_wpa(hapd, tailpos, tail + BEACON_TAIL_BUF_SIZE -
	//			  tailpos);

	//tailpos = hostapd_eid_bss_load(hapd, tailpos,
		//		       tail + BEACON_TAIL_BUF_SIZE - tailpos);

//#ifdef CONFIG_IEEE80211N
	tailpos = hostapd_eid_ht_capabilities(hapd, tailpos);
	tailpos = hostapd_eid_ht_operation(hapd, tailpos);
//#endif /* CONFIG_IEEE80211N */

	tailpos = hostapd_eid_ext_capab(hapd, tailpos);//notice:not work --nm

	/*
	 * TODO: Time Advertisement element should only be included in some
	 * DTIM Beacon frames.
	 */
	 /*
	tailpos = hostapd_eid_time_adv(hapd, tailpos);

	tailpos = hostapd_eid_interworking(hapd, tailpos);
	tailpos = hostapd_eid_adv_proto(hapd, tailpos);
	tailpos = hostapd_eid_roaming_consortium(hapd, tailpos);
	*/
    if (bs->is_csa) {
	    tailpos = wimaster_eid_channel_switch(hapd, tailpos, bs->cs_params);
    }
#ifdef CONFIG_IEEE80211AC
	//tailpos = hostapd_eid_vht_capabilities(hapd, tailpos);
	//tailpos = hostapd_eid_vht_operation(hapd, tailpos);
#endif /* CONFIG_IEEE80211AC */

	/* Wi-Fi Alliance WMM */
	tailpos = hostapd_eid_wmm(hapd, tailpos);


#ifdef CONFIG_HS20
	//tailpos = hostapd_eid_hs20_indication(hapd, tailpos);
	//tailpos = hostapd_eid_osen(hapd, tailpos);
#endif /* CONFIG_HS20 */
	//wpa_printf(MSG_ERROR, "ieee802_11_build_ap_params 0n-1\n");
	if (hapd->conf->vendor_elements) {
		os_memcpy(tailpos, wpabuf_head(hapd->conf->vendor_elements),
			  wpabuf_len(hapd->conf->vendor_elements));
		tailpos += wpabuf_len(hapd->conf->vendor_elements);
	}

	tail_len = tailpos > tail ? tailpos - tail : 0;

	//resp = hostapd_probe_resp_offloads(hapd, &resp_len);
//#endif /* NEED_AP_MLME */

	os_memset(params, 0, sizeof(*params));
	params->head = (u8 *) head;
	params->head_len = head_len;
	params->tail = tail;
	params->tail_len = tail_len;
	params->proberesp = resp;
	params->proberesp_len = resp_len;
	return 0;
}





/*******************************************ProbeResponse creat****************************************************/
u8 * hostapd_eid_bss_max_idle_period(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;

//#ifdef CONFIG_WNM
	if (hapd->conf->ap_max_inactivity > 0) {
		unsigned int val;
		*pos++ = WLAN_EID_BSS_MAX_IDLE_PERIOD;
		*pos++ = 3;
		val = hapd->conf->ap_max_inactivity;
		if (val > 68000)
			val = 68000;
		val *= 1000;
		val /= 1024;
		if (val == 0)
			val = 1;
		if (val > 65535)
			val = 65535;
		WPA_PUT_LE16(pos, val);
		pos += 2;
		*pos++ = 0x00; /* TODO: Protected Keep-Alive Required */
	}
//#endif /* CONFIG_WNM */

	return pos;
}
u8 * hostapd_eid_qos_map_set(struct hostapd_data *hapd, u8 *eid)
{
	u8 *pos = eid;
	u8 len = hapd->conf->qos_map_set_len;

	if (!len)
		return eid;

	*pos++ = WLAN_EID_QOS_MAP_SET;
	*pos++ = len;
	os_memcpy(pos, hapd->conf->qos_map_set, len);
	pos += len;

	return pos;
}

/***
 * proberesponse construct
 */
u8 * generate_assoc_resp(struct hostapd_data *hapd, struct sta_info *sta,u8 *vbssid,
			    u16 status_code, int reassoc,int *frame_len)
{
	int send_len;
	//u8 buf[sizeof(struct ieee80211_mgmt) + 1024];
	u8 *buf;
	struct ieee80211_mgmt *reply;
	u8 *p;

	buf = (u8 *) os_zalloc(sizeof(struct ieee80211_mgmt) + 1024);// may need debug -- nm
	reply = (struct ieee80211_mgmt *) buf;
	reply->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT,
			     (reassoc ? WLAN_FC_STYPE_REASSOC_RESP :
			      WLAN_FC_STYPE_ASSOC_RESP));

	os_memcpy(reply->da, sta->addr, ETH_ALEN);
	//os_memcpy(reply->sa, hapd->own_addr, ETH_ALEN);
	//os_memcpy(reply->bssid, hapd->own_addr, ETH_ALEN);
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

//#ifdef CONFIG_IEEE80211N
	p = hostapd_eid_ht_capabilities(hapd, p);
	//wpa_printf(MSG_INFO, "send assoc resp 999\n");	
	p = hostapd_eid_ht_operation(hapd, p);
//#endif /* CONFIG_IEEE80211N */
#ifdef CONFIG_IEEE80211AC
	//p = hostapd_eid_vht_capabilities(hapd, p);
	//p = hostapd_eid_vht_operation(hapd, p);
#endif /* CONFIG_IEEE80211AC */

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
	*frame_len = send_len;
	//if (hostapd_drv_send_mlme(hapd, reply, send_len, 0) < 0)
	//wpa_printf(MSG_INFO, "success to generate assoc resp\n");
	return buf;
}


