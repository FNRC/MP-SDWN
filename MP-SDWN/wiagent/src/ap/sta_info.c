/*
 * hostapd / Station table
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com> Jouni Malinen <j@w1.fi>
 * Copyright (c) 2002-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "../utils/common.h"
#include "hostapd.h"
#include "sta_info.h"

void ap_sta_hash_add(struct hostapd_data *hapd, struct sta_info *sta)
{
	sta->hnext = hapd->sta_hash[STA_HASH(sta->addr)];
	hapd->sta_hash[STA_HASH(sta->addr)] = sta;
}

void ap_sta_hash_del(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct sta_info *s;

	s = hapd->sta_hash[STA_HASH(sta->addr)];
	if (s == NULL) return;
	if (os_memcmp(s->addr, sta->addr, 6) == 0) {
		hapd->sta_hash[STA_HASH(sta->addr)] = s->hnext;
		return;
	}

	while (s->hnext != NULL &&
	       os_memcmp(s->hnext->addr, sta->addr, ETH_ALEN) != 0)
		s = s->hnext;
	if (s->hnext != NULL)
		s->hnext = s->hnext->hnext;
	else
		wpa_printf(MSG_DEBUG, "AP: could not remove STA " MACSTR
			   " from hash table", MAC2STR(sta->addr));
}

struct sta_info * ap_get_sta(struct hostapd_data *hapd, const u8 *sta)
{
	struct sta_info *s;

	s = hapd->sta_hash[STA_HASH(sta)];
	while (s != NULL && os_memcmp(s->addr, sta, 6) != 0)
		s = s->hnext;
	return s;
}

//用户态增加sta_info 供后面内核态使用111111111177
struct sta_info * ap_sta_add(struct hostapd_data *hapd, const u8 *addr)
{
	struct sta_info *sta;

	sta = ap_get_sta(hapd, addr);
	if (sta)
		return sta;

	sta = (struct sta_info*)os_zalloc(sizeof(struct sta_info));
	if (sta == NULL) {

		return NULL;
	}
	//sta->acct_interim_interval = hapd->conf->acct_interim_interval;
	//accounting_sta_get_id(hapd, sta);
	/* initialize STA info data */
	os_memcpy(sta->addr, addr, ETH_ALEN);
	sta->next = hapd->sta_list;
	hapd->sta_list = sta;
	hapd->num_sta++;
	ap_sta_hash_add(hapd, sta);
	//sta->ssid = &hapd->conf->ssid;
	//ap_sta_remove_in_other_bss(hapd, sta);
    //
    wpa_printf(MSG_DEBUG, "AP add one sta("MACSTR")", MAC2STR(addr));

	return sta;
}
