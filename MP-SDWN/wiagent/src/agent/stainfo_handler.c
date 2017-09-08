/*
 * Handling the sta_info with controller oriented. 
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <json.h>

#include "stainfo_handler.h"
#include "push.h"
#include "../ap/sta_info.h"

/**
 * Converts the sta_info structure data to json format, 
 * using Json-C library.
 */
static const char *stainfo_to_json(const struct sta_info *sta, 
        const struct ieee80211_ht_capabilities *ht_cap)
{
    const char *stainfo_json;
    int rate_len;
    int i;
	struct json_object *json = json_object_new_object();//main object
	struct json_object *json_supported_rates = json_object_new_array();//supported_rates
	struct json_object *json_ht_cap = json_object_new_object();//ht_cap
	struct json_object *supported_mcs_set = json_object_new_array();//ht_cap.supported_mcs_set

	//construct json
    json_object_object_add(json, "aid", json_object_new_int(sta->aid));
    json_object_object_add(json, "cap", json_object_new_int(sta->capability));
    json_object_object_add(json, "interval", json_object_new_int(sta->listen_interval));
    json_object_object_add(json, "flags", json_object_new_int(sta->flags));
    json_object_object_add(json, "qosinfo", json_object_new_int(sta->qosinfo));
    json_object_object_add(json, "vht_opmode", json_object_new_int(sta->vht_opmode));
    json_object_object_add(json, "supported_rates_len", json_object_new_int(sta->supported_rates_len));

	//construst json_supported_rates
	rate_len = sta->supported_rates_len;
	for(i = 0; i < rate_len; i++){
		json_object_array_add(json_supported_rates,json_object_new_int(sta->supported_rates[i]));
	}
	//add  json_supported_rates to json
	json_object_object_add(json, "supported_rates", json_supported_rates);

	//construst json_ht_cap
	json_object_object_add(json_ht_cap, "ht_capabilities_info", json_object_new_int(ht_cap->ht_capabilities_info));
	json_object_object_add(json_ht_cap, "a_mpdu_params", json_object_new_int(ht_cap->a_mpdu_params));
	json_object_object_add(json_ht_cap, "ht_extended_capabilities", json_object_new_int(ht_cap->ht_extended_capabilities));
	json_object_object_add(json_ht_cap, "tx_bf_capability_info", json_object_new_int(ht_cap->tx_bf_capability_info));
	json_object_object_add(json_ht_cap,"asel_capabilities",json_object_new_int(ht_cap->asel_capabilities));

	//construst supported_mcs_set
	for(i = 0; i < 15; i++){
		json_object_array_add(supported_mcs_set,json_object_new_int(ht_cap->supported_mcs_set[i]));
	}
	//add  supported_mcs_set to ht_cap
	json_object_object_add(json_ht_cap,"supported_mcs_set",supported_mcs_set);

	//add  json_ht_cap to json
	json_object_object_add(json, "ht_cap", json_ht_cap);

    stainfo_json = json_object_to_json_string(json);

    json_object_put(json);

    return stainfo_json;
}

/*
 * parse a json string of sta_info structure, and then fill in sta_info. 
 * if an error occurs, return NULL.
 */
static int json_to_stainfo(const char *json, struct sta_info *sta)
{
	//convert josn style string to json object
	struct json_object *obj;
	struct json_object *new_obj;
	struct ieee80211_ht_capabilities *ht_cap;
	int length = 0;//获取矩阵长度
	int value = 0;
    int i;
	
	obj=json_tokener_parse(json);//构造json对象
	//判断是否json格式,貌似这句判断在这里没有效果
	if(is_error(obj)){
		//printf("not json style string\n");
		return -1;
	}
	
	new_obj = json_object_object_get(obj,"aid");
	sta->aid = json_object_get_int(new_obj);
	//printf("add_sta_info 001\n");
	new_obj = json_object_object_get(obj,"cap");
	sta->capability = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"interval");
	sta->listen_interval = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"flags");
	sta->flags = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"qosinfo");
	sta->qosinfo = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"vht_opmode");
	sta->vht_opmode = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"supported_rates_len");
	sta->supported_rates_len = json_object_get_int(new_obj);
	
	//printf("real sart 111---len=%d\n",sta->supported_rates_len);
	//sta.support_rates
	new_obj = json_object_object_get(obj,"supported_rates");
	if(!new_obj){
		printf("json style string is null\n");
		return -1;
	}	
	length = json_object_array_length(new_obj);//获取矩阵长度
	
    for(i = 0; i < length; i++) {
        json_object *val=json_object_array_get_idx(new_obj,i);//获取矩阵第i个元素
        value = json_object_get_int(val);
		sta->supported_rates[i] = value;//需要值位0
    }	

	ht_cap = (struct ieee80211_ht_capabilities *)os_zalloc(sizeof(struct ieee80211_ht_capabilities));
	if(!ht_cap){
		printf("ht_cap malloc failed in add_sta_info\n");
		return -1;
	}
	//printf("add_sta_info 003\n");
	//sta.ht_cap
	obj = json_object_object_get(obj,"ht_cap");
	//printf("add_sta_info 004\n");
	if(!obj){
		printf("json style string is null\n");
		os_free(ht_cap);
		return -1;
	}
		
	new_obj = json_object_object_get(obj,"ht_capabilities_info");
	ht_cap->ht_capabilities_info = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"a_mpdu_params");
	ht_cap->a_mpdu_params = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"ht_extended_capabilities");
	ht_cap->ht_extended_capabilities = json_object_get_int(new_obj);

	new_obj = json_object_object_get(obj,"tx_bf_capability_info");
	ht_cap->tx_bf_capability_info = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"asel_capabilities");
	ht_cap->asel_capabilities = json_object_get_int(new_obj);
	
	new_obj = json_object_object_get(obj,"supported_mcs_set");
	//avoid segment error --nm
	if(!new_obj){
		printf("json style string is null\n");
		os_free(ht_cap);
		return -1;
	}
	length=json_object_array_length(new_obj);//获取矩阵长度

    for(i = 0; i < length; i++) {
        json_object *val=json_object_array_get_idx(new_obj,i);//获取矩阵第i个元素
        value = json_object_get_int(val);
		ht_cap->supported_mcs_set[i] = value;//需要值位0
    }
	
	//printf("add_sta_info 004\n");
	if (sta->ht_capabilities == NULL) {
		sta->ht_capabilities =
			(struct ieee80211_ht_capabilities*)os_zalloc(sizeof(struct ieee80211_ht_capabilities));
		if (sta->ht_capabilities == NULL){
			os_free(ht_cap);
			return -1;
		}
	}

	//sta->ht_capabilities = &ht_cap;//应该使用copy,或者ht_cap分配内存空间再赋值	
	os_memcpy(sta->ht_capabilities, ht_cap,sizeof(struct ieee80211_ht_capabilities));
	
	os_free(ht_cap);//回收内存

    return 0;
}

int wiagent_push_stainfo(struct hostapd_data *hapd, const u8 *addr)
{
    char *stainfo; 
    struct sta_info *sta;
    struct ieee80211_ht_capabilities ht_cap;

    sta = ap_get_sta(hapd, addr);
    if(!sta) {
        wpa_printf(MSG_DEBUG, "The "MACSTR" sta_info do not exist.", MAC2STR(addr));
        return -1;
    }

    if(sta->flags & WLAN_STA_HT) {
        wpa_printf(MSG_DEBUG, "The station "MACSTR" support HT",
                MAC2STR(addr));
        hostapd_get_ht_capab(hapd, sta->ht_capabilities, &ht_cap);
    }

    stainfo = stainfo_to_json(sta, &ht_cap);
    if(stainfo) {
        push_stainfo(addr, stainfo);
        return 0;
    }
    else {
        wpa_printf(MSG_WARN, "Fail to convert "MACSTR" struct sta_info to json.", 
                        MAC2STR(addr));
        return -1;
    }
}

/**
 * function: add station when receive add_station commond(write_handler) from Controller
 * return -1:failed 0:succeed
 */
int wiagent_add_stainfo(struct hostapd_data *hapd, 
        const u8 *addr, const char *stainfo)
{	
	//1.认为其已经是认证过的sta    分配sta_ifo内存  并并标记为auth
	handle_auth(hapd, addr, WLAN_AUTH_OPEN);

	//2.认为已经是关联上的sta 此时需要填充sta_info 
	struct sta_info *sta = ap_get_sta(hapd, addr);
	if (!sta){
		wpa_printf(MSG_WARN, "sta_info do not exist\n");
		return -1;
	}
    if(json_to_stainfo(stainfo, sta) < 0) {
        wpa_printf(MSG_WARN, "Fail to convert "MACSTR" sta_info json string format to struct sta_info.",
                MAC2STR(addr));
        ap_sta_hash_del(hapd, sta);
        return -1;
    }

	//last. sta_info填充完毕之后,这时候需要将其添加到内核中去
	hostapd_handle_assoc_cb(hapd, addr);	

    wpa_printf(MSG_DEBUG, "Add "MACSTR" sta_info", MAC2STR(addr));

	return 0;      
}

int wiagent_remove_stainfo(struct hostapd_data *hapd, const u8 *addr) 
{
    //1.用户态删除
    struct sta_info * sta = ap_get_sta(hapd, addr);
    if(!sta)
        return 0;
    ap_sta_hash_del(hapd,sta);
    //2.内核态删除
    if (hostapd_drv_sta_remove(hapd, addr) < 0) {
        wpa_printf(MSG_WARN, "Fail to remove "MACSTR" sta_info from kernel.",
                MAC2STR(addr));
        return -1;
    }
    
    wpa_printf(MSG_DEBUG, "Have removed sta_info "MACSTR" from kernel.",
                MAC2STR(addr));

    return 0;
}

