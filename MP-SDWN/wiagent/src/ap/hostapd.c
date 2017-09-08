/*
* hostapd / Initialization and configuration
* Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
* Copyright (c) 2017, liyaming <liyaming@gmail.com>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/
#include "../utils/common.h"
#include "hostapd.h"
#include "hw_features.h"
#include "beacon.h"

u32 hostapd_sta_flags_to_drv(u32 flags)
{
	int res = 0;
	if (flags & WLAN_STA_AUTHORIZED)
		res |= WPA_STA_AUTHORIZED;
	if (flags & WLAN_STA_WMM)
		res |= WPA_STA_WMM;
	if (flags & WLAN_STA_SHORT_PREAMBLE)
		res |= WPA_STA_SHORT_PREAMBLE;
	if (flags & WLAN_STA_MFP)
		res |= WPA_STA_MFP;
	return res;
}

int hostapd_get_mgmt_socket_fd(struct hostapd_data *hapd)
{
    if (hapd->driver == NULL || hapd->driver->get_mgmt_socket_fd == NULL)
		return -1;
	return hapd->driver->get_mgmt_socket_fd(hapd->drv_priv);
   
}

int hostapd_recv_mgmt_frame(struct hostapd_data *hapd)
{
    if (hapd->driver == NULL || hapd->driver->recv_mgmt_frame == NULL)
		return -1;
	return hapd->driver->recv_mgmt_frame(hapd->drv_priv);
   
}

void  hostapd_get_ht_capab(struct hostapd_data *hapd,
			  struct ieee80211_ht_capabilities *ht_cap,
			  struct ieee80211_ht_capabilities *neg_ht_cap)
{
	u16 cap;

	if (ht_cap == NULL)
		return;
	os_memcpy(neg_ht_cap, ht_cap, sizeof(*neg_ht_cap));
	//cap = le16_to_cpu(neg_ht_cap->ht_capabilities_info);
	cap = le16_to_cpu(neg_ht_cap->ht_capabilities_info);

	/*
	 * Mask out HT features we don't support, but don't overwrite
	 * non-symmetric features like STBC and SMPS. Just because
	 * we're not in dynamic SMPS mode the STA might still be.
	 */
	cap &= (hapd->iconf->ht_capab | HT_CAP_INFO_RX_STBC_MASK |
		HT_CAP_INFO_TX_STBC | HT_CAP_INFO_SMPS_MASK);

	/*
	 * STBC needs to be handled specially
	 * if we don't support RX STBC, mask out TX STBC in the STA's HT caps
	 * if we don't support TX STBC, mask out RX STBC in the STA's HT caps
	 */
	if (!(hapd->iconf->ht_capab & HT_CAP_INFO_RX_STBC_MASK))
		cap &= ~HT_CAP_INFO_TX_STBC;
	if (!(hapd->iconf->ht_capab & HT_CAP_INFO_TX_STBC))
		cap &= ~HT_CAP_INFO_RX_STBC_MASK;

	//neg_ht_cap->ht_capabilities_info = host_to_le16(cap);
	neg_ht_cap->ht_capabilities_info = cpu_to_le16(cap);
}

void  hostapd_get_vht_capab(struct hostapd_data *hapd,
			   struct ieee80211_vht_capabilities *vht_cap,
			   struct ieee80211_vht_capabilities *neg_vht_cap)
{
	u32 cap, own_cap, sym_caps;

	if (vht_cap == NULL)
		return;
	os_memcpy(neg_vht_cap, vht_cap, sizeof(*neg_vht_cap));

	cap = le32_to_cpu(neg_vht_cap->vht_capabilities_info);
	own_cap = hapd->iconf->vht_capab;

	/* mask out symmetric VHT capabilities we don't support */
	sym_caps = VHT_CAP_SHORT_GI_80 | VHT_CAP_SHORT_GI_160;
	cap &= ~sym_caps | (own_cap & sym_caps);

	/* mask out beamformer/beamformee caps if not supported */
	if (!(own_cap & VHT_CAP_SU_BEAMFORMER_CAPABLE))
		cap &= ~(VHT_CAP_SU_BEAMFORMEE_CAPABLE |
			 VHT_CAP_BEAMFORMEE_STS_MAX);

	if (!(own_cap & VHT_CAP_SU_BEAMFORMEE_CAPABLE))
		cap &= ~(VHT_CAP_SU_BEAMFORMER_CAPABLE |
			 VHT_CAP_SOUNDING_DIMENSION_MAX);

	if (!(own_cap & VHT_CAP_MU_BEAMFORMER_CAPABLE))
		cap &= ~VHT_CAP_MU_BEAMFORMEE_CAPABLE;

	if (!(own_cap & VHT_CAP_MU_BEAMFORMEE_CAPABLE))
		cap &= ~VHT_CAP_MU_BEAMFORMER_CAPABLE;

	/* mask channel widths we don't support */
	switch (own_cap & VHT_CAP_SUPP_CHAN_WIDTH_MASK) {
	case VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ:
		break;
	case VHT_CAP_SUPP_CHAN_WIDTH_160MHZ:
		if (cap & VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ) {
			cap &= ~VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ;
			cap |= VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
		}
		break;
	default:
		cap &= ~VHT_CAP_SUPP_CHAN_WIDTH_MASK;
		break;
	}

	if (!(cap & VHT_CAP_SUPP_CHAN_WIDTH_MASK))
		cap &= ~VHT_CAP_SHORT_GI_160;

	/*
	 * if we don't support RX STBC, mask out TX STBC in the STA's HT caps
	 * if we don't support TX STBC, mask out RX STBC in the STA's HT caps
	 */
	if (!(own_cap & VHT_CAP_RXSTBC_MASK))
		cap &= ~VHT_CAP_TXSTBC;
	if (!(own_cap & VHT_CAP_TXSTBC))
		cap &= ~VHT_CAP_RXSTBC_MASK;

	neg_vht_cap->vht_capabilities_info = cpu_to_le32(cap);
}

int hostapd_sta_add(struct hostapd_data *hapd,
		const u8 *addr, u16 aid, u16 capability,
		const u8 *supp_rates, size_t supp_rates_len,
		u16 listen_interval,
		const struct ieee80211_ht_capabilities *ht_capab,
		const struct ieee80211_vht_capabilities *vht_capab,
		u32 flags, u8 qosinfo, u8 vht_opmode,int session){
	struct hostapd_sta_add_params params;

	if (hapd->driver == NULL || hapd->driver->sta_add == NULL) {
		//nl80211 driver驱动不可用,可能出现空指针，未赋值
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		return 0;
	}
	///ff
	os_memset(&params, 0, sizeof(params));
	params.addr = addr;
	params.aid = aid;
	params.capability = capability;
	params.supp_rates = supp_rates;
	params.supp_rates_len = supp_rates_len;
	params.listen_interval = listen_interval;
	params.ht_capabilities = ht_capab;
	params.vht_capabilities = vht_capab;
	params.vht_opmode_enabled = !!(flags & WLAN_STA_VHT_OPMODE_ENABLED);
	params.vht_opmode = vht_opmode;
	params.flags = hostapd_sta_flags_to_drv(flags);
	params.qosinfo = qosinfo;
	/****重要: 如果内核重复的添加sta_info就会导致手机不能接入，注意这个细节*****/
	if(session == 0){
		params.set = 0;//增加station
	}else
		params.set = 1;//设置station
	//return 0;
	return hapd->driver->sta_add(hapd->drv_priv, &params);

}

//创建用户态的sta_info 结构体并填充认证的标志位
void handle_auth(struct hostapd_data *hapd,const u8 *addr,int auth_alg)
{

	struct sta_info *sta = NULL;

	sta = ap_sta_add(hapd, addr);
	if (!sta) {
		//resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		goto fail;
	}

	switch (auth_alg) {
		case WLAN_AUTH_OPEN:
			//hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			//		   HOSTAPD_LEVEL_DEBUG,
				//	   "authentication OK (open system)");
			sta->flags |= WLAN_STA_AUTH;//#define WLAN_STA_ASSOC BIT(1) ???????
			//wpa_auth_sm_event(sta->wpa_sm, WPA_AUTH);
			sta->auth_alg = WLAN_AUTH_OPEN;
			//mlme_authenticate_indication(hapd, sta);
			break;
		case WLAN_AUTH_SHARED_KEY:

			break;
		#ifdef CONFIG_IEEE80211R
		case WLAN_AUTH_FT:

			/* handle_auth_ft_finish() callback will complete auth. */
			return;
		#endif /* CONFIG_IEEE80211R */
		#ifdef CONFIG_SAE
		case WLAN_AUTH_SAE:

			return;
		#endif /* CONFIG_SAE */
	}

	wpa_printf(MSG_DEBUG, "The station "MACSTR" authentication successful.", MAC2STR(addr));
	return ;
fail:
    wpa_printf(MSG_DEBUG, "The station "MACSTR" authentication failed.", MAC2STR(addr));
}

int hostapd_drv_sta_remove(struct hostapd_data *hapd,
					 const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->sta_remove == NULL)
		return 0;
	return hapd->driver->sta_remove(hapd->drv_priv, addr);
}

int hostapd_set_sta_flags(struct hostapd_data *hapd, struct sta_info *sta)
{
	int set_flags, total_flags, flags_and, flags_or;
	total_flags = hostapd_sta_flags_to_drv(sta->flags);
	set_flags = WPA_STA_SHORT_PREAMBLE | WPA_STA_WMM | WPA_STA_MFP;
	if (((!hapd->conf->ieee802_1x && !hapd->conf->wpa) ||
		 sta->auth_alg == WLAN_AUTH_FT) &&
		sta->flags & WLAN_STA_AUTHORIZED)
		set_flags |= WPA_STA_AUTHORIZED;
	flags_or = total_flags & set_flags;
	flags_and = total_flags | ~set_flags;
	if (hapd->driver == NULL || hapd->driver->sta_set_flags == NULL)
		return 0;
	return hapd->driver->sta_set_flags(hapd->drv_priv, sta->addr, total_flags,
					   flags_or, flags_and);
}

int hostapd_send_csa_action_frame(struct hostapd_data *hapd, 
            const u8 *addr, const u8 *bssid,
            const u8 block_tx, const u8 new_channel, const u8 cs_count)
{
    int ret;
	struct sta_info *sta;
	u8 *buf;
    int len = 7;

	sta = ap_get_sta(hapd, addr);
	if (sta == NULL) {
		wpa_printf(MSG_DEBUG, "Station " MACSTR " not found "
			   "for channel switch message",
			   MAC2STR(addr));
		return -1;
	}

	buf = os_zalloc(len);
	if (buf == NULL)
		return -1;

    u8 *pos = buf;
	*pos++ = WLAN_ACTION_SPECTRUM_MGMT;
	*pos++ = WLAN_PROT_EXT_CSA;

	/* Channel Switch Announcement Element*/
	*pos++ = WLAN_EID_CHANNEL_SWITCH;
	*pos++ = 3;
	*pos++ = block_tx ? 1 : 0;
    *pos++ = new_channel;
    *pos++ = cs_count;

    if (hapd->driver == NULL || hapd->driver->send_action == NULL) {
		ret = -1;
    }
    else {
	    ret = hapd->driver->send_action(hapd->drv_priv, hapd->iface->freq, 0, addr,
					 bssid, bssid, buf, len, 0);
    }
	os_free(buf);

	return ret;

}

//return 0:WLAN_STATUS_SUCCESS 1:WLAN_STATUS_UNSPECIFIED_FAILURE
u16 check_assoc_ies(struct hostapd_data *hapd, struct sta_info *sta,
			   const u8 *ies, size_t ies_len, int reassoc)
{
	struct ieee802_11_elems elems;
	u16 resp;
	const u8 *wpa_ie;
	size_t wpa_ie_len;
	const u8 *p2p_dev_addr = NULL;

	//解析的核心代码
	if (ieee802_11_parse_elems(ies, ies_len, &elems, 0) == ParseFailed) {
	//if (1) {
		//hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		//	       HOSTAPD_LEVEL_INFO, "Station sent an invalid "
		//	       "association request");
		wpa_printf(MSG_ERROR,"ieee802_11_parse_elems failed.");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	/*
	if(elems.supp_rates == NULL)
		fprintf(stderr,"supp_rates == NUL\n");
		fprintf(stderr,"%d,%d,%d\n",elems.supp_rates_len,elems.ext_supp_rates_len,sizeof(sta->supported_rates));
	fprintf(stderr,"80211n=%d\n",hapd->conf->disable_11n);
	hapd->conf->disable_11n = 0;
	*/
	//复制速率集合到sta_info结构体中
	resp = copy_supp_rates(hapd, sta, &elems);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;


	//复制HT能力标志位到sta_info结构体中
	resp = copy_sta_ht_capab(hapd, sta, elems.ht_capabilities,
				 elems.ht_capabilities_len);
	if (resp != WLAN_STATUS_SUCCESS)
		return resp;

	//AP支持高速率但是sta不支持高速率
	if (hapd->iconf->ieee80211n && hapd->iconf->require_ht &&
	    !(sta->flags & WLAN_STA_HT)) {
		//hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		//	       HOSTAPD_LEVEL_INFO, "Station does not support "
		//	       "mandatory HT PHY - reject association");
		wpa_printf(MSG_DEBUG,"The station %s association do not support HT",sta->addr,sta->aid);
		return WLAN_STATUS_ASSOC_DENIED_NO_HT;
	}
	return WLAN_STATUS_SUCCESS;
}



//解析关联帧,并将参数填写到sta_info中----len是数据包的总长度
u8 *hostapd_handle_assoc(struct hostapd_data *hapd,
			 const u8 *packet, int len, u8 *vbssid,
			 int reassoc,int *frame_len){
	const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)packet;
	u16 capab_info, listen_interval;
	u16 resp = WLAN_STATUS_SUCCESS;
	const u8 *pos;
	int left, i;
	struct sta_info *sta;
	u8 *res;
	int res_len = 0;
	//wpa_printf(MSG_INFO, "hostapd_handle_assoc execute\n");
	//头部检验:帧的总长度不小于头部的长度
	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req)) {
		wpa_printf(MSG_INFO, "handle_assoc(reassoc=%d) - too short payload (len=%lu)",
			   reassoc, (unsigned long) len);
		return NULL;
	}
	//提取两个字段
	capab_info = le16_to_cpu(mgmt->u.assoc_req.capab_info);
	listen_interval = le16_to_cpu(mgmt->u.assoc_req.listen_interval);
	//wpa_printf(MSG_DEBUG, "association request: STA=" MACSTR
	//	   " capab_info=0x%02x listen_interval=%d	",
	//	   MAC2STR(mgmt->sa), capab_info, listen_interval);
	left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
	pos = mgmt->u.assoc_req.variable;//移动指针解析ex字段
	sta = ap_get_sta(hapd, mgmt->sa);
	//认证时候就因该分配了内存,如果为空代表没有经过认证
	if (sta == NULL /*|| (sta->flags & WLAN_STA_AUTH) == 0*/) {
		wpa_printf(MSG_DEBUG, "staion is null association has not authriened");
		//send_deauth(hapd, mgmt->sa,
		//	    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
		return NULL;
	}
	if (listen_interval > hapd->conf->max_listen_interval) {
		//hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
		//	       HOSTAPD_LEVEL_DEBUG,
			//       "Too large Listen Interval (%d)",
		//	       listen_interval);
		wpa_printf(MSG_DEBUG, "Association Too large Listen Interval (%d)",	listen_interval);
		//resp = WLAN_STATUS_ASSOC_DENIED_LISTEN_INT_TOO_LARGE;
		//goto fail;
	}

	/* followed by SSID and Supported rates; and HT capabilities if 802.11n
	 * is used */
	resp = check_assoc_ies(hapd, sta, pos, left, reassoc);//解析参数---核心函数 返回值0 才正确，如果不正确影响终端接入或者速率异常
	if (resp != WLAN_STATUS_SUCCESS)
		goto fail;

	//分配关联的aid
	if (hostapd_get_aid(hapd, sta) < 0) {
		//hostapd_logger(hapd, mgmt->sa, HOSTAPD_MODULE_IEEE80211,
			//       HOSTAPD_LEVEL_INFO, "No room for more AIDs");
		resp = WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		wpa_printf(MSG_ERROR, "hostapd_get_aid failed.");
		goto fail;
	}

	sta->capability = capab_info;
	sta->listen_interval = listen_interval;
	//这句可能出现segment error
	if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G){
		sta->flags |= WLAN_STA_NONERP;
	}

	for (i = 0; i < sta->supported_rates_len; i++) {
		if ((sta->supported_rates[i] & 0x7f) > 22) {
			//WLAN_STA_NONERP=0 0，WLAN_STA_NONERP=1 0
			sta->flags &= ~WLAN_STA_NONERP;
			break;
		}
	}
/*
	//重新设置beacon帧
	if (sta->flags & WLAN_STA_NONERP && !sta->nonerp_set) {
		sta->nonerp_set = 1;
		hapd->iface->num_sta_non_erp++;
		if (hapd->iface->num_sta_non_erp == 1)
			ieee802_11_set_beacons(hapd->iface);
	}
	//如果不使用短间隔，则重新设置beacon帧
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
	//是否使用短前导码
	if (sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE)
		sta->flags |= WLAN_STA_SHORT_PREAMBLE;
	else
		sta->flags &= ~WLAN_STA_SHORT_PREAMBLE;
/*
	//如果不支持短前导码，则重新设置beacon帧
	if (!(sta->capability & WLAN_CAPABILITY_SHORT_PREAMBLE) &&
	    !sta->no_short_preamble_set) {
		sta->no_short_preamble_set = 1;
		hapd->iface->num_sta_no_short_preamble++;
		if (hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G
		    && hapd->iface->num_sta_no_short_preamble == 1)
			ieee802_11_set_beacons(hapd->iface);
	}
	*/
#ifdef CONFIG_IEEE80211N
	//update_ht_state(hapd, sta);
#endif /* CONFIG_IEEE80211N */
	//wpa_printf(MSG_DEBUG,"station:"MACSTR" association OK (aid %d)\n",MAC2STR(sta->addr),sta->aid);

	/* Station will be marked associated, after it acknowledges AssocResp
	 */
	sta->flags |= WLAN_STA_ASSOC_REQ_OK;
	sta->flags |= WLAN_STA_AUTHORIZED;//kernel will use --nm

	/* Make sure that the previously registered inactivity timer will not
	 * remove the STA immediately. */
	sta->timeout_next = STA_NULLFUNC;


	//for sdwn --nm
	res = generate_assoc_resp(hapd, sta,vbssid,WLAN_STATUS_SUCCESS,0/*reassociation*/,&res_len);
	*frame_len = res_len;//frame length
	return res;

 fail:
	//发送关联的响应帧
	//send_assoc_resp(hapd, sta, resp, reassoc, pos, left);

	wpa_printf(MSG_ERROR,"handle_assoc failed.");
	return NULL;
}

int hostapd_read_all_sta_data(struct hostapd_data *hapd, 
            struct hostap_sta_list *sta_list)
{
    if (hapd->driver == NULL || hapd->driver->read_all_sta_data == NULL)
		return 0;
	
    return hapd->driver->read_all_sta_data(hapd->drv_priv, sta_list);
}



void hostapd_handle_assoc_cb(struct hostapd_data *hapd, const u8 *addr){
	struct sta_info *sta;
	struct ieee80211_ht_capabilities ht_cap;
	struct ieee80211_vht_capabilities vht_cap;
	int ht = 0;
	//wpa_printf(MSG_DEBUG,"hostapd_handle_assoc_cb start\n");
	//fprintf(stderr, "hostapd_handle_assoc_cb 111 --nm\n");
	sta = ap_get_sta(hapd, addr);
	if (!sta){
		wpa_printf(MSG_WARN, "The "MACSTR" sta_info does not exist.", MAC2STR(addr));
		return;
	}
	//通知内核态增加sta_infoll
	//_hapd->handle_assoc_cb(_hapd,sta);
	//先移除内核中可能已经添加的sta_info，
	//必须sta_info在用户态已经存在就删除如果不存在就直接返回
	//hostapd_drv_sta_remove(hapd, sta->addr);

	if(sta->acct_session_started == 0){
		//第一次连接认证
		//ap_sta_hash_del(hapd,sta);
		hostapd_drv_sta_remove(hapd, sta->addr);
	}

	//ht = sta->flags & WLAN_STA_HT;
	//fprintf(stderr,"sta support HT=%d\n",ht);

	//802.11n
	if (sta->flags & WLAN_STA_HT){
		//fprintf(stderr,"sta support HT\n");
		hostapd_get_ht_capab(hapd, sta->ht_capabilities, &ht_cap);
	}

	//80211ac
	if (sta->flags & WLAN_STA_VHT){
		//fprintf(stderr,"sta support VHT\n");
		hostapd_get_vht_capab(hapd, sta->vht_capabilities, &vht_cap);
	}


	/////// 防止多次的setstation

	if(sta->acct_session_started == 0)
	if (!hostapd_sta_add(hapd, sta->addr, sta->aid, sta->capability,
	//if (_hapd->handle_assoc_cb(_hapd, sta->addr, sta->aid, sta->capability,
				sta->supported_rates, sta->supported_rates_len,
				sta->listen_interval,
				sta->flags & WLAN_STA_HT ? &ht_cap : NULL,
				sta->flags & WLAN_STA_VHT ? &vht_cap : NULL,
				sta->flags, sta->qosinfo, sta->vht_opmode,sta->acct_session_started)) {
		//ap_sta_disconnect(_hapd, sta, sta->addr,
		//		  WLAN_REASON_DISASSOC_AP_BUSY);

		//return;
	}
	//if(sta->acct_session_started == 0)
	//send_sta_to_ctrol(sta,ht_cap);
	// 设置增加还是设置station
	//if(sta->acct_session_started == 0)
		sta->acct_session_started = 1;
	//设置标志
	hostapd_set_sta_flags(hapd, sta);
}


//初始化bss\drv\nl80211 的netlink////
int hostapd_driver_init(struct hostapd_iface *iface)
{
	struct wpa_init_params params;//不需要分配内存
	//u8 bssid[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	struct hostapd_data *hapd = iface->bss[0];
	struct hostapd_bss_config *conf = hapd->conf;
	u8 *b = conf->bssid;
	struct wpa_driver_capa capa;
	struct hostapd_data *bss ;

	//初始化驱动,建立netlink连接
	if (hapd->driver == NULL || hapd->driver->global_init == NULL) {
		//nl80211 driver驱动不可用,可能出现空指针，未赋值
		wpa_printf(MSG_ERROR, "hapd->driver || hapd->driver->global_init == NULL");
		return -1;
	}
	/* Initialize the driver interface */
	if (!(b[0] | b[1] | b[2] | b[3] | b[4] | b[5]))
		b = NULL;

	os_memset(&params, 0, sizeof(params));
	//设置struct hostapd_data *hapd 驱动ops
	hapd->driver = wpa_drivers[0];
	//global_init返回值类型为 nl80211_global_init === global
	params.global_priv = hapd->driver->global_init();

	//TODO:填充params的参数/////////
	params.bssid = b; //BSSID
	params.ifname = hapd->conf->iface; //网络接口名称（比如wlan0）
	params.ssid = hapd->conf->ssid.ssid; //SSID
	params.ssid_len = hapd->conf->ssid.ssid_len; //SSID 长度
	params.test_socket = hapd->conf->test_socket;
	params.use_pae_group_addr = hapd->conf->use_pae_group_addr;

	params.num_bridge = hapd->iface->num_bss;
	params.bridge = (char**)os_calloc(hapd->iface->num_bss, sizeof(char *));
	if (params.bridge == NULL){
		wpa_printf(MSG_ERROR, "params.bridge == NULL.");
		return -1;
	}

	bss = hapd->iface->bss[0];
	if (bss->conf->bridge[0])
		params.bridge[0] = bss->conf->bridge;
	params.own_addr = hapd->own_addr;
	if (hapd->driver == NULL || hapd->driver->hapd_init == NULL) {
		//nl80211 driver驱动不可用,可能出现空指针，未赋值
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available.");
		return -1;
	}
	//真正的为bss和drv分配内存,将params中信息填充到bss和drv中
	//hapd_init 函数返回值类型实际为bss
	hapd->drv_priv = hapd->driver->hapd_init(hapd, &params);//调用driver_80211.hh中的函数
	os_free(params.bridge);
	if (hapd->drv_priv == NULL) {
		wpa_printf(MSG_ERROR, "%s driver initialization failed.",
			   hapd->driver->name);
		hapd->driver = NULL;
		return -1;
	}
	if (hapd->driver->get_capa &&
		hapd->driver->get_capa(hapd->drv_priv, &capa) == 0) {
		iface->drv_flags = capa.flags;
		iface->probe_resp_offloads = capa.probe_resp_offloads;
		iface->extended_capa = capa.extended_capa;
		iface->extended_capa_mask = capa.extended_capa_mask;
		iface->extended_capa_len = capa.extended_capa_len;
		iface->drv_max_acl_mac_addrs = capa.max_acl_mac_addrs;
	}
	return 0;
}

/////
int setup_interface2(struct hostapd_iface *iface)
{
	iface->wait_channel_update = 0;

	if (hostapd_get_hw_features(iface)) {
	//if (1) {
		/* Not all drivers support this yet, so continue without hw
		 * feature data. */
	} else {
		int ret = hostapd_select_hw_mode(iface);
		//wpa_printf(MSG_DEBUG, "\ncomplete hostapd_select_hw_mode:%d\n",ret);
		//int ret = 0;
		if (ret < 0) {
			wpa_printf(MSG_ERROR, "Could not select hw_mode and "
				   "channel. (%d)", ret);
			goto fail;
		}
		if (ret == 1) {
			wpa_printf(MSG_DEBUG, "Interface initialization will be completed in a callback (ACS)");
			return 0;
		}
		/*
		ret = hostapd_check_ht_capab(iface);
		if (ret < 0)
			goto fail;
		*/
		if (ret == 1) {
			wpa_printf(MSG_DEBUG, "Interface initialization will "
				   "be completed in a callback");
			return 0;
		}

		if (iface->conf->ieee80211h)
			wpa_printf(MSG_DEBUG, "DFS support is enabled");
	}
	return hostapd_setup_interface_complete(iface, 0);
	//return 0;

fail:
	///hostapd_set_state(iface, HAPD_IFACE_DISABLED);
	wpa_printf(MSG_DEBUG, "setup_interface2 failed\n");
	iface->state = HAPD_IFACE_DISABLED;
	//wpa_msg(iface->bss[0]->msg_ctx, MSG_INFO, AP_EVENT_DISABLED);
//	if (iface->interfaces && iface->interfaces->terminate_on_error)
//		eloop_terminate();
	return -1;
}

const char * hostapd_drv_get_radio_name(struct hostapd_data *hapd)
{
	if (hapd->driver == NULL || hapd->drv_priv == NULL ||
	    hapd->driver->get_radio_name == NULL)
		return NULL;
	return hapd->driver->get_radio_name(hapd->drv_priv);
}

//这个函数获取网卡的物理参数重要 phy: 可以打印显示
int hostapd_setup_interface(struct hostapd_iface *iface)
{
	int ret;
	struct hostapd_data *hapd = iface->bss[0];
	size_t i;

	//ret = setup_interface(iface);
	iface->driver_ap_teardown = 0;

	if (!iface->phy[0]) {
		const char *phy = hostapd_drv_get_radio_name(hapd);
		if (phy) {
			//DEBUG
			//wpa_printf(MSG_DEBUG, "phy: %s\n", phy);
			//os_strlcpy(iface->phy, phy, sizeof(iface->phy));
		}
	}

	/*
	 * Make sure that all BSSes get configured with a pointer to the same
	 * driver interface.
	 */
	for (i = 1; i < iface->num_bss; i++) {
		iface->bss[i]->driver = hapd->driver;
		iface->bss[i]->drv_priv = hapd->drv_priv;
	}


	ret = setup_interface2(iface);
	if (ret) {
		wpa_printf(MSG_ERROR, "%s: Unable to setup interface.",
			   iface->bss[0]->conf->iface);
		return -1;
	}

	return 0;
}


int hostapd_drv_send_mlme(struct hostapd_data *hapd,
			  const u8 *msg, size_t len, int noack)
{
	if (hapd->driver == NULL || hapd->driver->send_mlme == NULL)
		return 0;
	return hapd->driver->send_mlme(hapd->drv_priv, msg, len, noack);
}

/*********************一些静态方法***********************/

u16 copy_supp_rates(struct hostapd_data *hapd, struct sta_info *sta,
			   struct ieee802_11_elems *elems)
{
	if (!elems->supp_rates) {
		wpa_printf(MSG_DEBUG, "No supported rates element in AssocReq\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {
        wpa_printf(MSG_DEBUG,
			       "Invalid supported rates element length %d+%d\n",
			       elems->supp_rates_len,
			       elems->ext_supp_rates_len);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->supported_rates_len = merge_byte_arrays(
		sta->supported_rates, sizeof(sta->supported_rates),
		elems->supp_rates, elems->supp_rates_len,
		elems->ext_supp_rates, elems->ext_supp_rates_len);

	return WLAN_STATUS_SUCCESS;
}

u16 copy_sta_ht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *ht_capab, size_t ht_capab_len)
{
	/* Disable HT caps for STAs associated to no-HT BSSes. */
	if (!ht_capab ||
	    ht_capab_len < sizeof(struct ieee80211_ht_capabilities) ||
	    hapd->conf->disable_11n) {
		sta->flags &= ~WLAN_STA_HT;
		os_free(sta->ht_capabilities);
		sta->ht_capabilities = NULL;
		return WLAN_STATUS_SUCCESS;
	}

	if (sta->ht_capabilities == NULL) {
		sta->ht_capabilities =
			(struct ieee80211_ht_capabilities*)os_zalloc(sizeof(struct ieee80211_ht_capabilities));
		if (sta->ht_capabilities == NULL)
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->flags |= WLAN_STA_HT;
	os_memcpy(sta->ht_capabilities, ht_capab,
		  sizeof(struct ieee80211_ht_capabilities));

	return WLAN_STATUS_SUCCESS;
}


//设置关联id
int hostapd_get_aid(struct hostapd_data *hapd, struct sta_info *sta)
{
	int i, j = 32, aid;

	/* get a unique AID */
	if (sta->aid > 0) {
		//wpa_printf(MSG_DEBUG, "  old association AID %d", sta->aid);
		return 0;
	}

	for (i = 0; i < AID_WORDS; i++) {
		if (hapd->sta_aid[i] == (u32) -1)
			continue;
		for (j = 0; j < 32; j++) {
			if (!(hapd->sta_aid[i] & BIT(j)))
				break;
		}
		if (j < 32)
			break;
	}
	if (j == 32)
		return -1;
	aid = i * 32 + j + 1;
	if (aid > 2007)
		return -1;

	sta->aid = aid;
	hapd->sta_aid[i] |= BIT(j);
	//wpa_printf(MSG_DEBUG, "  new association AID %d\n", sta->aid);
	return 0;
}

/**
 * hostapd_init - Allocate and initialize per-interface data
 * @config_file: Path to the configuration file
 * Returns: Pointer to the allocated interface data or %NULL on failure
 *
 * This function is used to allocate main data structures for per-interface
 * data. The allocated data buffer will be freed by calling
 * hostapd_cleanup_iface().
 */
struct hostapd_iface * hostapd_init(struct hapd_interfaces *interfaces,
				    const char *config_file)
{
	struct hostapd_iface *hapd_iface = NULL;
	struct hostapd_config *conf = NULL;
	struct hostapd_data *hapd;
	size_t i;

	hapd_iface = (struct hostapd_iface *)os_zalloc(sizeof(*hapd_iface));
	if (hapd_iface == NULL)
		goto fail;

	hapd_iface->config_fname = os_strdup(config_file);//分配内存保存配置名字
	if (hapd_iface->config_fname == NULL)
		goto fail;
	//config_read_cb   main.c 开始位置
	///tmp/run/hostapd-phy0.conf
	//取hostapd 的配置文件hostapd.conf 中的配置信息，并保存到hostapd_conf的结构体中去
	conf = interfaces->config_read_cb(hapd_iface->config_fname);
	if (conf == NULL)
		goto fail;
	hapd_iface->conf = conf;

	hapd_iface->num_bss = conf->num_bss;////从配置信息中获取BSS 的个数 
	hapd_iface->bss =(struct hostapd_data **)os_calloc(conf->num_bss,
				    sizeof(struct hostapd_data *));
	if (hapd_iface->bss == NULL)
		goto fail;
	
	//这里应该默认的为1   需要打印conf->num_bss
	for (i = 0; i < conf->num_bss; i++) {
		hapd = hapd_iface->bss[i] =
			hostapd_alloc_bss_data(hapd_iface, conf,
					       conf->bss[i]);//初始化每个BSS 数据结构  
		if (hapd == NULL)
			goto fail;
		hapd->msg_ctx = hapd;
	}
	return hapd_iface;
fail:
	wpa_printf(MSG_ERROR, "Failed to set up interface.");		   
	if (conf)
		os_free(conf);
		//hostapd_config_free(conf);
	if (hapd_iface) {
		os_free(hapd_iface->config_fname);
		os_free(hapd_iface->bss);
		wpa_printf(MSG_DEBUG, "%s: free iface %p",
			   __func__, hapd_iface);
		
		os_free(hapd_iface);
	}
	return NULL;
}

struct hostapd_iface * hostapd_interface_init(
        struct hapd_interfaces *interfaces, 
        const char *config_fname, 
        int debug)
{
	struct hostapd_iface *iface;
	int k;

	//wpa_printf(MSG_ERROR, "Configuration file: %s", config_fname);
	iface = hostapd_init(interfaces, config_fname);//读取配置文件
	if (!iface)
		return NULL;
	iface->interfaces = interfaces;
	//for (k = 0; k < debug; k++) {
	//	if (iface->bss[0]->conf->logger_stdout_level > 0)
	//		iface->bss[0]->conf->logger_stdout_level--;
	//}

	if (iface->conf->bss[0]->iface[0] == '\0') {
		wpa_printf(MSG_ERROR, "Interface name not specified in %s",
			   config_fname);
		os_free(iface);
		return NULL;
	}
	return iface;
}

struct hostapd_data *
hostapd_alloc_bss_data(struct hostapd_iface *hapd_iface,
		       struct hostapd_config *conf,
		       struct hostapd_bss_config *bss)
{
	struct hostapd_data *hapd;

	hapd = (struct hostapd_data *)os_zalloc(sizeof(*hapd));
	if (hapd == NULL)
		return NULL;

	//hapd->new_assoc_sta_cb = hostapd_new_assoc_sta;
	hapd->iconf = conf;
	hapd->conf = bss;
	hapd->iface = hapd_iface;
	hapd->driver = hapd->iconf->driver;
	hapd->ctrl_sock = -1;
	os_memcpy(hapd->own_addr,bss->bssid,6);

	return hapd;
}

//为hostapd_config_bss分配内存,该结构体记录的是一个BSS 的具体的配置
void hostapd_interface_init_bss(struct hapd_interfaces *interfaces){
	
	struct hostapd_iface  *iface = NULL;
	struct hostapd_bss_config *bss;	
	struct hostapd_data *hapd;
	struct hostapd_bss_config **tmp_conf;
	iface = interfaces->iface[0];//第一个
	if (iface == NULL) {
		wpa_printf(MSG_ERROR, "hostapd_iface can not access.");
		//hostapd_config_free(conf);
		return ;
	}	
	tmp_conf = (struct hostapd_bss_config **)os_realloc_array(
			iface->conf->bss, iface->conf->num_bss + 1,
			sizeof(struct hostapd_bss_config *));
	if (tmp_conf) {
		iface->conf->bss = tmp_conf;
		iface->conf->last_bss = tmp_conf[0];
	}
	if (tmp_conf == NULL) {
		wpa_printf(MSG_ERROR, "hostapd_bss_config alloc failed.");
		os_free(tmp_conf);
		//hostapd_config_free(conf);
		return ;
	}
	bss = iface->conf->bss[iface->conf->num_bss];
	//iface->conf->num_bss++;
	//hapd = hostapd_alloc_bss_data(iface, iface->conf, bss)
	
	if (interfaces->iface[0] == NULL || interfaces->iface[0]->bss[0] == NULL) {
		//nl80211 driver驱动不可用,可能出现空指针，未赋值
		wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		return ;
    }
	//之前hapd应该已经分配过内存了
	hapd = interfaces->iface[0]->bss[0];
	//hapd->new_assoc_sta_cb = hostapd_new_assoc_sta;
	//hapd->iconf = conf;
	hapd->conf = bss;
	//hapd->iface = hapd_iface;
	//hapd->driver = hapd->iconf->driver;
	//hapd->ctrl_sock = -1;
	if (hapd == NULL) {
		os_free(tmp_conf);
		return ;
	}
	iface->conf->last_bss = bss;
	iface->bss[iface->num_bss] = hapd;
	hapd->msg_ctx = hapd;		
}
	//void hostapd_data::hostapd_inf_init(struct hapd_interfaces &interfaces){
void hostapd_inf_init(struct hapd_interfaces *interfaces){
	os_memset(interfaces, 0, sizeof(struct hapd_interfaces));
	interfaces->config_read_cb = hostapd_config_read;
		
	interfaces->global_iface_path = NULL;
	interfaces->global_iface_name = NULL;
	interfaces->global_ctrl_sock = -1;
		
	interfaces->count = 1;
	if (interfaces->count) {
	    interfaces->iface = (struct hostapd_iface**)os_calloc(interfaces->count,sizeof(struct hostapd_iface *));
		if (interfaces->iface == NULL) {
			wpa_printf(MSG_ERROR, "interfaces->iface malloc failed.");
			return ;
		}
	}
	interfaces->iface[0] = hostapd_interface_init(interfaces,"/tmp/run/hostapd-phy0.conf", 0);		
	if (!interfaces->iface[0]) {
		wpa_printf(MSG_ERROR, "Failed to initialize interface");
		goto out;
	}
	wpa_printf(MSG_DEBUG, "hostapd_inf_init success\n");		
	return ;
out:
	os_free(interfaces->iface);
}

