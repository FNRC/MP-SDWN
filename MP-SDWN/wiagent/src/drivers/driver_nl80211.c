/*
 * Driver interaction with Linux nl80211/cfg80211
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 * Copyright (c) 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 * Copyright (c) 2009-2010, Atheros Communications
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef DRIVER_NL80211_H
#define DRIVER_NL80211_H

#include <libnl-tiny/netlink/genl/genl.h>
#include <libnl-tiny/netlink/genl/family.h>
#include <libnl-tiny/netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>
#include<unistd.h>

#include <linux/socket.h>

#include "../ap/ieee802_1x_defs.h"
#include "../ap/sta_info.h"
#include "../utils/qca-vendor.h"
#include "../utils/common.h"
#include "nl80211_copy.h"
#include "driver.h"


/* libnl 2.0 compatibility code */
#define nl_handle nl_sock
//#define nl80211_handle_alloc nl_socket_alloc_cb
//#define nl80211_handle_destroy nl_socket_free

#define OUI_QCA 0x001374

struct phy_info_arg {
	u16 *num_modes;
	struct hostapd_hw_modes *modes;
	int last_mode, last_chan_idx;
};

struct wpa_driver_nl80211_data {
	struct nl80211_global *global;
	struct dl_list list;
	//struct dl_list wiphy_list;
	char phyname[32];
	void *ctx;
	int ifindex;
	int if_removed;
	int if_disabled;
	int ignore_if_down_event;
	//struct rfkill_data *rfkill;
	struct wpa_driver_capa capa;
	u8 *extended_capa, *extended_capa_mask;
	unsigned int extended_capa_len;
	int has_capability;

	int operstate;

	int scan_complete_events;
	enum scan_states {
		NO_SCAN, SCAN_REQUESTED, SCAN_STARTED, SCAN_COMPLETED,
		SCAN_ABORTED, SCHED_SCAN_STARTED, SCHED_SCAN_STOPPED,
		SCHED_SCAN_RESULTS
	} scan_state;

	struct nl_cb *nl_cb;

	u8 auth_bssid[ETH_ALEN];
	u8 auth_attempt_bssid[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	u8 prev_bssid[ETH_ALEN];
	int associated;
	u8 ssid[32];
	size_t ssid_len;
	enum nl80211_iftype nlmode;
	enum nl80211_iftype ap_scan_as_station;
	unsigned int assoc_freq;

	int monitor_sock;
	int monitor_ifidx;
	int monitor_refcount;

	unsigned int disabled_11b_rates:1;
	unsigned int pending_remain_on_chan:1;
	unsigned int in_interface_list:1;
	unsigned int device_ap_sme:1;
	unsigned int poll_command_supported:1;
	unsigned int data_tx_status:1;
	unsigned int scan_for_auth:1;
	unsigned int retry_auth:1;
	unsigned int use_monitor:1;
	unsigned int ignore_next_local_disconnect:1;
	unsigned int ignore_next_local_deauth:1;
	unsigned int allow_p2p_device:1;
	unsigned int hostapd:1;
	unsigned int start_mode_ap:1;
	unsigned int start_iface_up:1;
	unsigned int test_use_roc_tx:1;
	unsigned int ignore_deauth_event:1;
	unsigned int dfs_vendor_cmd_avail:1;

	u64 remain_on_chan_cookie;
	u64 send_action_cookie;

	unsigned int last_mgmt_freq;

	struct wpa_driver_scan_filter *filter_ssids;
	size_t num_filter_ssids;

	struct i802_bss *first_bss;

	int eapol_tx_sock;

	int eapol_sock; /* socket for EAPOL frames */

	int default_if_indices[16];
	int *if_indices;
	int num_if_indices;

	/* From failed authentication command */
	int auth_freq;
	u8 auth_bssid_[ETH_ALEN];
	u8 auth_ssid[32];
	size_t auth_ssid_len;
	int auth_alg;
	u8 *auth_ie;
	size_t auth_ie_len;
	u8 auth_wep_key[4][16];
	size_t auth_wep_key_len[4];
	int auth_wep_tx_keyidx;
	int auth_local_state_change;
	int auth_p2p;
};

struct i802_bss {
	struct wpa_driver_nl80211_data *drv;
	struct i802_bss *next;
	int ifindex;
	u64 wdev_id;
	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ];
	unsigned int beacon_set:1;
	unsigned int added_if_into_bridge:1;
	unsigned int added_bridge:1;
	unsigned int in_deinit:1;
	unsigned int wdev_id_set:1;
	unsigned int added_if:1;

	u8 addr[ETH_ALEN];

	int freq;
	int bandwidth;
	int if_dynamic;

	void *ctx;
	struct nl_handle *nl_preq, *nl_mgmt;
	struct nl_cb *nl_cb;

	struct nl80211_wiphy_data *wiphy_data;
	//struct dl_list wiphy_list;
};

struct nl80211_global {
	struct dl_list interfaces;
	int if_add_ifindex;
	u64 if_add_wdevid;
	int if_add_wdevid_set;
	//struct netlink_data *netlink;
	struct nl_cb *nl_cb;
	struct nl_handle *nl;
	int nl80211_id;
	//int ioctl_sock; /* socket for ioctl() use */

	struct nl_handle *nl_event;
};

static u32 sta_flags_nl80211(int flags)
{
	u32 f = 0;

	if (flags & WPA_STA_AUTHORIZED)
		f |= BIT(NL80211_STA_FLAG_AUTHORIZED);
	if (flags & WPA_STA_WMM)
		f |= BIT(NL80211_STA_FLAG_WME);
	if (flags & WPA_STA_SHORT_PREAMBLE)
		f |= BIT(NL80211_STA_FLAG_SHORT_PREAMBLE);
	if (flags & WPA_STA_MFP)
		f |= BIT(NL80211_STA_FLAG_MFP);
	if (flags & WPA_STA_TDLS_PEER)
		f |= BIT(NL80211_STA_FLAG_TDLS_PEER);

	return f;
}

struct family_data {
	const char *group;
	int id;
};


/*******************nl80211_global_init  函数实现start**********************/
static uint32_t port_bitmap[32] = { 0 };
/* nl80211 code */
static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = (int *)arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = (int *)arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = (int *)arg;
	*ret = err->error;
	return NL_SKIP;
}


static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}
/*//此函数复写了原函数这里不使用用
static void nl80211_handle_destroy(struct nl_handle *handle)
{
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	port_bitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
*/
//销毁函数
static void nl_destroy_handles(struct nl_handle **handle)
{
	if (*handle == NULL)
		return;
	//nl80211_handle_destroy(*handle);
	nl_socket_free(*handle);//使用libnl的API接口函数
	*handle = NULL;
}
/*

static struct nl_handle *nl80211_handle_alloc(void *cb)
{
	struct nl_handle *handle;
	uint32_t pid = getpid() & 0x3FFFFF;
	int i;

	handle = nl_handle_alloc_cb(cb);

	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32)))
			continue;
		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);

	return handle;
}
*/

static struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg)
{
	struct nl_handle *handle;
	//创建netlink这里使用libnl的API函数
	//handle = nl80211_handle_alloc(cb);
	handle = nl_socket_alloc_cb(cb);
	//fprintf(stderr, "nl_create_handle 创建111 --nm\n");
	if (handle == NULL) {
		fprintf(stderr, "nl_create_handle 创建netlink失败 --nm\n");
		return NULL;
	}
	//fprintf(stderr, "nl_create_handle 创建222 --nm\n");
	//连接内核的netlink
	if (genl_connect(handle)) {
		//wpa_printf(MSG_ERROR, "nl80211: Failed to connect to generic "
		//	   "netlink (%s)", dbg);
		//nl80211_handle_destroy(handle);
		fprintf(stderr, "genl_connect 连接内核失败 --nm\n");
		nl_socket_free(handle);//使用libnl的API接口函数
		return NULL;
	}

	//fprintf(stderr, "nl_create_handle creat success--nm\n");
	return handle;
}
/*
* Android ICS has very minimal genl_ctrl_resolve() implementation, so
* need to work around that.
*/
/*libnl的API系统库函数
static int genl_ctrl_resolve(struct nl_handle *handle,
				     const char *name)
{

	struct nl_cache *cache = NULL;
	struct genl_family *nl80211 = NULL;
	int id = -1;
	// 创建cache，我也不清楚这个操作必要性
	if (genl_ctrl_alloc_cache(handle, &cache) < 0) {
		//wpa_printf(MSG_ERROR, "nl80211: Failed to allocate generic "
			//   "netlink cache");
		goto fail;
	}
	// // 查找NL80211簇
	nl80211 = genl_ctrl_search_by_name(cache, name);
	if (nl80211 == NULL)
		goto fail;

	id = genl_family_get_id(nl80211);

fail:
	if (nl80211)
		genl_family_put(nl80211);
	if (cache)
		nl_cache_free(cache);

	return id;
}
*/

/**
 *return@ 1:right,<0 :failed
 */
static int send_and_recv(struct nl80211_global *global,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;//-12
	
    cb = nl_cb_clone(global->nl_cb);
	if (!cb)
		goto out;
	
    err = nl_send_auto_complete(nl_handle, msg);
	if (err < 0) {
	    wpa_printf(MSG_INFO,
				   "nl80211: %s->nl_send_auto_complete failed: %d",
    				   __func__, err);
	    goto out;
    }
	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler) 
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0) {
		int res = nl_recvmsgs(nl_handle, cb);
		if (res < 0) {
			wpa_printf(MSG_INFO,
				   "nl80211: %s->nl_recvmsgs failed: %d",
				   __func__, res);
		}
	}
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}


static int send_and_recv_msgs_global(struct nl80211_global *global,
				     struct nl_msg *msg,
				     int (*valid_handler)(struct nl_msg *, void *),
				     void *valid_data)
{
	return send_and_recv(global, global->nl, msg, valid_handler,
			     valid_data);
}

static int family_handler(struct nl_msg *msg, void *arg)
{
	struct family_data *res = (struct family_data *)arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int i;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, (struct nlattr *)nla_data(mcgrp),
			  nla_len(mcgrp), NULL);
		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    os_strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
			       res->group,
			       nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;
		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	};

	return NL_SKIP;
}

static int nl_get_multicast_id(struct nl80211_global *global,
			       const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = { group, -ENOENT };

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(global->nl, "nlctrl"),
		    0, 0, CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv_msgs_global(global, msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

//TODO:接收函数
static int process_global_event(struct nl_msg *msg, void *arg)
{

	return NL_SKIP;
}

static int wpa_driver_nl80211_init_nl_global(struct nl80211_global *global)
{
	int ret;

	global->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (global->nl_cb == NULL) {
		fprintf(stderr, "nl80211: netlink 结构体内存分配失败'--nm\n");
		return -1;
	}

	global->nl = nl_create_handle(global->nl_cb, "nl");
	if (global->nl == NULL){
		fprintf(stderr, "netlink socket Creat failed --nm\n");
		goto err;
	}
	//fprintf(stderr, "nl80211: nl_create_handle分配成功'--nm\n");

	global->nl80211_id = genl_ctrl_resolve(global->nl, "nl80211");
	if (global->nl80211_id < 0) {
		//wpa_printf(MSG_ERROR, "nl80211: 'nl80211' generic netlink not "
		//	   "found");
		fprintf(stderr, "nl80211: 'nl80211' generic netlink not \
			found --nm\n");
		goto err;
	}
	//fprintf(stderr, "nl80211: genl_ctrl_resolve分配成功'--nm\n");
	//netlink事件之前由于没有内存分配导致了后面出现了段错误
	//创建了两个netlink,具体的作用未知,可能是基于事件的内核态通知用户态的netlink 猜测???
	global->nl_event = nl_create_handle(global->nl_cb, "event");
	if (global->nl_event == NULL)
		goto err;

	ret = nl_get_multicast_id(global, "nl80211", "scan");
	//fprintf(stderr, "nl80211: nl_get_multicast_id--scan分配成功'--nm\n");
	if (ret >= 0){
		//fprintf(stderr, "nl80211: nl_socket_add_membership分配000'--nm\n");
		ret = nl_socket_add_membership(global->nl_event, ret);
		//fprintf(stderr, "nl80211: nl_socket_add_membership分配0001'--nm\n");
	}

	if (ret < 0) {
		//wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
		//	   "membership for scan events: %d (%s)",
		//	   ret, strerror(-ret));
		fprintf(stderr, "nl80211: Could not add \
				multicastmembership for scan events --nm\n");
		goto err;
	}
	//fprintf(stderr, "nl80211: nl_socket_add_membership分配成功1111'--nm\n");
	ret = nl_get_multicast_id(global, "nl80211", "mlme");
	//fprintf(stderr, "nl80211: nl_get_multicast_id--mlme分配成功'--nm\n");
	if (ret >= 0)
		ret = nl_socket_add_membership(global->nl_event, ret);
	//fprintf(stderr, "nl80211: nl_socket_add_membership分配成功2222'--nm\n");
	if (ret < 0) {
		//wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
		//	   "membership for mlme events: %d (%s)",
		//	   ret, strerror(-ret));
		fprintf(stderr, "nl80211: Could not add multicast \
				membership for mlme events --nm\n");
		goto err;
	}

	ret = nl_get_multicast_id(global, "nl80211", "regulatory");
		//fprintf(stderr, "nl80211: nl_get_multicast_id--regulatory分配成功'--nm\n");
	if (ret >= 0)
		ret = nl_socket_add_membership(global->nl_event, ret);
	if (ret < 0) {
		//wpa_printf(MSG_DEBUG, "nl80211: Could not add multicast "
		//	   "membership for regulatory events: %d (%s)",
		//	   ret, strerror(-ret));
		fprintf(stderr, "nl80211: Could not add multicast \
			   membership for regulatory events:--nm\n");
		/* Continue without regulatory events */
	}
	//fprintf(stderr, "nl80211: nl_socket_add_membership分配成功3333'--nm\n");
	ret = nl_get_multicast_id(global, "nl80211", "vendor");
	if (ret >= 0)
		ret = nl_socket_add_membership(global->nl_event, ret);
	if (ret < 0) {
		//wpa_printf(MSG_DEBUG, "nl80211: Could not add multicast "
		//	   "membership for regulatory events: %d (%s)",
		//	   ret, strerror(-ret));
		fprintf(stderr, "nl80211: Could not add multicast \
			membership for regulatory events: --nm\n");
		/* Continue without vendor events */
	}

	nl_cb_set(global->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
		  no_seq_check, NULL);
	//fprintf(stderr, "no_seq_check 执行完毕--nm\n");
	nl_cb_set(global->nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
		  process_global_event, global);
	//fprintf(stderr, "process_global_event 执行完毕--nm\n");
	//nl80211_register_eloop_read(&global->nl_event,
	//			    wpa_driver_nl80211_event_receive,
	//			    global->nl_cb);
	//fprintf(stderr, "wpa_driver_nl80211_init_nl_global 执行完毕--nm\n");
	return 0;

err:
	nl_destroy_handles(&global->nl_event);
	nl_destroy_handles(&global->nl);
	nl_cb_put(global->nl_cb);
	global->nl_cb = NULL;
	return -1;
}


//初始化并分配内存global 结构体,在这里初始化与nl802.11层的netlink连接
static void * nl80211_global_init(void)
{
	struct nl80211_global *global;
	struct netlink_config *cfg;

	global = (struct nl80211_global *)os_zalloc(sizeof(*global));
	if (global == NULL){
		fprintf(stderr, "global_init global分配内存失败 --nm\n");
		return NULL;
	}

	//global->ioctl_sock = -1;
	//dl_list_init(&global->interfaces);
	global->if_add_ifindex = -1;

	//真正的建立netlink连接
	if (wpa_driver_nl80211_init_nl_global(global) < 0){
		fprintf(stderr, "global_init netlink创建失败 --nm\n");
		goto err;
	}
	//fprintf(stderr, "nl80211_global_init creat success --nm\n");

	return global;

err:
	os_free(global);
	//nl80211_global_deinit(global);
	return NULL;
}
/*******************nl80211_global_init  函数实现end**********************/


/*******************i802_init  函数实现start**********************/
static int process_drv_event(struct nl_msg *msg, void *arg)
{
	//这里面有设置接口的模式的，再就是事件驱动的初始化
	/*
	struct wpa_driver_nl80211_data *drv = arg;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct i802_bss *bss;
	*/
	return NL_SKIP;
}

static const char * nl80211_command_to_string(enum nl80211_commands cmd)
{
#define C2S(x) case x: return #x;
	switch (cmd) {
	C2S(NL80211_CMD_UNSPEC)
	C2S(NL80211_CMD_GET_WIPHY)
	C2S(NL80211_CMD_SET_WIPHY)
	C2S(NL80211_CMD_NEW_WIPHY)
	C2S(NL80211_CMD_DEL_WIPHY)
	C2S(NL80211_CMD_GET_INTERFACE)
	C2S(NL80211_CMD_SET_INTERFACE)
	C2S(NL80211_CMD_NEW_INTERFACE)
	C2S(NL80211_CMD_DEL_INTERFACE)
	C2S(NL80211_CMD_GET_KEY)
	C2S(NL80211_CMD_SET_KEY)
	C2S(NL80211_CMD_NEW_KEY)
	C2S(NL80211_CMD_DEL_KEY)
	C2S(NL80211_CMD_GET_BEACON)
	C2S(NL80211_CMD_SET_BEACON)
	C2S(NL80211_CMD_START_AP)
	C2S(NL80211_CMD_STOP_AP)
	C2S(NL80211_CMD_GET_STATION)
	C2S(NL80211_CMD_SET_STATION)
	C2S(NL80211_CMD_NEW_STATION)
	C2S(NL80211_CMD_DEL_STATION)
	C2S(NL80211_CMD_GET_MPATH)
	C2S(NL80211_CMD_SET_MPATH)
	C2S(NL80211_CMD_NEW_MPATH)
	C2S(NL80211_CMD_DEL_MPATH)
	C2S(NL80211_CMD_SET_BSS)
	C2S(NL80211_CMD_SET_REG)
	C2S(NL80211_CMD_REQ_SET_REG)
	C2S(NL80211_CMD_GET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MESH_CONFIG)
	C2S(NL80211_CMD_SET_MGMT_EXTRA_IE)
	C2S(NL80211_CMD_GET_REG)
	C2S(NL80211_CMD_GET_SCAN)
	C2S(NL80211_CMD_TRIGGER_SCAN)
	C2S(NL80211_CMD_NEW_SCAN_RESULTS)
	C2S(NL80211_CMD_SCAN_ABORTED)
	C2S(NL80211_CMD_REG_CHANGE)
	C2S(NL80211_CMD_AUTHENTICATE)
	C2S(NL80211_CMD_ASSOCIATE)
	C2S(NL80211_CMD_DEAUTHENTICATE)
	C2S(NL80211_CMD_DISASSOCIATE)
	C2S(NL80211_CMD_MICHAEL_MIC_FAILURE)
	C2S(NL80211_CMD_REG_BEACON_HINT)
	C2S(NL80211_CMD_JOIN_IBSS)
	C2S(NL80211_CMD_LEAVE_IBSS)
	C2S(NL80211_CMD_TESTMODE)
	C2S(NL80211_CMD_CONNECT)
	C2S(NL80211_CMD_ROAM)
	C2S(NL80211_CMD_DISCONNECT)
	C2S(NL80211_CMD_SET_WIPHY_NETNS)
	C2S(NL80211_CMD_GET_SURVEY)
	C2S(NL80211_CMD_NEW_SURVEY_RESULTS)
	C2S(NL80211_CMD_SET_PMKSA)
	C2S(NL80211_CMD_DEL_PMKSA)
	C2S(NL80211_CMD_FLUSH_PMKSA)
	C2S(NL80211_CMD_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL)
	C2S(NL80211_CMD_SET_TX_BITRATE_MASK)
	C2S(NL80211_CMD_REGISTER_FRAME)
	C2S(NL80211_CMD_FRAME)
	C2S(NL80211_CMD_FRAME_TX_STATUS)
	C2S(NL80211_CMD_SET_POWER_SAVE)
	C2S(NL80211_CMD_GET_POWER_SAVE)
	C2S(NL80211_CMD_SET_CQM)
	C2S(NL80211_CMD_NOTIFY_CQM)
	C2S(NL80211_CMD_SET_CHANNEL)
	C2S(NL80211_CMD_SET_WDS_PEER)
	C2S(NL80211_CMD_FRAME_WAIT_CANCEL)
	C2S(NL80211_CMD_JOIN_MESH)
	C2S(NL80211_CMD_LEAVE_MESH)
	C2S(NL80211_CMD_UNPROT_DEAUTHENTICATE)
	C2S(NL80211_CMD_UNPROT_DISASSOCIATE)
	C2S(NL80211_CMD_NEW_PEER_CANDIDATE)
	C2S(NL80211_CMD_GET_WOWLAN)
	C2S(NL80211_CMD_SET_WOWLAN)
	C2S(NL80211_CMD_START_SCHED_SCAN)
	C2S(NL80211_CMD_STOP_SCHED_SCAN)
	C2S(NL80211_CMD_SCHED_SCAN_RESULTS)
	C2S(NL80211_CMD_SCHED_SCAN_STOPPED)
	C2S(NL80211_CMD_SET_REKEY_OFFLOAD)
	C2S(NL80211_CMD_PMKSA_CANDIDATE)
	C2S(NL80211_CMD_TDLS_OPER)
	C2S(NL80211_CMD_TDLS_MGMT)
	C2S(NL80211_CMD_UNEXPECTED_FRAME)
	C2S(NL80211_CMD_PROBE_CLIENT)
	C2S(NL80211_CMD_REGISTER_BEACONS)
	C2S(NL80211_CMD_UNEXPECTED_4ADDR_FRAME)
	C2S(NL80211_CMD_SET_NOACK_MAP)
	C2S(NL80211_CMD_CH_SWITCH_NOTIFY)
	C2S(NL80211_CMD_START_P2P_DEVICE)
	C2S(NL80211_CMD_STOP_P2P_DEVICE)
	C2S(NL80211_CMD_CONN_FAILED)
	C2S(NL80211_CMD_SET_MCAST_RATE)
	C2S(NL80211_CMD_SET_MAC_ACL)
	C2S(NL80211_CMD_RADAR_DETECT)
	C2S(NL80211_CMD_GET_PROTOCOL_FEATURES)
	C2S(NL80211_CMD_UPDATE_FT_IES)
	C2S(NL80211_CMD_FT_EVENT)
	C2S(NL80211_CMD_CRIT_PROTOCOL_START)
	C2S(NL80211_CMD_CRIT_PROTOCOL_STOP)
	C2S(NL80211_CMD_GET_COALESCE)
	C2S(NL80211_CMD_SET_COALESCE)
	C2S(NL80211_CMD_CHANNEL_SWITCH)
	C2S(NL80211_CMD_VENDOR)
	C2S(NL80211_CMD_SET_QOS_MAP)
	default:
		return "NL80211_CMD_UNKNOWN";
	}
#undef C2S
}

static void mlme_event_mgmt(struct i802_bss *bss,
			    struct nlattr *freq, struct nlattr *sig,
			    const u8 *frame, size_t len)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 fc, stype;
	int ssi_signal = 0;
	int rx_freq = 0;

	mgmt = (const struct ieee80211_mgmt *) frame;
	if (len < 24) {
		wpa_printf(MSG_DEBUG, "nl80211: Too short management frame");
		return;
	}

	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);

	if (sig)
		ssi_signal = (s32) nla_get_u32(sig);

	os_memset(&event, 0, sizeof(event));
	if (freq) {
		event.rx_mgmt.freq = nla_get_u32(freq);
		rx_freq = drv->last_mgmt_freq = event.rx_mgmt.freq;
	}
    /**
	wpa_printf(MSG_DEBUG,
		   "nl80211: RX frame freq=%d ssi_signal=%d stype=%u len=%u",
		   rx_freq, ssi_signal, stype, (unsigned int) len);
    **/
	event.rx_mgmt.frame = frame;
	event.rx_mgmt.frame_len = len;
	event.rx_mgmt.ssi_signal = ssi_signal;
	event.rx_mgmt.drv_priv = bss;
	wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
}


static void mlme_event(struct i802_bss *bss,
		       enum nl80211_commands cmd, struct nlattr *frame,
		       struct nlattr *addr, struct nlattr *timed_out,
		       struct nlattr *freq, struct nlattr *ack,
		       struct nlattr *cookie, struct nlattr *sig)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	const u8 *data;
    size_t len;

	data = (const u8 *)nla_data(frame);
	len = nla_len(frame);
	if (len < 4 + 2 * ETH_ALEN) {
		wpa_printf(MSG_MSGDUMP, "nl80211: MLME event %d (%s) on %s("
			   MACSTR ") - too short",
			   cmd, nl80211_command_to_string(cmd), bss->ifname,
			   MAC2STR(bss->addr));
		return;
	}

	switch (cmd) {
	case NL80211_CMD_FRAME:
		mlme_event_mgmt(bss, freq, sig, nla_data(frame),
		    nla_len(frame));
	break;

	default:
		break;
	}
}

static int process_bss_event(struct nl_msg *msg, void *arg)
{
	struct i802_bss *bss = (struct i802_bss *)arg;
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	switch (gnlh->cmd) {
	case NL80211_CMD_FRAME:
	case NL80211_CMD_FRAME_TX_STATUS:
	//need to notice gnlh->cmd is u8 type --nm
		mlme_event(bss, (enum nl80211_commands)gnlh->cmd, tb[NL80211_ATTR_FRAME],
			   tb[NL80211_ATTR_MAC], tb[NL80211_ATTR_TIMED_OUT],
			   tb[NL80211_ATTR_WIPHY_FREQ], tb[NL80211_ATTR_ACK],
			   tb[NL80211_ATTR_COOKIE],
			   tb[NL80211_ATTR_RX_SIGNAL_DBM]);
		break;
	case NL80211_CMD_UNEXPECTED_FRAME:
		//nl80211_spurious_frame(bss, tb, 0);
		break;
	case NL80211_CMD_UNEXPECTED_4ADDR_FRAME:
		//nl80211_spurious_frame(bss, tb, 1);
		break;
	default:
		wpa_printf(MSG_DEBUG, "nl80211: Ignored unknown event "
			   "(cmd=%d)", gnlh->cmd);
		break;
	}
	return NL_SKIP;
}
static int wpa_driver_nl80211_init_nl(struct wpa_driver_nl80211_data *drv)
{
	drv->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!drv->nl_cb) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to alloc cb struct");
		return -1;
	}

	nl_cb_set(drv->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
		  no_seq_check, NULL);
	nl_cb_set(drv->nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
		  process_drv_event, drv);
	//wpa_printf(MSG_ERROR, "wpa_driver_nl80211_init_nls success to init\n");
	return 0;
}

static void * nl80211_cmd(struct wpa_driver_nl80211_data *drv,
			  struct nl_msg *msg, int flags, uint8_t cmd)
{

////往刚生成的帧中填充头部信息
	return genlmsg_put(msg, 0, 0, drv->global->nl80211_id,
			   0, flags, cmd, 0);
}

static int nl80211_alloc_mgmt_handle(struct i802_bss *bss)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;

	if (bss->nl_mgmt) {
		wpa_printf(MSG_DEBUG, "nl80211: Mgmt reporting "
			   "already on! (nl_mgmt=%p)", bss->nl_mgmt);
		return -1;
	}

	bss->nl_mgmt = nl_create_handle(drv->nl_cb, "mgmt");
	if (bss->nl_mgmt == NULL)
		return -1;
	wpa_printf(MSG_DEBUG, "bss->nl_mgmt success\n");
	return 0;
}

static int nl80211_set_iface_id(struct nl_msg *msg, struct i802_bss *bss)
{
	if (bss->wdev_id_set)
		NLA_PUT_U64(msg, NL80211_ATTR_WDEV, bss->wdev_id);
	else
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, bss->ifindex);
	return 0;

nla_put_failure:
	return -1;
}

static int nl80211_register_frame(struct i802_bss *bss,
				  struct nl_handle *nl_handle,
				  u16 type, const u8 *match, size_t match_len)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret = -1;
	char buf[30];

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	buf[0] = '\0';
	//wpa_snprintf_hex(buf, sizeof(buf), match, match_len);
	//wpa_printf(MSG_DEBUG, "nl80211: Register frame type=0x%x nl_handle=%p match=%s",
	//	   type, nl_handle, buf);

	nl80211_cmd(drv, msg, 0, NL80211_CMD_REGISTER_ACTION);

	if (nl80211_set_iface_id(msg, bss) < 0)
		goto nla_put_failure;

	NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, type);
	NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, match_len, match);

	ret = send_and_recv(drv->global, nl_handle, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Register frame command "
			   "failed (type=%u): ret=%d (%s)\n",
			   type, ret, strerror(-ret));
		//wpa_hexdump(MSG_DEBUG, "nl80211: Register frame match",
		//	    match, match_len);
		goto nla_put_failure;
	}
	ret = 0;
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int wpa_driver_nl80211_capa(struct wpa_driver_nl80211_data *drv)
{
	//wpa_driver_nl80211_capa
	drv->has_capability = 1;
	drv->capa.key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
		WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
	drv->capa.auth = WPA_DRIVER_AUTH_OPEN |
		WPA_DRIVER_AUTH_SHARED |
		WPA_DRIVER_AUTH_LEAP;

	drv->capa.flags |= WPA_DRIVER_FLAGS_SANE_ERROR_CODES;
	drv->capa.flags |= WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC_DONE;
	drv->capa.flags |= WPA_DRIVER_FLAGS_EAPOL_TX_STATUS;
	drv->capa.flags |= WPA_DRIVER_FLAGS_AP_TEARDOWN_SUPPORT;
	drv->start_mode_ap = 1;
	//TODO
	return 0;
}



static int nl80211_register_spurious_class3(struct i802_bss *bss)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_UNEXPECTED_FRAME);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, bss->ifindex);

	ret = send_and_recv(drv->global, bss->nl_mgmt, msg, NULL, NULL);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Register spurious class3 "
			   "failed: ret=%d (%s)",
			   ret, strerror(-ret));
		goto nla_put_failure;
	}
	ret = 0;
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int nl80211_mgmt_subscribe_ap(struct i802_bss *bss)
{
	static const int stypes[] = {
		WLAN_FC_STYPE_AUTH,
		WLAN_FC_STYPE_ASSOC_REQ,
		WLAN_FC_STYPE_REASSOC_REQ,
		WLAN_FC_STYPE_DISASSOC,
		WLAN_FC_STYPE_DEAUTH,
		WLAN_FC_STYPE_ACTION,
		WLAN_FC_STYPE_PROBE_REQ,
/* Beacon doesn't work as mac80211 doesn't currently allow
 * it, but it wouldn't really be the right thing anyway as
 * it isn't per interface ... maybe just dump the scan
 * results periodically for OLBC?
 */
		/* WLAN_FC_STYPE_BEACON, */
	};
	unsigned int i;

	if (nl80211_alloc_mgmt_handle(bss))
		return -1;
	wpa_printf(MSG_DEBUG, "nl80211: Subscribe to mgmt frames with AP "
		   "handle %p\n", bss->nl_mgmt);

	//hostapd may have done,so no need do again
	for (i = 0; i < ARRAY_SIZE(stypes); i++) {
		if (nl80211_register_frame(bss, bss->nl_mgmt,
					   (WLAN_FC_TYPE_MGMT << 2) |
					   (stypes[i] << 4),
					   NULL, 0) < 0) {
			goto out_err;
		}
	}
	/*
	if (nl80211_register_spurious_class3(bss))
		goto out_err;
    */
	//if (nl80211_get_wiphy_data_ap(bss) == NULL)
	//	goto out_err;

	//nl80211_mgmt_handle_register_eloop(bss);
	return 0;

out_err:
	wpa_printf(MSG_DEBUG, "nl80211_mgmt_subscribe_ap failed\n");
	nl_destroy_handles(&bss->nl_mgmt);
	return -1;
}

static int nl80211_mgmt_subscribe_ap_dev_sme(struct i802_bss *bss)
{
	if (nl80211_alloc_mgmt_handle(bss))
		return -1;
	wpa_printf(MSG_DEBUG, "nl80211: Subscribe to mgmt frames with AP "
		   "handle %p (device SME)", bss->nl_mgmt);

	if (nl80211_register_frame(bss, bss->nl_mgmt,
				   (WLAN_FC_TYPE_MGMT << 2) |
				   (WLAN_FC_STYPE_ACTION << 4),
				   NULL, 0) < 0)
		goto out_err;

	//nl80211_mgmt_handle_register_eloop(bss);
	return 0;

out_err:
	nl_destroy_handles(&bss->nl_mgmt);
	return -1;
}

static int nl80211_setup_ap(struct i802_bss *bss)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	if (!drv->device_ap_sme && !drv->use_monitor)
	if (nl80211_mgmt_subscribe_ap(bss))
		return -1;
	wpa_printf(MSG_DEBUG, "nl80211_setup_ap success\n");
	return 0;
}

static int is_ap_interface(enum nl80211_iftype nlmode)
{
	return nlmode == NL80211_IFTYPE_AP ||
		nlmode == NL80211_IFTYPE_P2P_GO;
}

static int is_sta_interface(enum nl80211_iftype nlmode)
{
	return nlmode == NL80211_IFTYPE_STATION ||
		nlmode == NL80211_IFTYPE_P2P_CLIENT;
}

static int wpa_driver_nl80211_set_mode(struct i802_bss *bss,
				       enum nl80211_iftype nlmode)
{
	if (is_ap_interface(nlmode)) {
		//nl80211_mgmt_unsubscribe(bss, "start AP");
		/* Setup additional AP mode functionality if needed */
		if (nl80211_setup_ap(bss)){
			return -1;
			wpa_printf(MSG_DEBUG, "nl80211_setup_ap failed\n");
		}

	}
	return 0;
}
static int
wpa_driver_nl80211_finish_drv_init(struct wpa_driver_nl80211_data *drv,
				   const u8 *set_addr, int first)
{
	struct i802_bss *bss = drv->first_bss;
	int send_rfkill_event = 0;
	enum nl80211_iftype nlmode;

	drv->ifindex = if_nametoindex(bss->ifname);
	bss->ifindex = drv->ifindex;
	bss->wdev_id = drv->global->if_add_wdevid;
	bss->wdev_id_set = drv->global->if_add_wdevid_set;

	bss->if_dynamic = drv->ifindex == drv->global->if_add_ifindex;
	bss->if_dynamic = bss->if_dynamic || drv->global->if_add_wdevid_set;
	drv->global->if_add_wdevid_set = 0;

	if (wpa_driver_nl80211_capa(drv))
		return -1;

	//.............
	nlmode = NL80211_IFTYPE_AP;//set AP mode only
	if (wpa_driver_nl80211_set_mode(bss, nlmode) < 0) {
		wpa_printf(MSG_ERROR, "nl80211: Could not configure driver mode");
		return -1;
	}
	wpa_printf(MSG_ERROR, "wpa_driver_nl80211_finish_drv_init\n");
	return 0;
}

//call_func is complete in odinagnet --nm
static int nl80211_init_bss(struct i802_bss *bss)
{
	bss->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!bss->nl_cb)
		return -1;

	nl_cb_set(bss->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
		  no_seq_check, NULL);
	nl_cb_set(bss->nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
		  process_bss_event, bss);
	//wpa_printf(MSG_ERROR, "nl80211_init_bss success to init\n");
	return 0;
}

//真正的为bss和drv分配内存
static void * wpa_driver_nl80211_drv_init(void *ctx, const char *ifname,
					  void *global_priv, int hostapd,
					  const u8 *set_addr)
{
	struct wpa_driver_nl80211_data *drv;
	struct i802_bss *bss;

	if (global_priv == NULL)
		return NULL;
	//drv内存分配
	drv = (struct wpa_driver_nl80211_data *)os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;
	drv->global = (struct nl80211_global*)global_priv;
	drv->ctx = ctx;
	drv->hostapd = !!hostapd;
	drv->eapol_sock = -1;
	drv->num_if_indices = sizeof(drv->default_if_indices) / sizeof(int);
	drv->if_indices = drv->default_if_indices;
	//bss内存分配
	drv->first_bss = (struct i802_bss *)os_zalloc(sizeof(*drv->first_bss));
	if (!drv->first_bss) {
		os_free(drv);
		return NULL;
	}
	bss = drv->first_bss;
	bss->drv = drv;
	bss->ctx = ctx;

	os_strlcpy(bss->ifname, ifname, sizeof(bss->ifname));
	drv->monitor_ifidx = -1;
	drv->monitor_sock = -1;
	drv->eapol_tx_sock = -1;
	drv->ap_scan_as_station = NL80211_IFTYPE_UNSPECIFIED;


	if (wpa_driver_nl80211_init_nl(drv)) {
		os_free(drv);
		return NULL;
	}
	//wpa_printf(MSG_ERROR, "wpa_driver_nl80211_drv_init 11111 to init\n");
	if (nl80211_init_bss(bss))
		goto failed;

	/**开启接口
	 *Hostapd已经完成这里不需要做，可能有些参数需要填写,如有需要再写
	 * if (linux_iface_up(drv->global->ioctl_sock, ifname) > 0)
		drv->start_iface_up = 1;
	*/

	if (wpa_driver_nl80211_finish_drv_init(drv, set_addr, 1))
		goto failed;
	wpa_printf(MSG_ERROR, "wpa_driver_nl80211_drv_init 222 to init\n");
	if (drv->global) {
		//dl_list_add(&drv->global->interfaces, &drv->list);//这句出错了不需要
		//wpa_printf(MSG_ERROR, "wpa_driver_nl80211_drv_init 3333 to init\n");
		drv->in_interface_list = 1;
	}
	//wpa_printf(MSG_ERROR, "wpa_driver_nl80211_drv_init success to init\n");
	return bss;

failed:
	//wpa_driver_nl80211_deinit(bss);
    wpa_printf(MSG_ERROR, "wpa_driver_nl80211_drv_init Failed to init\n");
	os_free(drv);
	return NULL;
}


//初始化BSS和DRV结构体，这两个结构体保存一些信息共后面使用
static void *i802_init(struct hostapd_data *hapd,
		       struct wpa_init_params *params)
{
	//BSS初始化分配内存
	//Drv初始化分配内存
	//struct wpa_driver_nl80211_data *drv;
	struct i802_bss *bss;

	bss = (struct i802_bss *)wpa_driver_nl80211_drv_init(hapd, params->ifname,
					  params->global_priv, 1,
					  params->bssid);
	if (bss == NULL){
		fprintf(stderr, "hapd_init (BSS DRV初始化)失败 --nm\n");
		return NULL;
	}

	//drv = bss->drv;
	//TODO:填充drv信息

    memcpy(bss->addr, params->own_addr, ETH_ALEN);
	//fprintf(stderr, "hapd_init (BSS DRV初始化)执行成功执行完毕 --nm\n");
	return bss;
}
/*******************i802_init  函数实现end**********************/

/*******************wpa_driver_nl80211_sta_add  函数实现start**********************/

static int send_and_recv_msgs(struct wpa_driver_nl80211_data *drv,
			      struct nl_msg *msg,
			      int (*valid_handler)(struct nl_msg *, void *),
			      void *valid_data)
{
	return send_and_recv(drv->global, drv->global->nl, msg,
			     valid_handler, valid_data);
}


static int wpa_driver_nl80211_sta_add(void *priv,
				      struct hostapd_sta_add_params *params)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	struct nl80211_sta_flag_update upd;
	int ret = -ENOBUFS;

	//if ((params->flags & WPA_STA_TDLS_PEER) &&
	 //   !(drv->capa.flags & WPA_DRIVER_FLAGS_TDLS_SUPPORT))
	//	return -EOPNOTSUPP;
  // //生成要发送往内核的帧（还没有填充内容）
	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	wpa_printf(MSG_DEBUG, "nl80211: %s STA " MACSTR "\n",
		   params->set ? "Set" : "Add", MAC2STR(params->addr));
	//params->set的值来决定是增加一个sta_info还是设置一个sta_info
	//fprintf(stderr, "nl80211: add station:%02x:%02x:%02x:%02x:%02x:%02x\n",MAC2STR(params->addr));
	//设置或者增加sta_info
	nl80211_cmd(drv, msg, 0, params->set ? NL80211_CMD_SET_STATION :
		    NL80211_CMD_NEW_STATION);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(bss->ifname));
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr);
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, params->supp_rates_len,
		params->supp_rates);
	//wpa_hexdump(MSG_DEBUG, "  * supported rates", params->supp_rates,
	//	    params->supp_rates_len);
	if (!params->set) {
		//设置sta_info属性值
		if (params->aid) {
			//wpa_printf(MSG_DEBUG, "  * aid=%u", params->aid);
			NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, params->aid);
		} else {
			/*
			 * cfg80211 validates that AID is non-zero, so we have
			 * to make this a non-zero value for the TDLS case where
			 * a dummy STA entry is used for now.
			 */
			//wpa_printf(MSG_DEBUG, "  * aid=1 (TDLS workaround)");
			NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, 1);
		}
		//wpa_printf(MSG_DEBUG, "  * listen_interval=%u",
		//	   params->listen_interval);
		NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
			    params->listen_interval);
	} else if (params->aid && (params->flags & WPA_STA_TDLS_PEER)) {
		//增加新的sta_info
		//wpa_printf(MSG_DEBUG, "  * peer_aid=%u", params->aid);
		NLA_PUT_U16(msg, NL80211_ATTR_PEER_AID, params->aid);//关联的id号
	}
	//支持的HT速率集合
	if (params->ht_capabilities) {
		//wpa_hexdump(MSG_DEBUG, "  * ht_capabilities",
		//	    (u8 *) params->ht_capabilities,
		//	    sizeof(*params->ht_capabilities));
		NLA_PUT(msg, NL80211_ATTR_HT_CAPABILITY,
			sizeof(*params->ht_capabilities),
			params->ht_capabilities);
	}
   //支持的VHT速率集合
	if (params->vht_capabilities) {
		//wpa_hexdump(MSG_DEBUG, "  * vht_capabilities",
		//	    (u8 *) params->vht_capabilities,
		//	    sizeof(*params->vht_capabilities));
		NLA_PUT(msg, NL80211_ATTR_VHT_CAPABILITY,
			sizeof(*params->vht_capabilities),
			params->vht_capabilities);
	}

	if (params->vht_opmode_enabled) {
		//wpa_printf(MSG_DEBUG, "  * opmode=%u", params->vht_opmode);
		NLA_PUT_U8(msg, NL80211_ATTR_OPMODE_NOTIF,
			   params->vht_opmode);
	}

	//wpa_printf(MSG_DEBUG, "  * capability=0x%x", params->capability);
	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, params->capability);//标志参数

	if (params->ext_capab) {
		//wpa_hexdump(MSG_DEBUG, "  * ext_capab",
		//	    params->ext_capab, params->ext_capab_len);
		NLA_PUT(msg, NL80211_ATTR_STA_EXT_CAPABILITY,
			params->ext_capab_len, params->ext_capab);
	}

	if (params->supp_channels) {
		//wpa_hexdump(MSG_DEBUG, "  * supported channels",
		//	    params->supp_channels, params->supp_channels_len);
		NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_CHANNELS,
			params->supp_channels_len, params->supp_channels);
	}

	if (params->supp_oper_classes) {
		//wpa_hexdump(MSG_DEBUG, "  * supported operating classes",
		//	    params->supp_oper_classes,
		//	    params->supp_oper_classes_len);
		NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES,
			params->supp_oper_classes_len,
			params->supp_oper_classes);
	}

	os_memset(&upd, 0, sizeof(upd));
	upd.mask = sta_flags_nl80211(params->flags);
	upd.set = upd.mask;
	//wpa_printf(MSG_DEBUG, "  * flags set=0x%x mask=0x%x",
	//	   upd.set, upd.mask);
	NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd);

	if (params->flags & WPA_STA_WMM) {
		struct nlattr *wme = nla_nest_start(msg, NL80211_ATTR_STA_WME);

		if (!wme)
			goto nla_put_failure;

		//wpa_printf(MSG_DEBUG, "  * qosinfo=0x%x", params->qosinfo);
		NLA_PUT_U8(msg, NL80211_STA_WME_UAPSD_QUEUES,
				params->qosinfo & WMM_QOSINFO_STA_AC_MASK);
		NLA_PUT_U8(msg, NL80211_STA_WME_MAX_SP,
				(params->qosinfo >> WMM_QOSINFO_STA_SP_SHIFT) &
				WMM_QOSINFO_STA_SP_MASK);
		nla_nest_end(msg, wme);
	}

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	//fprintf(stderr, "sta_add 执行完毕\n");
	msg = NULL;
	if (ret)
		wpa_printf(MSG_DEBUG, "	nl80211: NL80211_CMD_%s_STATION "
		   "result: %d (%s)\n", params->set ? "SET" : "NEW", ret,
		   strerror(-ret));
	//if (ret)
	//	fprintf(stderr, "	nl80211:Station add,DEBUG result: code=%d,%s  --nm\n",(-ret),strerror(-ret));
		//wpa_printf(MSG_DEBUG, "nl80211: NL80211_CMD_%s_STATION "
		//	   "result: %d (%s)", params->set ? "SET" : "NEW", ret,
		//	   strerror(-ret));
	if (ret == -EEXIST)
		ret = 0;
 nla_put_failure:
	nlmsg_free(msg);
	return ret;


}

/*******************wpa_driver_nl80211_sta_add  函数实现end**********************/




/*******************wpa_driver_nl80211_get_capa  函数实现start**********************/

static int dfs_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
	int *dfs_capability_ptr = (int *)arg;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_VENDOR_DATA]) {
		struct nlattr *nl_vend = tb[NL80211_ATTR_VENDOR_DATA];
		struct nlattr *tb_vendor[QCA_WLAN_VENDOR_ATTR_MAX + 1];

		nla_parse(tb_vendor, QCA_WLAN_VENDOR_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_vend), nla_len(nl_vend), NULL);

		if (tb_vendor[QCA_WLAN_VENDOR_ATTR_DFS]) {
			u32 val;
			val = nla_get_u32(tb_vendor[QCA_WLAN_VENDOR_ATTR_DFS]);
			wpa_printf(MSG_DEBUG, "nl80211: DFS offload capability: %u",
				   val);
			*dfs_capability_ptr = val;
		}
	}

	return NL_SKIP;
}

static int wpa_driver_nl80211_get_capa(void *priv,
				       struct wpa_driver_capa *capa)
{
	struct i802_bss *bss = (struct i802_bss*)priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int dfs_capability = 0;
	int ret = 0;

	if (!drv->has_capability)
		return -1;
	os_memcpy(capa, &drv->capa, sizeof(*capa));
	if (drv->extended_capa && drv->extended_capa_mask) {
		capa->extended_capa = drv->extended_capa;
		capa->extended_capa_mask = drv->extended_capa_mask;
		capa->extended_capa_len = drv->extended_capa_len;
	}

	if ((capa->flags & WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE) &&
	    !drv->allow_p2p_device) {
		wpa_printf(MSG_DEBUG, "nl80211: Do not indicate P2P_DEVICE support (p2p_device=1 driver param not specified)");
		capa->flags &= ~WPA_DRIVER_FLAGS_DEDICATED_P2P_DEVICE;
	}

	if (drv->dfs_vendor_cmd_avail == 1) {
		msg = nlmsg_alloc();
		if (!msg)
			return -ENOMEM;

		nl80211_cmd(drv, msg, 0, NL80211_CMD_VENDOR);

		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
		NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA);
		NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
			    QCA_NL80211_VENDOR_SUBCMD_DFS_CAPABILITY);

		ret = send_and_recv_msgs(drv, msg, dfs_info_handler,
					 &dfs_capability);
		if (!ret) {
			if (dfs_capability)
				capa->flags |= WPA_DRIVER_FLAGS_DFS_OFFLOAD;
		}
	}

	return ret;

 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/*******************wpa_driver_nl80211_get_capa  函数实现end**********************/


/*******************driver_nl80211_sta_remove  函数实现start**********************/
static int wpa_driver_nl80211_sta_remove(struct i802_bss *bss, const u8 *addr)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_DEL_STATION);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX,
		    if_nametoindex(bss->ifname));
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	//wpa_printf(MSG_DEBUG, "nl80211: sta_remove -> DEL_STATION %s " MACSTR
	//	   " --> %d (%s)",
	//	   bss->ifname, MAC2STR(addr), ret, strerror(-ret));
	if (ret == -ENOENT)
		return 0;
	return ret;
 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int driver_nl80211_sta_remove(void *priv, const u8 *addr)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	return wpa_driver_nl80211_sta_remove(bss, addr);
}
/*******************driver_nl80211_sta_remove  函数实现end**********************/


/*******************wpa_driver_nl80211_sta_set_flags  函数实现start**********************/
static int wpa_driver_nl80211_sta_set_flags(void *priv, const u8 *addr,
					    int total_flags,
					    int flags_or, int flags_and)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	struct nlattr *flags;
	struct nl80211_sta_flag_update upd;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_SET_STATION);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX,
		    if_nametoindex(bss->ifname));
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, addr);

	/*
	 * Backwards compatibility version using NL80211_ATTR_STA_FLAGS. This
	 * can be removed eventually.
	 */
	flags = nla_nest_start(msg, NL80211_ATTR_STA_FLAGS);
	if (!flags)
		goto nla_put_failure;
	if (total_flags & WPA_STA_AUTHORIZED)
		NLA_PUT_FLAG(msg, NL80211_STA_FLAG_AUTHORIZED);

	if (total_flags & WPA_STA_WMM)
		NLA_PUT_FLAG(msg, NL80211_STA_FLAG_WME);

	if (total_flags & WPA_STA_SHORT_PREAMBLE)
		NLA_PUT_FLAG(msg, NL80211_STA_FLAG_SHORT_PREAMBLE);

	if (total_flags & WPA_STA_MFP)
		NLA_PUT_FLAG(msg, NL80211_STA_FLAG_MFP);

	if (total_flags & WPA_STA_TDLS_PEER)
		NLA_PUT_FLAG(msg, NL80211_STA_FLAG_TDLS_PEER);

	nla_nest_end(msg, flags);

	os_memset(&upd, 0, sizeof(upd));
	upd.mask = sta_flags_nl80211(flags_or | ~flags_and);
	upd.set = sta_flags_nl80211(flags_or);
	NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd);

	return send_and_recv_msgs(drv, msg, NULL, NULL);
 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/*******************wpa_driver_nl80211_sta_set_flags  函数实现start**********************/


/*******************wpa_driver_nl80211_get_hw_feature_data  函数实现start**********************/


static int protocol_feature_handler(struct nl_msg *msg, void *arg)
{
	u32 *feat = (u32 *)arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES])
		*feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);

	return NL_SKIP;
}

static u32 get_nl80211_protocol_features(struct wpa_driver_nl80211_data *drv)
{
	u32 feat = 0;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		goto nla_put_failure;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_GET_PROTOCOL_FEATURES);
	if (send_and_recv_msgs(drv, msg, protocol_feature_handler, &feat) == 0)
		return feat;

	msg = NULL;
nla_put_failure:
	nlmsg_free(msg);
	return 0;
}

static void phy_info_ht_capa(struct hostapd_hw_modes *mode, struct nlattr *capa,
			     struct nlattr *ampdu_factor,
			     struct nlattr *ampdu_density,
			     struct nlattr *mcs_set)
{
	if (capa)
		mode->ht_capab = nla_get_u16(capa);
	//fprintf(stderr,"phy_info_ht_capa 11111111111111111111 11111 ht_capab =%04x,%04x\n",\
		mode->ht_capab,host_to_le16(mode->ht_capab));
	if (ampdu_factor)
		mode->a_mpdu_params |= nla_get_u8(ampdu_factor) & 0x03;

	if (ampdu_density)
		mode->a_mpdu_params |= nla_get_u8(ampdu_density) << 2;

	if (mcs_set && nla_len(mcs_set) >= 16) {
		u8 *mcs;
		mcs = (u8 *)nla_data(mcs_set);
		os_memcpy(mode->mcs_set, mcs, 16);
	}
}

static enum hostapd_hw_mode ieee80211_freq_to_chan(int freq, u8 *channel)
{
	enum hostapd_hw_mode mode = NUM_HOSTAPD_MODES;

	if (freq >= 2412 && freq <= 2472) {
		mode = HOSTAPD_MODE_IEEE80211G;
		*channel = (freq - 2407) / 5;
	} else if (freq == 2484) {
		mode = HOSTAPD_MODE_IEEE80211B;
		*channel = 14;
	} else if (freq >= 4900 && freq < 5000) {
		mode = HOSTAPD_MODE_IEEE80211A;
		*channel = (freq - 4000) / 5;
	} else if (freq >= 5000 && freq < 5900) {
		mode = HOSTAPD_MODE_IEEE80211A;
		*channel = (freq - 5000) / 5;
	} else if (freq >= 56160 + 2160 * 1 && freq <= 56160 + 2160 * 4) {
		mode = HOSTAPD_MODE_IEEE80211AD;
		*channel = (freq - 56160) / 2160;
	}

	return mode;
}

static void phy_info_freq(struct hostapd_hw_modes *mode,
			  struct hostapd_channel_data *chan,
			  struct nlattr *tb_freq[])
{
	u8 channel;
	chan->freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
	chan->flag = 0;
	chan->dfs_cac_ms = 0;
	if (ieee80211_freq_to_chan(chan->freq, &channel) != NUM_HOSTAPD_MODES)
		chan->chan = channel;

	if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
		chan->flag |= HOSTAPD_CHAN_DISABLED;
	if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR])
		chan->flag |= HOSTAPD_CHAN_PASSIVE_SCAN | HOSTAPD_CHAN_NO_IBSS;
	if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
		chan->flag |= HOSTAPD_CHAN_RADAR;

	if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]) {
		enum nl80211_dfs_state state =
			(enum nl80211_dfs_state)nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_DFS_STATE]);

		switch (state) {
		case NL80211_DFS_USABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_USABLE;
			break;
		case NL80211_DFS_AVAILABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_AVAILABLE;
			break;
		case NL80211_DFS_UNAVAILABLE:
			chan->flag |= HOSTAPD_CHAN_DFS_UNAVAILABLE;
			break;
		}
	}

	if (tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]) {
		chan->dfs_cac_ms = nla_get_u32(
			tb_freq[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME]);
	}
}

static int phy_info_freqs(struct phy_info_arg *phy_info,
			  struct hostapd_hw_modes *mode, struct nlattr *tb)
{
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ}/*should be invaild--nm*/,
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_FLAG,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_FLAG,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_FLAG,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ },
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ },
	};
	int new_channels = 0;
	struct hostapd_channel_data *channel;
	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	struct nlattr *nl_freq;
	int rem_freq, idx;

	if (tb == NULL)
		return NL_OK;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_freq), nla_len(nl_freq), freq_policy);
		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;
		new_channels++;
	}

	channel = (struct hostapd_channel_data*)os_realloc_array(mode->channels,
				   mode->num_channels + new_channels,
				   sizeof(struct hostapd_channel_data));
	if (!channel)
		return NL_SKIP;

	mode->channels = channel;
	mode->num_channels += new_channels;

	idx = phy_info->last_chan_idx;

	nla_for_each_nested(nl_freq, tb, rem_freq) {
		nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_freq), nla_len(nl_freq), freq_policy);
		if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
			continue;
		phy_info_freq(mode, &mode->channels[idx], tb_freq);
		idx++;
	}
	phy_info->last_chan_idx = idx;

	return NL_OK;
}


static void phy_info_vht_capa(struct hostapd_hw_modes *mode,
			      struct nlattr *capa,
			      struct nlattr *mcs_set)
{
	if (capa)
		mode->vht_capab = nla_get_u32(capa);

	if (mcs_set && nla_len(mcs_set) >= 8) {
		u8 *mcs;
		mcs = (u8 *)nla_data(mcs_set);
		os_memcpy(mode->vht_mcs_set, mcs, 8);
	}
}

static int phy_info_rates(struct hostapd_hw_modes *mode, struct nlattr *tb)
{/*
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] =
		{ .type = NLA_FLAG },
	};
	{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ},
	*/
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_U32,NLA_HDRLEN,GENL_NAMSIZ},
		{ NLA_FLAG,NLA_HDRLEN,GENL_NAMSIZ}
	};
	struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
	struct nlattr *nl_rate;
	int rem_rate, idx;

	if (tb == NULL)
		return NL_OK;

	nla_for_each_nested(nl_rate, tb, rem_rate) {
		nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_rate), nla_len(nl_rate),
			  rate_policy);
		if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
			continue;
		mode->num_rates++;
	}

	mode->rates = (int *)os_calloc(mode->num_rates, sizeof(int));
	if (!mode->rates)
		return NL_SKIP;

	idx = 0;

	nla_for_each_nested(nl_rate, tb, rem_rate) {
		nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_rate), nla_len(nl_rate),
			  rate_policy);
		if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
			continue;
		mode->rates[idx] = nla_get_u32(
			tb_rate[NL80211_BITRATE_ATTR_RATE]);
		idx++;
	}

	return NL_OK;
}

static int phy_info_band(struct phy_info_arg *phy_info, struct nlattr *nl_band)
{
	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
	struct hostapd_hw_modes *mode;
	int ret;

	if (phy_info->last_mode != nl_band->nla_type) {
		mode = (struct hostapd_hw_modes*)os_realloc_array(phy_info->modes,
					*phy_info->num_modes + 1,
					sizeof(*mode));
		if (!mode)
			return NL_SKIP;
		phy_info->modes = mode;

		mode = &phy_info->modes[*(phy_info->num_modes)];
		os_memset(mode, 0, sizeof(*mode));
		mode->mode = NUM_HOSTAPD_MODES;
		mode->flags = HOSTAPD_MODE_FLAG_HT_INFO_KNOWN |
			HOSTAPD_MODE_FLAG_VHT_INFO_KNOWN;

		/*
		 * Unsupported VHT MCS stream is defined as value 3, so the VHT
		 * MCS RX/TX map must be initialized with 0xffff to mark all 8
		 * possible streams as unsupported. This will be overridden if
		 * driver advertises VHT support.
		 */
		mode->vht_mcs_set[0] = 0xff;
		mode->vht_mcs_set[1] = 0xff;
		mode->vht_mcs_set[4] = 0xff;
		mode->vht_mcs_set[5] = 0xff;

		*(phy_info->num_modes) += 1;
		phy_info->last_mode = nl_band->nla_type;
		phy_info->last_chan_idx = 0;
	} else
		mode = &phy_info->modes[*(phy_info->num_modes) - 1];

	nla_parse(tb_band, NL80211_BAND_ATTR_MAX, (struct nlattr*)nla_data(nl_band),
		  nla_len(nl_band), NULL);

	phy_info_ht_capa(mode, tb_band[NL80211_BAND_ATTR_HT_CAPA],
			 tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR],
			 tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY],
			 tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
	phy_info_vht_capa(mode, tb_band[NL80211_BAND_ATTR_VHT_CAPA],
			  tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
	ret = phy_info_freqs(phy_info, mode, tb_band[NL80211_BAND_ATTR_FREQS]);
	if (ret != NL_OK)
		return ret;
	ret = phy_info_rates(mode, tb_band[NL80211_BAND_ATTR_RATES]);
	if (ret != NL_OK)
		return ret;

	return NL_OK;
}

static int phy_info_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct phy_info_arg *phy_info = (struct phy_info_arg *)arg;
	struct nlattr *nl_band;
	int rem_band;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
		return NL_SKIP;

	nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band)
	{
		int res = phy_info_band(phy_info, nl_band);
		if (res != NL_OK)
			return res;
	}

	return NL_SKIP;

}


static void nl80211_reg_rule_max_eirp(u32 start, u32 end, u32 max_eirp,
				      struct phy_info_arg *results)
{
	u16 m;

	for (m = 0; m < *results->num_modes; m++) {
		int c;
		struct hostapd_hw_modes *mode = &results->modes[m];

		for (c = 0; c < mode->num_channels; c++) {
			struct hostapd_channel_data *chan = &mode->channels[c];
			if ((u32) chan->freq - 10 >= start &&
			    (u32) chan->freq + 10 <= end)
				chan->max_tx_power = max_eirp;
		}
	}
}

static void nl80211_set_ht40_mode(struct hostapd_hw_modes *mode, int start,
				  int end)
{
	int c;

	for (c = 0; c < mode->num_channels; c++) {
		struct hostapd_channel_data *chan = &mode->channels[c];
		if (chan->freq - 10 >= start && chan->freq + 10 <= end)
			chan->flag |= HOSTAPD_CHAN_HT40;
	}
}
static void nl80211_reg_rule_ht40(u32 start, u32 end,
				  struct phy_info_arg *results)
{
	u16 m;

	for (m = 0; m < *results->num_modes; m++) {
		if (!(results->modes[m].ht_capab &
		      HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET))
			continue;
		nl80211_set_ht40_mode(&results->modes[m], start, end);
	}
}


static void nl80211_set_ht40_mode_sec(struct hostapd_hw_modes *mode, int start,
				      int end)
{
	int c;

	for (c = 0; c < mode->num_channels; c++) {
		struct hostapd_channel_data *chan = &mode->channels[c];
		if (!(chan->flag & HOSTAPD_CHAN_HT40))
			continue;
		if (chan->freq - 30 >= start && chan->freq - 10 <= end)
			chan->flag |= HOSTAPD_CHAN_HT40MINUS;
		if (chan->freq + 10 >= start && chan->freq + 30 <= end)
			chan->flag |= HOSTAPD_CHAN_HT40PLUS;
	}
}

static void nl80211_reg_rule_sec(struct nlattr *tb[],
				 struct phy_info_arg *results)
{
	u32 start, end, max_bw;
	u16 m;

	if (tb[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
	    tb[NL80211_ATTR_FREQ_RANGE_END] == NULL ||
	    tb[NL80211_ATTR_FREQ_RANGE_MAX_BW] == NULL)
		return;

	start = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
	end = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
	max_bw = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;

	if (max_bw < 20)
		return;

	for (m = 0; m < *results->num_modes; m++) {
		if (!(results->modes[m].ht_capab &
		      HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET))
			continue;
		nl80211_set_ht40_mode_sec(&results->modes[m], start, end);
	}
}



static void nl80211_set_vht_mode(struct hostapd_hw_modes *mode, int start,
				 int end)
{
	int c;

	for (c = 0; c < mode->num_channels; c++) {
		struct hostapd_channel_data *chan = &mode->channels[c];
		if (chan->freq - 10 >= start && chan->freq + 70 <= end)
			chan->flag |= HOSTAPD_CHAN_VHT_10_70;

		if (chan->freq - 30 >= start && chan->freq + 50 <= end)
			chan->flag |= HOSTAPD_CHAN_VHT_30_50;

		if (chan->freq - 50 >= start && chan->freq + 30 <= end)
			chan->flag |= HOSTAPD_CHAN_VHT_50_30;

		if (chan->freq - 70 >= start && chan->freq + 10 <= end)
			chan->flag |= HOSTAPD_CHAN_VHT_70_10;
	}
}

static void nl80211_reg_rule_vht(struct nlattr *tb[],
				 struct phy_info_arg *results)
{
	u32 start, end, max_bw;
	u16 m;

	if (tb[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
	    tb[NL80211_ATTR_FREQ_RANGE_END] == NULL ||
	    tb[NL80211_ATTR_FREQ_RANGE_MAX_BW] == NULL)
		return;

	start = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
	end = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
	max_bw = nla_get_u32(tb[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;

	if (max_bw < 80)
		return;

	for (m = 0; m < *results->num_modes; m++) {
		if (!(results->modes[m].ht_capab &
		      HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET))
			continue;
		/* TODO: use a real VHT support indication */
		if (!results->modes[m].vht_capab)
			continue;

		nl80211_set_vht_mode(&results->modes[m], start, end);
	}
}
static const char * dfs_domain_name(enum nl80211_dfs_regions region)
{
	switch (region) {
	case NL80211_DFS_UNSET:
		return "DFS-UNSET";
	case NL80211_DFS_FCC:
		return "DFS-FCC";
	case NL80211_DFS_ETSI:
		return "DFS-ETSI";
	case NL80211_DFS_JP:
		return "DFS-JP";
	default:
		return "DFS-invalid";
	}
}
//参数调试
static int nl80211_get_reg(struct nl_msg *msg, void *arg)
{
	struct phy_info_arg *results = (struct phy_info_arg *)arg;
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *nl_rule;
	struct nlattr *tb_rule[NL80211_FREQUENCY_ATTR_MAX + 1];
	int rem_rule;
	/*
	static struct nla_policy reg_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_ATTR_REG_RULE_FLAGS] = { .type = NLA_U32 },
		[NL80211_ATTR_FREQ_RANGE_START] = { .type = NLA_U32 },
		[NL80211_ATTR_FREQ_RANGE_END] = { .type = NLA_U32 },
		[NL80211_ATTR_FREQ_RANGE_MAX_BW] = { .type = NLA_U32 },
		[NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN] = { .type = NLA_U32 },
		[NL80211_ATTR_POWER_RULE_MAX_EIRP] = { .type = NLA_U32 },
	}; */
	static struct nla_policy reg_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
		{ .type = NLA_U32 },
	};
	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb_msg[NL80211_ATTR_REG_ALPHA2] ||
	    !tb_msg[NL80211_ATTR_REG_RULES]) {
		//wpa_printf(MSG_DEBUG, "nl80211: No regulatory information "
		//	   "available");
		return NL_SKIP;
	}

	if (tb_msg[NL80211_ATTR_DFS_REGION]) {
		enum nl80211_dfs_regions dfs_domain;
		dfs_domain = (enum nl80211_dfs_regions)nla_get_u8(tb_msg[NL80211_ATTR_DFS_REGION]);
		//DEBUG
		//wpa_printf(MSG_DEBUG, "nl80211: Regulatory information - country=%s (%s)",
		//	   (char *) nla_data(tb_msg[NL80211_ATTR_REG_ALPHA2]),
			   //dfs_domain_name(dfs_domain));
	} else {
		;
		//DEBUG
		//wpa_printf(MSG_DEBUG, "nl80211: Regulatory information - country=%s",
			  // (char *) nla_data(tb_msg[NL80211_ATTR_REG_ALPHA2]));
	}

	nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
	{
		u32 start, end, max_eirp = 0, max_bw = 0, flags = 0;
		nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_rule), nla_len(nl_rule), reg_policy);
		if (tb_rule[NL80211_ATTR_FREQ_RANGE_START] == NULL ||
		    tb_rule[NL80211_ATTR_FREQ_RANGE_END] == NULL)
			continue;
		start = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_START]) / 1000;
		end = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_END]) / 1000;
		if (tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP])
			max_eirp = nla_get_u32(tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP]) / 100;
		if (tb_rule[NL80211_ATTR_FREQ_RANGE_MAX_BW])
			max_bw = nla_get_u32(tb_rule[NL80211_ATTR_FREQ_RANGE_MAX_BW]) / 1000;
		if (tb_rule[NL80211_ATTR_REG_RULE_FLAGS])
			flags = nla_get_u32(tb_rule[NL80211_ATTR_REG_RULE_FLAGS]);

		/*wpa_printf(MSG_DEBUG, "nl80211: %u-%u @ %u MHz %u mBm%s%s%s%s%s%s%s%s",
			   start, end, max_bw, max_eirp,
			   flags & NL80211_RRF_NO_OFDM ? " (no OFDM)" : "",
			   flags & NL80211_RRF_NO_CCK ? " (no CCK)" : "",
			   flags & NL80211_RRF_NO_INDOOR ? " (no indoor)" : "",
			   flags & NL80211_RRF_NO_OUTDOOR ? " (no outdoor)" :
			   "",
			   flags & NL80211_RRF_DFS ? " (DFS)" : "",
			   flags & NL80211_RRF_PTP_ONLY ? " (PTP only)" : "",
			   flags & NL80211_RRF_PTMP_ONLY ? " (PTMP only)" : "",
			   flags & NL80211_RRF_NO_IR ? " (no IR)" : "");
			   */
		if (max_bw >= 40)
			nl80211_reg_rule_ht40(start, end, results);
		if (tb_rule[NL80211_ATTR_POWER_RULE_MAX_EIRP])
			nl80211_reg_rule_max_eirp(start, end, max_eirp,
						  results);
	}

	nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
	{
		nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_rule), nla_len(nl_rule), reg_policy);
		nl80211_reg_rule_sec(tb_rule, results);
	}

	nla_for_each_nested(nl_rule, tb_msg[NL80211_ATTR_REG_RULES], rem_rule)
	{
		nla_parse(tb_rule, NL80211_FREQUENCY_ATTR_MAX,
			  (struct nlattr*)nla_data(nl_rule), nla_len(nl_rule), reg_policy);
		nl80211_reg_rule_vht(tb_rule, results);
	}

	return NL_SKIP;
}

static int nl80211_set_regulatory_flags(struct wpa_driver_nl80211_data *drv,
					struct phy_info_arg *results)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	nl80211_cmd(drv, msg, 0, NL80211_CMD_GET_REG);
	return send_and_recv_msgs(drv, msg, nl80211_get_reg, results);
}




static struct hostapd_hw_modes *
wpa_driver_nl80211_postprocess_modes(struct hostapd_hw_modes *modes,
				     u16 *num_modes)
{
	u16 m;
	struct hostapd_hw_modes *mode11g = NULL, *nmodes, *mode;
	int i, mode11g_idx = -1;

	/* heuristic to set up modes */
	for (m = 0; m < *num_modes; m++) {
		if (!modes[m].num_channels)
			continue;
		if (modes[m].channels[0].freq < 4000) {
			modes[m].mode = HOSTAPD_MODE_IEEE80211B;
			for (i = 0; i < modes[m].num_rates; i++) {
				if (modes[m].rates[i] > 200) {
					modes[m].mode = HOSTAPD_MODE_IEEE80211G;
					break;
				}
			}
		} else if (modes[m].channels[0].freq > 50000)
			modes[m].mode = HOSTAPD_MODE_IEEE80211AD;
		else
			modes[m].mode = HOSTAPD_MODE_IEEE80211A;
	}

	/* If only 802.11g mode is included, use it to construct matching
	 * 802.11b mode data. */

	for (m = 0; m < *num_modes; m++) {
		if (modes[m].mode == HOSTAPD_MODE_IEEE80211B)
			return modes; /* 802.11b already included */
		if (modes[m].mode == HOSTAPD_MODE_IEEE80211G)
			mode11g_idx = m;
	}

	if (mode11g_idx < 0)
		return modes; /* 2.4 GHz band not supported at all */

	nmodes = (struct hostapd_hw_modes *)os_realloc_array(modes, *num_modes + 1, sizeof(*nmodes));
	if (nmodes == NULL)
		return modes; /* Could not add 802.11b mode */

	mode = &nmodes[*num_modes];
	os_memset(mode, 0, sizeof(*mode));
	(*num_modes)++;
	modes = nmodes;

	mode->mode = HOSTAPD_MODE_IEEE80211B;

	mode11g = &modes[mode11g_idx];
	mode->num_channels = mode11g->num_channels;
	mode->channels = (struct hostapd_channel_data*)os_malloc(mode11g->num_channels *
				   sizeof(struct hostapd_channel_data));
	if (mode->channels == NULL) {
		(*num_modes)--;
		return modes; /* Could not add 802.11b mode */
	}
	os_memcpy(mode->channels, mode11g->channels,
		  mode11g->num_channels * sizeof(struct hostapd_channel_data));

	mode->num_rates = 0;
	mode->rates = (int *)os_malloc(4 * sizeof(int));
	if (mode->rates == NULL) {
		os_free(mode->channels);
		(*num_modes)--;
		return modes; /* Could not add 802.11b mode */
	}

	for (i = 0; i < mode11g->num_rates; i++) {
		if (mode11g->rates[i] != 10 && mode11g->rates[i] != 20 &&
		    mode11g->rates[i] != 55 && mode11g->rates[i] != 110)
			continue;
		mode->rates[mode->num_rates] = mode11g->rates[i];
		mode->num_rates++;
		if (mode->num_rates == 4)
			break;
	}

	if (mode->num_rates == 0) {
		os_free(mode->channels);
		os_free(mode->rates);
		(*num_modes)--;
		return modes; /* No 802.11b rates */
	}

	wpa_printf(MSG_DEBUG, "nl80211: Added 802.11b mode based on 802.11g "
		   "information");

	return modes;
}

static struct hostapd_hw_modes *
wpa_driver_nl80211_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags)
{

	u32 feat;
	struct i802_bss *bss = (struct i802_bss *)priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	struct phy_info_arg result = {
		.num_modes = num_modes,
		.modes = NULL,
		.last_mode = -1,
	};

	*num_modes = 0;
	*flags = 0;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	feat = get_nl80211_protocol_features(drv);
	if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
		nl80211_cmd(drv, msg, NLM_F_DUMP, NL80211_CMD_GET_WIPHY);
	else
		nl80211_cmd(drv, msg, 0, NL80211_CMD_GET_WIPHY);

	NLA_PUT_FLAG(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
	if (nl80211_set_iface_id(msg, bss) < 0)
		goto nla_put_failure;

	if (send_and_recv_msgs(drv, msg, phy_info_handler, &result) == 0) {
		nl80211_set_regulatory_flags(drv, &result);
		return wpa_driver_nl80211_postprocess_modes(result.modes,
							    num_modes);
	}
	msg = NULL;
 nla_put_failure:
	nlmsg_free(msg);

	return NULL;
}

/**wpa_driver_nl80211_get_hw_feature_data  函数实现end**/





/*******************nl80211_get_radio_name  函数实现start**********************/
static const char * nl80211_get_radio_name(void *priv)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	return drv->phyname;
}
/*******************nl80211_get_radio_name  函数实现end**********************/




/**i802_set_freq  函数实现start**/
static int nl80211_put_freq_params(struct nl_msg *msg,
				   struct hostapd_freq_params *freq)
{
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq->freq);
	if (freq->vht_enabled) {
		switch (freq->bandwidth) {
		case 20:
			NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH,
				    NL80211_CHAN_WIDTH_20);
			break;
		case 40:
			NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH,
				    NL80211_CHAN_WIDTH_40);
			break;
		case 80:
			if (freq->center_freq2)
				NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH,
					    NL80211_CHAN_WIDTH_80P80);
			else
				NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH,
					    NL80211_CHAN_WIDTH_80);
			break;
		case 160:
			NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH,
				    NL80211_CHAN_WIDTH_160);
			break;
		default:
			return -EINVAL;
		}
		NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, freq->center_freq1);
		if (freq->center_freq2)
			NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ2,
				    freq->center_freq2);
	} else if (freq->ht_enabled) {
		switch (freq->sec_channel_offset) {
		case -1:
			NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE,
				    NL80211_CHAN_HT40MINUS);
			break;
		case 1:
			NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE,
				    NL80211_CHAN_HT40PLUS);
			break;
		default:
			NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE,
				    NL80211_CHAN_HT20);
			break;
		}
	}
	return 0;

nla_put_failure:
	return -ENOBUFS;
}

static int nl80211_set_channel(struct i802_bss *bss,
			       struct hostapd_freq_params *freq, int set_chan)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret;

	//wpa_printf(MSG_DEBUG,
	//	   "nl80211: Set freq %d (ht_enabled=%d, vht_enabled=%d, bandwidth=%d MHz, cf1=%d MHz, cf2=%d MHz)",
	//	   freq->freq, freq->ht_enabled, freq->vht_enabled,
	//	   freq->bandwidth, freq->center_freq1, freq->center_freq2);
	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	nl80211_cmd(drv, msg, 0, set_chan ? NL80211_CMD_SET_CHANNEL :
		    NL80211_CMD_SET_WIPHY);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, bss->ifindex);
	if (nl80211_put_freq_params(msg, freq) < 0)
		goto nla_put_failure;

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	msg = NULL;
	if (ret == 0) {
		bss->freq = freq->freq;
		return 0;
	}
	wpa_printf(MSG_DEBUG, "nl80211: Failed to set channel (freq=%d): "
		   "%d (%s)", freq->freq, ret, strerror(-ret));
nla_put_failure:
	nlmsg_free(msg);
	return -1;
}

/* Set kernel driver on given frequency (MHz) */
static int i802_set_freq(void *priv, struct hostapd_freq_params *freq)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	return nl80211_set_channel(bss, freq, 0);
}

/**i802_set_freq  函数实现end**/


/**send_mlme  函数实现start**/

static int cookie_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
	u64 *cookie = (u64 *)arg;
	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (tb[NL80211_ATTR_COOKIE])
		*cookie = nla_get_u64(tb[NL80211_ATTR_COOKIE]);
	return NL_SKIP;
}

static int nl80211_send_frame_cmd(struct i802_bss *bss,
				  unsigned int freq, unsigned int wait,
				  const u8 *buf, size_t buf_len,
				  u64 *cookie_out, int no_cck, int no_ack,
				  int offchanok)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	u64 cookie;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	//wpa_printf(MSG_MSGDUMP, "nl80211: CMD_FRAME freq=%u wait=%u no_cck=%d "
	//	   "no_ack=%d offchanok=%d",
	//	   freq, wait, no_cck, no_ack, offchanok);
	//wpa_hexdump(MSG_MSGDUMP, "CMD_FRAME", buf, buf_len);
	nl80211_cmd(drv, msg, 0, NL80211_CMD_FRAME);

	if (nl80211_set_iface_id(msg, bss) < 0)
		goto nla_put_failure;
	if (freq)
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	if (wait)
		NLA_PUT_U32(msg, NL80211_ATTR_DURATION, wait);
	if (offchanok && ((drv->capa.flags & WPA_DRIVER_FLAGS_OFFCHANNEL_TX) ||
			  drv->test_use_roc_tx))
		NLA_PUT_FLAG(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
	if (no_cck)
		NLA_PUT_FLAG(msg, NL80211_ATTR_TX_NO_CCK_RATE);
	if (no_ack)
		NLA_PUT_FLAG(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK);

	NLA_PUT(msg, NL80211_ATTR_FRAME, buf_len, buf);

	cookie = 0;
	ret = send_and_recv_msgs(drv, msg, cookie_handler, &cookie);
	msg = NULL;
	if (ret) {
		wpa_printf(MSG_DEBUG, "nl80211: Frame command failed: ret=%d "
			   "(%s) (freq=%u wait=%u)", ret, strerror(-ret),
			   freq, wait);
		goto nla_put_failure;
	}
	/*
     * wpa_printf(MSG_DEBUG, "nl80211: Frame TX command accepted%s; "
		   "cookie 0x%llx", no_ack ? " (no ACK)" : "",
		   (long long unsigned int) cookie);
    */
	if (cookie_out)
		*cookie_out = no_ack ? (u64) -1 : cookie;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int wpa_driver_nl80211_send_frame(struct i802_bss *bss,
					 const u8 *data, size_t len,
					 int encrypt, int noack,
					 unsigned int freq, int no_cck,
					 int offchanok, unsigned int wait_time)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	u64 cookie;
	int res;

	//模式 判断  我们系统是邋AP模式
	if (freq == 0 && drv->nlmode == NL80211_IFTYPE_ADHOC) {
		//freq = nl80211_get_assoc_freq(drv);///TODO
		//wpa_printf(MSG_DEBUG,
		//	   "nl80211: send_frame - Use assoc_freq=%u for IBSS",
		//	   freq);
	}
	if (freq == 0) {
		//wpa_printf(MSG_DEBUG, "nl80211: send_frame - Use bss->freq=%u",
		//	   bss->freq);
		freq = bss->freq;
	}

	//是否通过监听接口发送
	if (drv->use_monitor) {
		//wpa_printf(MSG_DEBUG, "nl80211: send_frame(freq=%u bss->freq=%u) -> send_mntr",
		//	   freq, bss->freq);
		//return wpa_driver_nl80211_send_mntr(drv, data, len,
		//				    encrypt, noack);
	}

	//wpa_printf(MSG_DEBUG, "nl80211: send_frame -> send_frame_cmd");
	res = nl80211_send_frame_cmd(bss, freq, wait_time, data, len,
				     &cookie, no_cck, noack, offchanok);
	if (res == 0 && !noack) {
		const struct ieee80211_mgmt *mgmt;
		u16 fc;

		mgmt = (const struct ieee80211_mgmt *) data;
		fc = le_to_host16(mgmt->frame_control);
		if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
		    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_ACTION) {
			//wpa_printf(MSG_MSGDUMP,
			//	   "nl80211: Update send_action_cookie from 0x%llx to 0x%llx",
			//	   (long long unsigned int)
			//	   drv->send_action_cookie,
			//	   (long long unsigned int) cookie);
			drv->send_action_cookie = cookie;
		}
	}

	return res;
}


static int wpa_driver_nl80211_send_mlme(struct i802_bss *bss, const u8 *data,
					size_t data_len, int noack,
					unsigned int freq, int no_cck,
					int offchanok,
					unsigned int wait_time)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct ieee80211_mgmt *mgmt;
	int encrypt = 1;
	u16 fc;

	mgmt = (struct ieee80211_mgmt *) data;
	fc = le_to_host16(mgmt->frame_control);

	//判断接口的模式为AP 还是client 模式，这段可以去掉
	if ((is_sta_interface(drv->nlmode) ||
	     drv->nlmode == NL80211_IFTYPE_P2P_DEVICE) &&
	    WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
	    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_RESP) {
		/*
		 * The use of last_mgmt_freq is a bit of a hack,
		 * but it works due to the single-threaded nature
		 * of wpa_supplicant.
		 */
		if (freq == 0) {
			wpa_printf(MSG_DEBUG, "nl80211: Use last_mgmt_freq=%d",
				   drv->last_mgmt_freq);
			freq = drv->last_mgmt_freq;
		}
		return nl80211_send_frame_cmd(bss, freq, 0,
					      data, data_len, NULL, 1, noack,
					      1);
	}

	//AP 模式
	if (drv->device_ap_sme && is_ap_interface(drv->nlmode)) {
		//频率设置
		if (freq == 0) {
			//wpa_printf(MSG_DEBUG, "nl80211: Use bss->freq=%d",
			//	   bss->freq);
			freq = bss->freq;
		}

		//发送出去了
		return nl80211_send_frame_cmd(bss, freq,
					      (int) freq == bss->freq ? 0 :
					      wait_time,
					      data, data_len,
					      &drv->send_action_cookie,
					      no_cck, noack, offchanok);
	}

	//如果是认证帧 需要单独设置 标志位
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
	    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_AUTH) {
		/*
		 * Only one of the authentication frame types is encrypted.
		 * In order for static WEP encryption to work properly (i.e.,
		 * to not encrypt the frame), we need to tell mac80211 about
		 * the frames that must not be encrypted.
		 */
		u16 auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
		u16 auth_trans = le_to_host16(mgmt->u.auth.auth_transaction);
		if (auth_alg != WLAN_AUTH_SHARED_KEY || auth_trans != 3)
			encrypt = 0;
	}

	//wpa_printf(MSG_DEBUG, "nl80211: send_mlme -> send_frame");
	return wpa_driver_nl80211_send_frame(bss, data, data_len, encrypt,
					     noack, freq, no_cck, offchanok,
					     wait_time);
}

static int wpa_driver_nl80211_send_action(struct i802_bss *bss,
					  unsigned int freq,
					  unsigned int wait_time,
					  const u8 *dst, const u8 *src,
					  const u8 *bssid,
					  const u8 *data, size_t data_len,
					  int no_cck)
{
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret = -1;
	u8 *buf;
	struct ieee80211_hdr *hdr;

	wpa_printf(MSG_DEBUG, "nl80211: Send Action frame (ifindex=%d, "
		   "freq=%u MHz wait=%d ms no_cck=%d)",
		   drv->ifindex, freq, wait_time, no_cck);

	buf = os_zalloc(24 + data_len);
	if (buf == NULL)
		return ret;
	os_memcpy(buf + 24, data, data_len);
	hdr = (struct ieee80211_hdr *) buf;
	hdr->frame_control =
		IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_ACTION);
	os_memcpy(hdr->addr1, dst, ETH_ALEN);
	os_memcpy(hdr->addr2, src, ETH_ALEN);
	os_memcpy(hdr->addr3, bssid, ETH_ALEN);

	if (is_ap_interface(drv->nlmode) &&
	    (!(drv->capa.flags & WPA_DRIVER_FLAGS_OFFCHANNEL_TX) ||
	     (int) freq == bss->freq || drv->device_ap_sme ||
	     !drv->use_monitor))
		ret = wpa_driver_nl80211_send_mlme(bss, buf, 24 + data_len,
						   0, freq, no_cck, 1,
						   wait_time);
	else
		ret = nl80211_send_frame_cmd(bss, freq, wait_time, buf,
					     24 + data_len,
					     &drv->send_action_cookie,
					     no_cck, 0, 1);

	os_free(buf);
	return ret;
}

static int driver_nl80211_send_mlme(void *priv, const u8 *data,
				    size_t data_len, int noack)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
	return wpa_driver_nl80211_send_mlme(bss, data, data_len, noack,
					    0, 0, 0, 0);
}
/**send_mlme  函数实现end**/

static int nl80211_get_mgmt_socket_fd(void *priv)
{
	struct i802_bss *bss = (struct i802_bss *)priv;
    return nl_socket_get_fd(bss->nl_mgmt);
}

static int nl80211_recv_mgmt_frame(void *priv)
{
    struct i802_bss *bss = (struct i802_bss *)priv;
    return nl_recvmsgs(bss->nl_mgmt, bss->nl_cb);
}

static int get_sta_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct hostap_sta_driver_data *data = arg;
	struct nlattr *stats[NL80211_STA_INFO_MAX + 1];
	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
        [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8},
		[NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
        [NL80211_STA_INFO_SIGNAL_AVG] = { .type = NLA_U8},
        [NL80211_STA_INFO_CONNECTED_TIME] = { .type = NLA_U32}
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	/*
	 * TODO: validate the interface and mac address!
	 * Otherwise, there's a race condition as soon as
	 * the kernel starts sending station notifications.
	 */

	if (!tb[NL80211_ATTR_STA_INFO]) {
		wpa_printf(MSG_DEBUG, "sta stats missing!");
		return NL_SKIP;
	}
	if (nla_parse_nested(stats, NL80211_STA_INFO_MAX,
			     tb[NL80211_ATTR_STA_INFO],
			     stats_policy)) {
		wpa_printf(MSG_DEBUG, "failed to parse nested attributes!");
		return NL_SKIP;
	}

	if (stats[NL80211_STA_INFO_INACTIVE_TIME])
		data->inactive_msec =
			nla_get_u32(stats[NL80211_STA_INFO_INACTIVE_TIME]);
	if (stats[NL80211_STA_INFO_RX_BYTES])
		data->rx_bytes = nla_get_u32(stats[NL80211_STA_INFO_RX_BYTES]);
	if (stats[NL80211_STA_INFO_TX_BYTES])
		data->tx_bytes = nla_get_u32(stats[NL80211_STA_INFO_TX_BYTES]);
    if (stats[NL80211_STA_INFO_SIGNAL])
		data->last_rssi = (int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL]);
    if (stats[NL80211_STA_INFO_SIGNAL_AVG])
		data->rssi_avg = (int8_t)nla_get_u8(stats[NL80211_STA_INFO_SIGNAL_AVG]);
	if (stats[NL80211_STA_INFO_RX_PACKETS])
		data->rx_packets =
			nla_get_u32(stats[NL80211_STA_INFO_RX_PACKETS]);
	if (stats[NL80211_STA_INFO_TX_PACKETS])
		data->tx_packets =
			nla_get_u32(stats[NL80211_STA_INFO_TX_PACKETS]);
	if (stats[NL80211_STA_INFO_TX_FAILED])
		data->tx_retry_failed =
			nla_get_u32(stats[NL80211_STA_INFO_TX_FAILED]);
    if (stats[NL80211_STA_INFO_CONNECTED_TIME])
		data->connected_msec =
			nla_get_u32(stats[NL80211_STA_INFO_CONNECTED_TIME]);
    
    return NL_SKIP;
}

static int get_sta_list_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct hostap_sta_list *sta_list = arg;
	struct hostap_sta_driver_data *data = 
        (struct hostap_sta_driver_data *)os_zalloc(sizeof(struct hostap_sta_driver_data));

	/*
	 * TODO: validate the interface and mac address!
	 * Otherwise, there's a race condition as soon as
	 * the kernel starts sending station notifications.
	 */
	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[NL80211_ATTR_STA_INFO]) {
		wpa_printf(MSG_DEBUG, "sta stats missing!");
		return NL_SKIP;
	}
    
    while(sta_list->next) {
        sta_list = sta_list->next;
    }
    sta_list->next = (struct hostap_sta_list *)os_zalloc(
                sizeof(struct hostap_sta_list));
    sta_list = sta_list->next;
    sta_list->sta_data = data;
    sta_list->next = NULL;

    /** get the station mac address **/
    u8 *addr = (u8 *)nla_data(tb[NL80211_ATTR_MAC]);
    os_memcpy(sta_list->sta_addr, addr, ETH_ALEN);

    /** parse nested attributes **/
    get_sta_handler(msg, sta_list->sta_data);
    
	return NL_SKIP;
}

static int nl80211_read_all_sta_data(void *priv, struct hostap_sta_list *sta_list)
{
    struct i802_bss *bss = (struct i802_bss *)priv;
    struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	nl80211_cmd(drv, msg, NLM_F_DUMP, NL80211_CMD_GET_STATION);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(bss->ifname));

	return send_and_recv_msgs(drv, msg, get_sta_list_handler, sta_list);
 nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;

}

//const struct wpa_driver_ops wpa_driver_nl80211_ops = {
const struct wpa_driver_ops wpa_driver_nl80211_ops = {
	.name = "nl80211",
	.desc = "Linux nl80211/cfg80211",
	.global_init = nl80211_global_init,
	//.global_deinit = nl80211_global_deinit,
	//.if_add = wpa_driver_nl80211_if_add,
	//.if_remove = driver_nl80211_if_remove,
	//.send_mlme = driver_nl80211_send_mlme,

	.sta_add = wpa_driver_nl80211_sta_add,
	//.sta_remove = driver_nl80211_sta_remove,
	.hapd_init = i802_init,
	//.hapd_deinit = i802_deinit
	.get_capa = wpa_driver_nl80211_get_capa,
	.sta_remove = driver_nl80211_sta_remove,
	.sta_set_flags = wpa_driver_nl80211_sta_set_flags,
	.get_hw_feature_data = wpa_driver_nl80211_get_hw_feature_data,
	.get_radio_name = nl80211_get_radio_name,
	.set_freq = i802_set_freq,
	.send_mlme = driver_nl80211_send_mlme,
    .send_action = wpa_driver_nl80211_send_action,
    .get_mgmt_socket_fd = nl80211_get_mgmt_socket_fd,
    .recv_mgmt_frame = nl80211_recv_mgmt_frame,
    .read_all_sta_data = nl80211_read_all_sta_data
};

#endif /* DRIVER_NL80211_H */
