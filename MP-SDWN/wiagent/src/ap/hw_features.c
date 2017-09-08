/*
 * hostapd / Hardware feature query and different modes
 * Copyright 2002-2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2008-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "../utils/common.h"
#include "hw_features.h"

char * dfs_info(struct hostapd_channel_data *chan)
{
	static char info[256];
	const char *state;

	switch (chan->flag & HOSTAPD_CHAN_DFS_MASK) {
	case HOSTAPD_CHAN_DFS_UNKNOWN:
		state = "unknown";
		break;
	case HOSTAPD_CHAN_DFS_USABLE:
		state = "usable";
		break;
	case HOSTAPD_CHAN_DFS_UNAVAILABLE:
		state = "unavailable";
		break;
	case HOSTAPD_CHAN_DFS_AVAILABLE:
		state = "available";
		break;
	default:
		return NULL;
	}
	os_snprintf(info, sizeof(info), " (DFS state = %s)", state);
	info[sizeof(info) - 1] = '\0';

	return info;
}

void hostapd_free_hw_features(struct hostapd_hw_modes *hw_features,
			      size_t num_hw_features)
{
	size_t i;

	if (hw_features == NULL)
		return;

	for (i = 0; i < num_hw_features; i++) {
		os_free(hw_features[i].channels);
		os_free(hw_features[i].rates);
	}

	os_free(hw_features);
}

struct hostapd_hw_modes *
hostapd_get_hw_feature_data(struct hostapd_data *hapd, u16 *num_modes,
			    u16 *flags)
{
	if (hapd->driver == NULL ||
	    hapd->driver->get_hw_feature_data == NULL)
		return NULL;
	return hapd->driver->get_hw_feature_data(hapd->drv_priv, num_modes,
						 flags);
}


/**
 * hostapd_select_hw_mode - Select the hardware mode
 * @iface: Pointer to interface data.
 * Returns: 0 on success, < 0 on failure
 *
 * Sets up the hardware mode, channel, rates, and passive scanning
 * based on the configuration.
 */
int hostapd_select_hw_mode(struct hostapd_iface *iface)
{
	int i;

	if (iface->num_hw_features < 1)
		return -1;

	//14信道特殊处理
	if ((iface->conf->hw_mode == HOSTAPD_MODE_IEEE80211G ||
	     iface->conf->ieee80211n || iface->conf->ieee80211ac) &&
	    iface->conf->channel == 14) {
		wpa_printf(MSG_INFO, "Disable OFDM/HT/VHT on channel 14");
		iface->conf->hw_mode = HOSTAPD_MODE_IEEE80211B;
		iface->conf->ieee80211n = 0;
		iface->conf->ieee80211ac = 0;
	}
	//wpa_printf(MSG_DEBUG, "\nhostapd_select_hw_mode00:%d,%d\n",iface->hw_features[i],iface->conf->hw_mode);
	//从之前获取的多个硬件特性中选择一个我们
	//设置需要的,这个选择依据就是硬件的模式
	iface->current_mode = NULL;
	for (i = 0; i < iface->num_hw_features; i++) {
		struct hostapd_hw_modes *mode = &iface->hw_features[i];
		if (mode->mode == iface->conf->hw_mode) {
		//wpa_printf(MSG_DEBUG, "\nhostapd_select_hw_mode11:%d,%d\n",mode->mode,iface->conf->hw_mode);
			iface->current_mode = mode;
			break;
		}
	}

	if (iface->current_mode == NULL) {
		wpa_printf(MSG_ERROR, "Hardware does not support configured "
			   "mode");
		//hostapd_logger(iface->bss[0], NULL, HOSTAPD_MODULE_IEEE80211,
		//	       HOSTAPD_LEVEL_WARNING,
		//	       "Hardware does not support configured mode "
		//	       "(%d) (hw_mode in hostapd.conf)",
		///	       (int) iface->conf->hw_mode);
		return -2;
	}

	//switch (hostapd_check_chans(iface)) {
	switch (0) {
	case HOSTAPD_CHAN_VALID:
		return 0;
	case HOSTAPD_CHAN_ACS: /* ACS will run and later complete */
		return 1;
	case HOSTAPD_CHAN_INVALID:
	default:
		//hostapd_notify_bad_chans(iface);
		return -3;
	}
}
//参数调试
int hostapd_get_hw_features(struct hostapd_iface *iface)
{
	struct hostapd_data *hapd = iface->bss[0];
	int ret = 0, i, j;
	u16 num_modes, flags;
	struct hostapd_hw_modes *modes;

	//if (hostapd_drv_none(hapd))
	//	return -1;
	//获取硬件的特性参数
	modes = hostapd_get_hw_feature_data(hapd, &num_modes, &flags);
	if (modes == NULL) {
		//hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
		//	       HOSTAPD_LEVEL_DEBUG,
		//	       "Fetching hardware channel/rate support not "
		//	       "supported.");
		wpa_printf(MSG_DEBUG, "hostapd get hw_features failed\n");
		return -1;
	}

	iface->hw_flags = flags;

	hostapd_free_hw_features(iface->hw_features, iface->num_hw_features);
	iface->hw_features = modes;
	iface->num_hw_features = num_modes;
		//wpa_printf(MSG_DEBUG, "hostapd get hw_features success num_hw_features is %d\n",num_modes);
	for (i = 0; i < num_modes; i++) {
		struct hostapd_hw_modes *feature = &modes[i];
		int dfs_enabled = hapd->iconf->ieee80211h &&
			(iface->drv_flags & WPA_DRIVER_FLAGS_RADAR);

		/* set flag for channels we can use in current regulatory
		 * domain */
		for (j = 0; j < feature->num_channels; j++) {
			int dfs = 0;

			/*
			 * Disable all channels that are marked not to allow
			 * IBSS operation or active scanning.
			 * Use radar channels only if the driver supports DFS.
			 */
			if ((feature->channels[j].flag &
			     HOSTAPD_CHAN_RADAR) && dfs_enabled) {
				dfs = 1;
			} else if (((feature->channels[j].flag &
				     HOSTAPD_CHAN_RADAR) &&
				    !(iface->drv_flags &
				      WPA_DRIVER_FLAGS_DFS_OFFLOAD)) ||
				   (feature->channels[j].flag &
				    (HOSTAPD_CHAN_NO_IBSS |
				     HOSTAPD_CHAN_PASSIVE_SCAN))) {
				feature->channels[j].flag |=
					HOSTAPD_CHAN_DISABLED;
			}

			if (feature->channels[j].flag & HOSTAPD_CHAN_DISABLED)
				continue;

			//DEBUG
			/*wpa_printf(MSG_MSGDUMP, "Allowed channel: mode=%d "
				   "chan=%d freq=%d MHz max_tx_power=%d dBm%s",
				   feature->mode,
				   feature->channels[j].chan,
				   feature->channels[j].freq,
				   feature->channels[j].max_tx_power,
				   dfs ? dfs_info(&feature->channels[j]) : "");
				   */
		}
	}

	return ret;
}





int hostapd_hw_get_freq(struct hostapd_data *hapd, int chan)
{
	int i;

	if (!hapd->iface->current_mode)
		return 0;

	for (i = 0; i < hapd->iface->current_mode->num_channels; i++) {
		struct hostapd_channel_data *ch =
			&hapd->iface->current_mode->channels[i];
		if (ch->chan == chan)
			return ch->freq;
	}

	return 0;
}


//drv_ops
int hostapd_set_freq_params(struct hostapd_freq_params *data, int mode,
			    int freq, int channel, int ht_enabled,
			    int vht_enabled, int sec_channel_offset,
			    int vht_oper_chwidth, int center_segment0,
			    int center_segment1, u32 vht_caps)
{
	int tmp;

	os_memset(data, 0, sizeof(*data));
	data->mode = mode;
	data->freq = freq;
	data->channel = channel;
	data->ht_enabled = ht_enabled;
	data->vht_enabled = vht_enabled;
	data->sec_channel_offset = sec_channel_offset;
	data->center_freq1 = freq + sec_channel_offset * 10;
	data->center_freq2 = 0;
	data->bandwidth = sec_channel_offset ? 40 : 20;

	/*
	 * This validation code is probably misplaced, maybe it should be
	 * in src/ap/hw_features.c and check the hardware support as well.
	 */
	if (data->vht_enabled) switch (vht_oper_chwidth) {
	case VHT_CHANWIDTH_USE_HT:
		if (center_segment1)
			return -1;
		if (center_segment0 != 0 &&
		    5000 + center_segment0 * 5 != data->center_freq1 &&
		    2407 + center_segment0 * 5 != data->center_freq1)
			return -1;
		break;
	case VHT_CHANWIDTH_80P80MHZ:
		if (!(vht_caps & VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ)) {
			wpa_printf(MSG_ERROR,
				   "80+80 channel width is not supported!");
			return -1;
		}
		if (center_segment1 == center_segment0 + 4 ||
		    center_segment1 == center_segment0 - 4)
			return -1;
		data->center_freq2 = 5000 + center_segment1 * 5;
		/* fall through */
	case VHT_CHANWIDTH_80MHZ:
		data->bandwidth = 80;
		if (vht_oper_chwidth == 1 && center_segment1)
			return -1;
		if (vht_oper_chwidth == 3 && !center_segment1)
			return -1;
		if (!sec_channel_offset)
			return -1;
		/* primary 40 part must match the HT configuration */
		tmp = (30 + freq - 5000 - center_segment0 * 5)/20;
		tmp /= 2;
		if (data->center_freq1 != 5000 +
					 center_segment0 * 5 - 20 + 40 * tmp)
			return -1;
		data->center_freq1 = 5000 + center_segment0 * 5;
		break;
	case VHT_CHANWIDTH_160MHZ:
		data->bandwidth = 160;
		if (!(vht_caps & (VHT_CAP_SUPP_CHAN_WIDTH_160MHZ |
				  VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ))) {
			wpa_printf(MSG_ERROR,
				   "160MHZ channel width is not supported!");
			return -1;
		}
		if (center_segment1)
			return -1;
		if (!sec_channel_offset)
			return -1;
		/* primary 40 part must match the HT configuration */
		tmp = (70 + freq - 5000 - center_segment0 * 5)/20;
		tmp /= 2;
		if (data->center_freq1 != 5000 +
					 center_segment0 * 5 - 60 + 40 * tmp)
			return -1;
		data->center_freq1 = 5000 + center_segment0 * 5;
		break;
	}

	return 0;
}


//drv_ops.c
int hostapd_set_freq(struct hostapd_data *hapd, int mode, int freq,
		     int channel, int ht_enabled, int vht_enabled,
		     int sec_channel_offset, int vht_oper_chwidth,
		     int center_segment0, int center_segment1)
{
	struct hostapd_freq_params data;

	if (hostapd_set_freq_params(&data, mode, freq, channel, ht_enabled,
				    vht_enabled, sec_channel_offset,
				    vht_oper_chwidth,
				    center_segment0, center_segment1,
				    hapd->iface->current_mode->vht_capab))
		return -1;

	if (hapd->driver == NULL)
		return 0;
	if (hapd->driver->set_freq == NULL)
		return 0;
	return hapd->driver->set_freq(hapd->drv_priv, &data);
}

int hostapd_rate_found(int *list, int rate)
{
	int i;

	if (list == NULL)
		return 0;

	for (i = 0; list[i] >= 0; i++)
		if (list[i] == rate)
			return 1;

	return 0;
}

int hostapd_prepare_rates(struct hostapd_iface *iface,
			  struct hostapd_hw_modes *mode)
{
	int i, num_basic_rates = 0;
	int basic_rates_a[] = { 60, 120, 240, -1 };
	int basic_rates_b[] = { 10, 20, -1 };
	int basic_rates_g[] = { 10, 20, 55, 110, -1 };
	int *basic_rates;
	//wpa_printf(MSG_DEBUG, "hostapd prepare set rates num is %d\n",mode->num_rates);
	if (iface->conf->basic_rates)
		basic_rates = iface->conf->basic_rates;
	else switch (mode->mode) {
	case HOSTAPD_MODE_IEEE80211A:
		basic_rates = basic_rates_a;
		break;
	case HOSTAPD_MODE_IEEE80211B:
		basic_rates = basic_rates_b;
		break;
	case HOSTAPD_MODE_IEEE80211G:
		basic_rates = basic_rates_g;
		break;
	case HOSTAPD_MODE_IEEE80211AD:
		return 0; /* No basic rates for 11ad */
	default:
		return -1;
	}

	i = 0;
	while (basic_rates[i] >= 0)
		i++;
	if (i)
		i++; /* -1 termination */
	os_free(iface->basic_rates);
	iface->basic_rates = (int *)os_malloc(i * sizeof(int));
	if (iface->basic_rates)
		os_memcpy(iface->basic_rates, basic_rates, i * sizeof(int));

	os_free(iface->current_rates);
	iface->num_rates = 0;

	iface->current_rates =
		(struct hostapd_rate_data*)os_calloc(mode->num_rates, sizeof(struct hostapd_rate_data));
	if (!iface->current_rates) {
		wpa_printf(MSG_ERROR, "Failed to allocate memory for rate "
			   "table.");
		return -1;
	}

	for (i = 0; i < mode->num_rates; i++) {
		struct hostapd_rate_data *rate;

		if (iface->conf->supported_rates &&
		    !hostapd_rate_found(iface->conf->supported_rates,
					mode->rates[i]))
			continue;

		rate = &iface->current_rates[iface->num_rates];
		rate->rate = mode->rates[i];
		if (hostapd_rate_found(basic_rates, rate->rate)) {
			rate->flags |= HOSTAPD_RATE_BASIC;
			num_basic_rates++;
		}
		//DEBUG
		//wpa_printf(MSG_DEBUG, "RATE[%d] rate=%d flags=0x%x",
		//	   iface->num_rates, rate->rate, rate->flags);
		iface->num_rates++;
	}

	if ((iface->num_rates == 0 || num_basic_rates == 0) &&
	    (!iface->conf->ieee80211n || !iface->conf->require_ht)) {
		wpa_printf(MSG_ERROR, "No rates remaining in supported/basic "
			   "rate sets (%d,%d).",
			   iface->num_rates, num_basic_rates);
		return -1;
	}

	return 0;
}

const char * hostapd_hw_mode_txt(int mode)
{
	switch (mode) {
	case HOSTAPD_MODE_IEEE80211A:
		return "IEEE 802.11a";
	case HOSTAPD_MODE_IEEE80211B:
		return "IEEE 802.11b";
	case HOSTAPD_MODE_IEEE80211G:
		return "IEEE 802.11g";
	case HOSTAPD_MODE_IEEE80211AD:
		return "IEEE 802.11ad";
	default:
		return "UNKNOWN";
	}
}


/**
 * hostapd_setup_interface_complete - Complete interface setup
 *
 * This function is called when previous steps in the interface setup has been
 * completed. This can also start operations, e.g., DFS, that will require
 * additional processing before interface is ready to be enabled. Such
 * operations will call this function from eloop callbacks when finished.
 */
int hostapd_setup_interface_complete(struct hostapd_iface *iface, int err)
{
	struct hostapd_data *hapd = iface->bss[0];
	size_t j;
	u8 *prev_addr;

	if (err)
		goto fail;

	//hostapd_ubus_add_iface(iface);
	//wpa_printf(MSG_DEBUG, "Completing interface initialization");
	if (iface->conf->channel) {
//#ifdef NEED_AP_MLME
		int res;
//#endif /* NEED_AP_MLME */
		//现获取频率然后再设置频率
		iface->freq = hostapd_hw_get_freq(hapd, iface->conf->channel);
		//下面的调试可以查看AP无线配置参数
		//wpa_printf(MSG_DEBUG, "Mode: %s  Channel: %d  "
			//   "Frequency: %d MHz",
			//   hostapd_hw_mode_txt(iface->conf->hw_mode),
			 //  iface->conf->channel, iface->freq);

//#ifdef NEED_AP_MLME
		/* Check DFS */
		//TODO
		//res = hostapd_handle_dfs(iface);
		//if (res <= 0) {
		//	if (res < 0)
		////		goto fail;
		//	return res;
		//}
//#endif /* NEED_AP_MLME */

		//设置频率
		if (hostapd_set_freq(hapd, hapd->iconf->hw_mode, iface->freq,
				     hapd->iconf->channel,
				     hapd->iconf->ieee80211n,
				     hapd->iconf->ieee80211ac,
				     hapd->iconf->secondary_channel,
				     hapd->iconf->vht_oper_chwidth,
				     hapd->iconf->vht_oper_centr_freq_seg0_idx,
				     hapd->iconf->vht_oper_centr_freq_seg1_idx)) {
			wpa_printf(MSG_ERROR, "Could not set channel for "
				   "kernel driver");
			goto fail;
		}
	}

	if (iface->current_mode) {
		//设置模式支持的基本速率
		if (hostapd_prepare_rates(iface, iface->current_mode)) {
			wpa_printf(MSG_ERROR, "Failed to prepare rates "
				   "table.");
			//hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
				//       HOSTAPD_LEVEL_WARNING,
			//	       "Failed to prepare rates table.");
			goto fail;
		}
		//wpa_printf(MSG_ERROR, "complete to set current mode\n");
	}
	//设置rts

	//设置fragm


	//prev_addr = hapd->own_addr;
/*
	for (j = 0; j < iface->num_bss; j++) {
		hapd = iface->bss[j];
		if (j)
			os_memcpy(hapd->own_addr, prev_addr, ETH_ALEN);
		if (hostapd_setup_bss(hapd, j == 0)) {
			do {
				hapd = iface->bss[j];
				hostapd_bss_deinit_no_free(hapd);
				hostapd_free_hapd_data(hapd);
			} while (j-- > 0);
			goto fail;
		}
		if (hostapd_mac_comp_empty(hapd->conf->bssid) == 0)
			prev_addr = hapd->own_addr;
	}
*/
	hapd = iface->bss[0];

	return 0;

fail:
	wpa_printf(MSG_ERROR, "Interface initialization failed\n");
	iface->state = (enum Hostapd_iface_state)HAPD_IFACE_DISABLED;
	return -1;
}

