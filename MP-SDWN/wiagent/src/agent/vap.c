/*
 * SDWN system virtual ap data structure.
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "vap.h"

static struct vap_data *vap_first = NULL;
static struct vap_data *vap_last = NULL;

static char *bssid_file_path = "/sys/kernel/debug/ieee80211/phy0/ath9k/bssid_extra";

static void wiagent_vap_list(void)
{
    int num = 0;
    struct vap_data *vap_temp = vap_first;

    wpa_printf(MSG_INFO, "wi vap list:");
    while (vap_temp) {
        wpa_printf(MSG_INFO, "%d. vap:"MACSTR" bssid:"
                MACSTR" ssid:%s", ++num, MAC2STR(vap_temp->addr),
                MAC2STR(vap_temp->bssid), vap_temp->ssid);
        vap_temp =  vap_temp->next;
    }
}

/*
 * This re-computes the BSSID mask for this node
 * using all the BSSIDs of the VAPs, and sets the
 * hardware register accordingly.
 */
static void reset_bssid_mask(const u8 *hw_addr)
{
    int i;
    u8 bssid_mask[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct vap_data *vap_temp = vap_first;
    
    /**
     * compute bssid mask
     */
    while (vap_temp) {
        for (i = 0; i < 6; i++)
            bssid_mask[i] &= ~(hw_addr[i] ^ vap_temp->bssid[i]);
        vap_temp = vap_temp->next;
    }
    
    // Update bssid mask register through debugfs
    FILE *debugfs_file = fopen(bssid_file_path, "w");
    if (debugfs_file!=NULL) {
        fprintf(debugfs_file,MACSTR"\n", MAC2STR(bssid_mask));
        fclose(debugfs_file);
    }
}

void wiagent_vap_cleaner(int fd, short what, void *arg)
{
    u8 *bss_addr = arg;
    struct vap_data *vap = vap_first;
    struct vap_data *vap_previous = NULL;
    time_t now_time = time(NULL);

    while (vap) {
        if (difftime(now_time, vap->connected_time) > CLEANER_SECONDS
                && vap->is_beacon == 0) {

            if (vap_previous) {
                vap_previous->next = vap->next;
                if (vap->ssid) {
                    os_free(vap->ssid);
                }
                if (vap->beacon_data) {
                    os_free(vap->beacon_data);
                    vap->beacon_len = 0;
                }
                os_free(vap);
                vap = vap_previous->next;
            }
            else {
                vap_first = vap->next;
                if (vap->ssid) {
                    os_free(vap->ssid);
                }
                if (vap->beacon_data) {
                    os_free(vap->beacon_data);
                    vap->beacon_len = 0;
                }
                os_free(vap);
                vap = vap_first;
                vap_previous = NULL;
            }
        }
        else {
            vap_previous = vap;
            vap = vap->next;
        }
    }
    reset_bssid_mask(bss_addr);

}

struct vap_data *wiagent_get_vap(const u8 *addr)
{
    struct vap_data *vap_temp = vap_first;

    while (vap_temp !=  NULL) {
        if (os_memcmp(vap_temp->addr, addr, ETH_ALEN) == 0) 
            return vap_temp;
        vap_temp = vap_temp->next;
    }
    return NULL;
}

struct vap_data * wiagent_vap_add(const u8 *bss_addr,
                    const u8 *addr, const u8 *bssid, const char *ssid)
{
    struct vap_data *vap_temp;

    vap_temp = wiagent_get_vap(addr);
    if (vap_temp) 
        return vap_temp;

    vap_temp = (struct vap_data *)os_zalloc(sizeof(struct vap_data));
    if(vap_temp == NULL) {
        wpa_printf(MSG_DEBUG, "vap malloc failed, memory is not enough!\n");
        return NULL;
    }

    if (vap_first == NULL) {
        vap_first = vap_temp;
        vap_last = vap_first;
    }
    else {
        vap_last->next = vap_temp;
        vap_last = vap_temp;
    } 
    os_memcpy(vap_last->addr, addr, ETH_ALEN);
    os_memcpy(vap_last->bssid, bssid, ETH_ALEN);
    vap_last->ssid = (char *)os_zalloc(strlen(ssid) + 1);
    strcpy(vap_last->ssid, ssid);
    vap_last->ssid_len = strlen(vap_last->ssid);
    vap_last->connected_time = time(NULL);    //get current time as vap connected time
    vap_last->beacon_data = NULL;
    vap_last->beacon_len = 0;
    vap_last->sta = NULL;
    vap_last->next = NULL;
    
    reset_bssid_mask(bss_addr);

    return vap_last;
}

int wiagent_vap_remove(const u8 *bss_addr, const u8 *addr)
{
    struct vap_data *vap_temp = vap_first;
    struct vap_data *vap_previous = NULL;

    while (vap_temp) {
        if (os_memcmp(vap_temp->addr, addr, ETH_ALEN) == 0) {

            if(vap_previous) {
                vap_previous->next = vap_temp->next;
            }
            else {
                vap_first = vap_temp->next;
            }
            
            if (vap_temp->ssid) {
                os_free(vap_temp->ssid);
            }
            if (vap_temp->beacon_data) {
                os_free(vap_temp->beacon_data);
                vap_temp->beacon_len == 0;
            }
            os_free(vap_temp);
            vap_temp = NULL;
            
            break;
        }
        
        vap_previous = vap_temp;
        vap_temp = vap_temp->next;
    }
    reset_bssid_mask(bss_addr);
    return 0;
}

void wiagent_for_each_vap(void (*cb)(struct vap_data *vap, void *ctx), void *ctx)
{
    struct vap_data *vap;
    for(vap = vap_first; vap; vap = vap->next) {
        cb(vap, ctx);
    }
}
