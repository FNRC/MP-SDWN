/*
 * WiAgent / main()
 * Copyright (c) 2017, liyaming <liyaming1994@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <signal.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "ap/hostapd.h"
#include "ap/beacon.h"
#include "ap/wiagent_80211.h"
#include "agent/controller_event.h"
#include "agent/push.h"
#include "drivers/driver.h"
#include "drivers/nl80211_copy.h"
#include "utils/common.h"
#include "utils/wiagent_event.h"

static void
wiagent_mgmt_frame_cb(evutil_socket_t fd, short what, void *arg)
{
    int res;
    struct hostapd_data *hapd = (struct hostapd_data *)arg;
        
    res = hostapd_recv_mgmt_frame(hapd);
    if (res < 0) {
        wpa_printf(MSG_ERROR, "%s - nl_recvmsgs failed, return code: %d",
            __func__, res);
    }	
}

static int
init_hostapd_interface(struct hapd_interfaces *interfaces)
{
	interfaces->config_read_cb = hostapd_config_read;	
	interfaces->global_iface_path = NULL;
	interfaces->global_iface_name = NULL;
	interfaces->global_ctrl_sock = -1;

    wpa_supplicant_event = wiagent_wpa_event;
	
	interfaces->count = 1;   //only using wlan0
	if (interfaces->count) {
	    interfaces->iface = (struct hostapd_iface**)os_calloc(
                interfaces->count,sizeof(struct hostapd_iface *));
		if (interfaces->iface == NULL) {
			wpa_printf(MSG_ERROR, "interfaces->iface malloc failed");
			goto out;
		}
	}

	/* Allocate and parse configuration for wlan0 interface files */
    interfaces->iface[0] = hostapd_interface_init(interfaces,"/tmp/run/hostapd-phy0.conf", 0);
	if (!interfaces->iface[0]) {
		wpa_printf(MSG_ERROR, "Failed to initialize interface");
        goto out;
	}
	
    if (interfaces->iface[0] == NULL || interfaces->iface[0]->bss[0] == NULL) {
		//nl80211 driver驱动不可用,可能出现空指针，未赋值
		//wpa_printf(MSG_ERROR, "No hostapd driver wrapper available");
		wpa_printf(MSG_ERROR, "Fail to read wireless interface configuration.");
		goto out;
    }

    /* Enable configured interfaces. */
	//  hapd = interfaces.iface[0]->bss[0];     //一个hostapd_data代表一个基本服务集合
    if (hostapd_driver_init(interfaces->iface[0]) < 0)
        goto out;
    if (hostapd_setup_interface(interfaces->iface[0]) < 0)
        goto out;

    return 0;

out:
	os_free(interfaces->iface);
    wpa_printf(MSG_ERROR, "Hostapd interface initialize failed.");
    return -1;
}

int wiagent_80211_event_init(struct hostapd_data *hapd)
{
    struct event *ev_frame; 
    struct event *ev_beacon;
    struct timeval tv_beacon; 
    int frame_sock;
    int frame_sock_flags;

    /**
     * Set the socket fd that receive management frame 
     * to a non-blocking state.
     */
    frame_sock = hostapd_get_mgmt_socket_fd(hapd);
    frame_sock_flags = fcntl(frame_sock, F_GETFL, 0); //获取文件的flags值。
    fcntl(frame_sock, F_SETFL, frame_sock_flags | O_NONBLOCK);   //设置成非阻塞模式；
    
    ev_frame = wiagent_event_new(frame_sock, EV_READ | EV_PERSIST,
            wiagent_mgmt_frame_cb, hapd);
    wiagent_event_add(ev_frame, NULL);

    /**
     * Creating a new event which broadcast beacon frames every 200ms.
     */
    ev_beacon = wiagent_event_new(-1, EV_TIMEOUT | EV_PERSIST, 
            wiagent_send_beacon, hapd);
	tv_beacon.tv_sec = 0;
    tv_beacon.tv_usec = 200 * 1000;
	wiagent_event_add(ev_beacon, &tv_beacon);

    return 0;

}

int main(int argc, char **argv)
{
    struct hapd_interfaces interfaces;
    struct hostapd_data *hapd;
    char *controller_ip;
    
    if ((controller_ip = *(++argv)) == NULL) {
        wpa_printf(MSG_ERROR, "Need controller's ip address.");
        return 1;
    }
    
    /**
     * Initialize the wireless interfaces (wlan0), 
     * the code is transplanted from hostapd.
     */
    os_memset(&interfaces, 0, sizeof(struct hapd_interfaces));
    if (init_hostapd_interface(&interfaces) < 0) { 
        wpa_printf(MSG_ERROR, "Initialize the wireless interfaces failed.");
        return 1;
    }
    hapd = interfaces.iface[0]->bss[0];

    
    if (controller_event_init(hapd, controller_ip) < 0 ||
            wiagent_80211_event_init(hapd) < 0) {
        wpa_printf(MSG_ERROR, "Failed to initialize wiagent.");
        return 1;
    }

    wiagent_event_dispatch();

	return 0;
}

