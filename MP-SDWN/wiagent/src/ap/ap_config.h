/*
 * hostapd / Configuration definitions and helpers functions
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HOSTAPD_CONFIG_HH
#define HOSTAPD_CONFIG_HH

#include <netinet/in.h>
#include "../utils/common.h"
#include "../utils/common_defs.h"
#include "ieee802_1x_defs.h"

#define MAX_STA_COUNT 2007
#define MAX_VLAN_ID 4094
#define PMK_LEN 32
#define IFNAMSIZ 16

#define VLAN_ID_WILDCARD -1
struct hostapd_vlan {
	struct hostapd_vlan *next;
	int vlan_id; /* VLAN ID or -1 (VLAN_ID_WILDCARD) for wildcard entry */
	char ifname[IFNAMSIZ + 1];
	int dynamic_vlan;
#ifdef CONFIG_FULL_DYNAMIC_VLAN

#define DVLAN_CLEAN_BR 	0x1
#define DVLAN_CLEAN_VLAN	0x2
#define DVLAN_CLEAN_VLAN_PORT	0x4
#define DVLAN_CLEAN_WLAN_PORT	0x8
	int clean;
#endif /* CONFIG_FULL_DYNAMIC_VLAN */
};

typedef u8 macaddr[ETH_ALEN];


struct mac_acl_entry {
	macaddr addr;
	int vlan_id;
};

struct hostapd_ip_addr {
	int af; /* AF_INET / AF_INET6 */
	union {
		struct in_addr v4;
#ifdef CONFIG_IPV6
		struct in6_addr v6;
#endif /* CONFIG_IPV6 */
		u8 max_len[16];
	} u;
};

typedef enum hostap_security_policy {
	SECURITY_PLAINTEXT = 0,
	SECURITY_STATIC_WEP = 1,
	SECURITY_IEEE_802_1X = 2,
	SECURITY_WPA_PSK = 3,
	SECURITY_WPA = 4,
	SECURITY_OSEN = 5
} secpolicy;

struct hostapd_wep_keys {
	u8 idx;
	u8 *key[NUM_WEP_KEYS];
	size_t len[NUM_WEP_KEYS];
	int keys_set;
	size_t default_len; /* key length used for dynamic key generation */
};

struct hostapd_tx_queue_params {
	int aifs;
	int cwmin;
	int cwmax;
	int burst; /* maximum burst time in 0.1 ms, i.e., 10 = 1 ms */
};

enum Macaddr_acl{
		ACCEPT_UNLESS_DENIED = 0,
		DENY_UNLESS_ACCEPTED = 1,
		USE_EXTERNAL_RADIUS_AUTH = 2
	};
	
//�Զ����ö������
enum Wpa_psk_radius{
		PSK_RADIUS_IGNORED = 0,
		PSK_RADIUS_ACCEPTED = 1,
		PSK_RADIUS_REQUIRED = 2
	} ;
	
struct hostapd_radius_servers;
struct ft_remote_r0kh;
struct ft_remote_r1kh;

#define HOSTAPD_MAX_SSID_LEN 32

#define NUM_WEP_KEYS 4

struct hostapd_ssid {
	u8 ssid[HOSTAPD_MAX_SSID_LEN];
	size_t ssid_len;
	unsigned int ssid_set:1;
	unsigned int utf8_ssid:1;
	unsigned int wpa_passphrase_set:1;
	unsigned int wpa_psk_set:1;

	char vlan[IFNAMSIZ + 1];
	secpolicy security_policy;

	struct hostapd_wpa_psk *wpa_psk;
	char *wpa_passphrase;
	char *wpa_psk_file;

	struct hostapd_wep_keys wep;

#define DYNAMIC_VLAN_DISABLED 0
#define DYNAMIC_VLAN_OPTIONAL 1
#define DYNAMIC_VLAN_REQUIRED 2
	int dynamic_vlan;
#define DYNAMIC_VLAN_NAMING_WITHOUT_DEVICE 0
#define DYNAMIC_VLAN_NAMING_WITH_DEVICE 1
#define DYNAMIC_VLAN_NAMING_END 2
	int vlan_naming;
#ifdef CONFIG_FULL_DYNAMIC_VLAN
	char *vlan_tagged_interface;
#endif /* CONFIG_FULL_DYNAMIC_VLAN */
};


struct hostapd_radius_attr {
	u8 type;
	struct wpabuf *val;
	struct hostapd_radius_attr *next;
};

struct hostapd_wpa_psk {
	struct hostapd_wpa_psk *next;
	int group;
	u8 psk[PMK_LEN];
	u8 addr[ETH_ALEN];
	u8 p2p_dev_addr[ETH_ALEN];
};

struct hostapd_radius_server {
	/**
	 * addr - radiusAuthServerAddress or radiusAccServerAddress
	 */
	struct hostapd_ip_addr addr;

	/**
	 * port - radiusAuthClientServerPortNumber or radiusAccClientServerPortNumber
	 */
	int port;

	/**
	 * shared_secret - Shared secret for authenticating RADIUS messages
	 */
	u8 *shared_secret;

	/**
	 * shared_secret_len - Length of shared_secret in octets
	 */
	size_t shared_secret_len;

	/* Dynamic (not from configuration file) MIB data */

	/**
	 * index - radiusAuthServerIndex or radiusAccServerIndex
	 */
	int index;

	/**
	 * round_trip_time - radiusAuthClientRoundTripTime or radiusAccClientRoundTripTime
	 * Round-trip time in hundredths of a second.
	 */
	int round_trip_time;

	/**
	 * requests - radiusAuthClientAccessRequests or radiusAccClientRequests
	 */
	u32 requests;

	/**
	 * retransmissions - radiusAuthClientAccessRetransmissions or radiusAccClientRetransmissions
	 */
	u32 retransmissions;

	/**
	 * access_accepts - radiusAuthClientAccessAccepts
	 */
	u32 access_accepts;

	/**
	 * access_rejects - radiusAuthClientAccessRejects
	 */
	u32 access_rejects;

	/**
	 * access_challenges - radiusAuthClientAccessChallenges
	 */
	u32 access_challenges;

	/**
	 * responses - radiusAccClientResponses
	 */
	u32 responses;

	/**
	 * malformed_responses - radiusAuthClientMalformedAccessResponses or radiusAccClientMalformedResponses
	 */
	u32 malformed_responses;

	/**
	 * bad_authenticators - radiusAuthClientBadAuthenticators or radiusAccClientBadAuthenticators
	 */
	u32 bad_authenticators;

	/**
	 * timeouts - radiusAuthClientTimeouts or radiusAccClientTimeouts
	 */
	u32 timeouts;

	/**
	 * unknown_types - radiusAuthClientUnknownTypes or radiusAccClientUnknownTypes
	 */
	u32 unknown_types;

	/**
	 * packets_dropped - radiusAuthClientPacketsDropped or radiusAccClientPacketsDropped
	 */
	u32 packets_dropped;
};

/**
 * struct hostapd_radius_servers - RADIUS servers for RADIUS client
 */
struct hostapd_radius_servers {
	/**
	 * auth_servers - RADIUS Authentication servers in priority order
	 */
	struct hostapd_radius_server *auth_servers;

	/**
	 * num_auth_servers - Number of auth_servers entries
	 */
	int num_auth_servers;

	/**
	 * auth_server - The current Authentication server
	 */
	struct hostapd_radius_server *auth_server;

	/**
	 * acct_servers - RADIUS Accounting servers in priority order
	 */
	struct hostapd_radius_server *acct_servers;

	/**
	 * num_acct_servers - Number of acct_servers entries
	 */
	int num_acct_servers;

	/**
	 * acct_server - The current Accounting server
	 */
	struct hostapd_radius_server *acct_server;

	/**
	 * retry_primary_interval - Retry interval for trying primary server
	 *
	 * This specifies a retry interval in sexconds for trying to return to
	 * the primary RADIUS server. RADIUS client code will automatically try
	 * to use the next server when the current server is not replying to
	 * requests. If this interval is set (non-zero), the primary server
	 * will be retried after the specified number of seconds has passed
	 * even if the current used secondary server is still working.
	 */
	int retry_primary_interval;

	/**
	 * msg_dumps - Whether RADIUS message details are shown in stdout
	 */
	int msg_dumps;

	/**
	 * client_addr - Client (local) address to use if force_client_addr
	 */
	struct hostapd_ip_addr client_addr;

	/**
	 * force_client_addr - Whether to force client (local) address
	 */
	int force_client_addr;
};

static int hostapd_config_wmm_ac(struct hostapd_wmm_ac_params wmm_ac_params[],
			  const char *name, const char *val)
{
	int num, v;
	const char *pos;
	struct hostapd_wmm_ac_params *ac;

	/* skip 'wme_ac_' or 'wmm_ac_' prefix */
	pos = name + 7;
	if (os_strncmp(pos, "be_", 3) == 0) {
		num = 0;
		pos += 3;
	} else if (os_strncmp(pos, "bk_", 3) == 0) {
		num = 1;
		pos += 3;
	} else if (os_strncmp(pos, "vi_", 3) == 0) {
		num = 2;
		pos += 3;
	} else if (os_strncmp(pos, "vo_", 3) == 0) {
		num = 3;
		pos += 3;
	} else {
		wpa_printf(MSG_ERROR, "Unknown WMM name '%s'", pos);
		return -1;
	}

	ac = &wmm_ac_params[num];

	if (os_strcmp(pos, "aifs") == 0) {
		v = atoi(val);
		if (v < 1 || v > 255) {
			wpa_printf(MSG_ERROR, "Invalid AIFS value %d", v);
			return -1;
		}
		ac->aifs = v;
	} else if (os_strcmp(pos, "cwmin") == 0) {
		v = atoi(val);
		if (v < 0 || v > 12) {
			wpa_printf(MSG_ERROR, "Invalid cwMin value %d", v);
			return -1;
		}
		ac->cwmin = v;
	} else if (os_strcmp(pos, "cwmax") == 0) {
		v = atoi(val);
		if (v < 0 || v > 12) {
			wpa_printf(MSG_ERROR, "Invalid cwMax value %d", v);
			return -1;
		}
		ac->cwmax = v;
	} else if (os_strcmp(pos, "txop_limit") == 0) {
		v = atoi(val);
		if (v < 0 || v > 0xffff) {
			wpa_printf(MSG_ERROR, "Invalid txop value %d", v);
			return -1;
		}
		ac->txop_limit = v;
	} else if (os_strcmp(pos, "acm") == 0) {
		v = atoi(val);
		if (v < 0 || v > 1) {
			wpa_printf(MSG_ERROR, "Invalid acm value %d", v);
			return -1;
		}
		ac->admission_control_mandatory = v;
	} else {
		wpa_printf(MSG_ERROR, "Unknown wmm_ac_ field '%s'", pos);
		return -1;
	}

	return 0;
}

/**
 * struct hostapd_bss_config - Per-BSS configuration
 */
struct hostapd_bss_config {
	char iface[IFNAMSIZ + 1];
	char bridge[IFNAMSIZ + 1];
	char vlan_bridge[IFNAMSIZ + 1];
	char wds_bridge[IFNAMSIZ + 1];

	enum hostapd_logger_level logger_syslog_level, logger_stdout_level;

	unsigned int logger_syslog; /* module bitfield */
	unsigned int logger_stdout; /* module bitfield */

	int max_num_sta; /* maximum number of STAs in station table */

	int dtim_period;

	int ieee802_1x; /* use IEEE 802.1X */
	int eapol_version;
	int eap_server; /* Use internal EAP server instead of external
			 * RADIUS server */
	struct hostapd_eap_user *eap_user;
	char *eap_user_sqlite;
	char *eap_sim_db;
	struct hostapd_ip_addr own_ip_addr;
	char *nas_identifier;
	struct hostapd_radius_servers *radius;
	int acct_interim_interval;
	int radius_request_cui;
	struct hostapd_radius_attr *radius_auth_req_attr;
	struct hostapd_radius_attr *radius_acct_req_attr;
	int radius_das_port;
	unsigned int radius_das_time_window;
	int radius_das_require_event_timestamp;
	struct hostapd_ip_addr radius_das_client_addr;
	u8 *radius_das_shared_secret;
	size_t radius_das_shared_secret_len;

	struct hostapd_ssid ssid;

	char *eap_req_id_text; /* optional displayable message sent with
				* EAP Request-Identity */
	size_t eap_req_id_text_len;
	int eapol_key_index_workaround;

	size_t default_wep_key_len;
	int individual_wep_key_len;
	int wep_rekeying_period;
	int broadcast_key_idx_min, broadcast_key_idx_max;
	int eap_reauth_period;

	int ieee802_11f; /* use IEEE 802.11f (IAPP) */
	char iapp_iface[IFNAMSIZ + 1]; /* interface used with IAPP broadcast
					* frames */

	enum Macaddr_acl macaddr_acl;
	struct mac_acl_entry *accept_mac;
	int num_accept_mac;
	struct mac_acl_entry *deny_mac;
	int num_deny_mac;
	int wds_sta;
	int isolate;
	int start_disabled;

	int auth_algs; /* bitfield of allowed IEEE 802.11 authentication
			* algorithms, WPA_AUTH_ALG_{OPEN,SHARED,LEAP} */

	int wpa; /* bitfield of WPA_PROTO_WPA, WPA_PROTO_RSN */
	int wpa_key_mgmt;
#ifdef CONFIG_IEEE80211W
	enum mfp_options ieee80211w;
	int group_mgmt_cipher;
	/* dot11AssociationSAQueryMaximumTimeout (in TUs) */
	unsigned int assoc_sa_query_max_timeout;
	/* dot11AssociationSAQueryRetryTimeout (in TUs) */
	int assoc_sa_query_retry_timeout;
#endif /* CONFIG_IEEE80211W */
	enum Wpa_psk_radius wpa_psk_radius;
	int wpa_pairwise;
	int wpa_group;
	int wpa_group_rekey;
	int wpa_strict_rekey;
	int wpa_gmk_rekey;
	int wpa_ptk_rekey;
	int rsn_pairwise;
	int rsn_preauth;
	char *rsn_preauth_interfaces;
	int peerkey;

#ifdef CONFIG_IEEE80211R
	/* IEEE 802.11r - Fast BSS Transition */
	u8 mobility_domain[MOBILITY_DOMAIN_ID_LEN];
	u8 r1_key_holder[FT_R1KH_ID_LEN];
	u32 r0_key_lifetime;
	u32 reassociation_deadline;
	struct ft_remote_r0kh *r0kh_list;
	struct ft_remote_r1kh *r1kh_list;
	int pmk_r1_push;
	int ft_over_ds;
#endif /* CONFIG_IEEE80211R */

	char *ctrl_interface; /* directory for UNIX domain sockets */
#ifndef CONFIG_NATIVE_WINDOWS
	gid_t ctrl_interface_gid;
#endif /* CONFIG_NATIVE_WINDOWS */
	int ctrl_interface_gid_set;

	char *ca_cert;
	char *server_cert;
	char *private_key;
	char *private_key_passwd;
	int check_crl;
	char *ocsp_stapling_response;
	char *dh_file;
	u8 *pac_opaque_encr_key;
	u8 *eap_fast_a_id;
	size_t eap_fast_a_id_len;
	char *eap_fast_a_id_info;
	int eap_fast_prov;
	int pac_key_lifetime;
	int pac_key_refresh_time;
	int eap_sim_aka_result_ind;
	int tnc;
	int fragment_size;
	u16 pwd_group;

	char *radius_server_clients;
	int radius_server_auth_port;
	int radius_server_acct_port;
	int radius_server_ipv6;

	char *test_socket; /* UNIX domain socket path for driver_test */

	int use_pae_group_addr; /* Whether to send EAPOL frames to PAE group
				 * address instead of individual address
				 * (for driver_wired.c).
				 */

	int ap_max_inactivity;
	int ignore_broadcast_ssid;

	int wmm_enabled;
	int wmm_uapsd;

	struct hostapd_vlan *vlan;

	macaddr bssid;

	/*
	 * Maximum listen interval that STAs can use when associating with this
	 * BSS. If a STA tries to use larger value, the association will be
	 * denied with status code 51.
	 */
	u16 max_listen_interval;

	int disable_pmksa_caching;
	int okc; /* Opportunistic Key Caching */

	int wps_state;
#ifdef CONFIG_WPS
	int wps_independent;
	int ap_setup_locked;
	u8 uuid[16];
	char *wps_pin_requests;
	char *device_name;
	char *manufacturer;
	char *model_name;
	char *model_number;
	char *serial_number;
	u8 device_type[WPS_DEV_TYPE_LEN];
	char *config_methods;
	u8 os_version[4];
	char *ap_pin;
	int skip_cred_build;
	u8 *extra_cred;
	size_t extra_cred_len;
	int wps_cred_processing;
	int force_per_enrollee_psk;
	u8 *ap_settings;
	size_t ap_settings_len;
	char *upnp_iface;
	char *friendly_name;
	char *manufacturer_url;
	char *model_description;
	char *model_url;
	char *upc;
	struct wpabuf *wps_vendor_ext[MAX_WPS_VENDOR_EXTENSIONS];
	int wps_nfc_pw_from_config;
	int wps_nfc_dev_pw_id;
	struct wpabuf *wps_nfc_dh_pubkey;
	struct wpabuf *wps_nfc_dh_privkey;
	struct wpabuf *wps_nfc_dev_pw;
#endif /* CONFIG_WPS */
	int pbc_in_m1;
	char *server_id;

#define P2P_ENABLED BIT(0)
#define P2P_GROUP_OWNER BIT(1)
#define P2P_GROUP_FORMATION BIT(2)
#define P2P_MANAGE BIT(3)
#define P2P_ALLOW_CROSS_CONNECTION BIT(4)
	int p2p;
#ifdef CONFIG_P2P
	u8 ip_addr_go[4];
	u8 ip_addr_mask[4];
	u8 ip_addr_start[4];
	u8 ip_addr_end[4];
#endif /* CONFIG_P2P */

	int disassoc_low_ack;
	int skip_inactivity_poll;

#define TDLS_PROHIBIT BIT(0)
#define TDLS_PROHIBIT_CHAN_SWITCH BIT(1)
	int tdls;
	int disable_11n;
	int disable_11ac;

	/* IEEE 802.11v */
	int time_advertisement;
	char *time_zone;
	int wnm_sleep_mode;
	int bss_transition;

	/* IEEE 802.11u - Interworking */
	int interworking;
	int access_network_type;
	int internet;
	int asra;
	int esr;
	int uesa;
	int venue_info_set;
	u8 venue_group;
	u8 venue_type;
	u8 hessid[ETH_ALEN];

	/* IEEE 802.11u - Roaming Consortium list */
	unsigned int roaming_consortium_count;
	struct hostapd_roaming_consortium *roaming_consortium;

	/* IEEE 802.11u - Venue Name duples */
	unsigned int venue_name_count;
	struct hostapd_lang_string *venue_name;

	/* IEEE 802.11u - Network Authentication Type */
	u8 *network_auth_type;
	size_t network_auth_type_len;

	/* IEEE 802.11u - IP Address Type Availability */
	u8 ipaddr_type_availability;
	u8 ipaddr_type_configured;

	/* IEEE 802.11u - 3GPP Cellular Network */
	u8 *anqp_3gpp_cell_net;
	size_t anqp_3gpp_cell_net_len;

	/* IEEE 802.11u - Domain Name */
	u8 *domain_name;
	size_t domain_name_len;

	unsigned int nai_realm_count;
	struct hostapd_nai_realm_data *nai_realm_data;

	u16 gas_comeback_delay;
	int gas_frag_limit;

	u8 qos_map_set[16 + 2 * 21];
	unsigned int qos_map_set_len;

	int osen;
#ifdef CONFIG_HS20
	int hs20;
	int disable_dgaf;
	u16 anqp_domain_id;
	unsigned int hs20_oper_friendly_name_count;
	struct hostapd_lang_string *hs20_oper_friendly_name;
	u8 *hs20_wan_metrics;
	u8 *hs20_connection_capability;
	size_t hs20_connection_capability_len;
	u8 *hs20_operating_class;
	u8 hs20_operating_class_len;
	struct hs20_icon {
		u16 width;
		u16 height;
		char language[3];
		char type[256];
		char name[256];
		char file[256];
	} *hs20_icons;
	size_t hs20_icons_count;
	u8 osu_ssid[HOSTAPD_MAX_SSID_LEN];
	size_t osu_ssid_len;
	struct hs20_osu_provider {
		unsigned int friendly_name_count;
		struct hostapd_lang_string *friendly_name;
		char *server_uri;
		int *method_list;
		char **icons;
		size_t icons_count;
		char *osu_nai;
		unsigned int service_desc_count;
		struct hostapd_lang_string *service_desc;
	} *hs20_osu_providers, *last_osu;
	size_t hs20_osu_providers_count;
	unsigned int hs20_deauth_req_timeout;
	char *subscr_remediation_url;
	u8 subscr_remediation_method;
#endif /* CONFIG_HS20 */

	u8 wps_rf_bands; /* RF bands for WPS (WPS_RF_*) */

#ifdef CONFIG_RADIUS_TEST
	char *dump_msk_file;
#endif /* CONFIG_RADIUS_TEST */

	struct wpabuf *vendor_elements;

	unsigned int sae_anti_clogging_threshold;
	int *sae_groups;

#ifdef CONFIG_TESTING_OPTIONS
	u8 bss_load_test[5];
	u8 bss_load_test_set;
#endif /* CONFIG_TESTING_OPTIONS */
};

//���������ӿڵ����ã��������ļ�hostapd.conf�м��أ�
/**
 * struct hostapd_config - Per-radio interface configuration
 */
struct hostapd_config {
	struct hostapd_bss_config **bss, *last_bss;
	size_t num_bss;

	u16 beacon_int;
	int rts_threshold;
	int fragm_threshold;
	u8 send_probe_response;
	u8 channel;
	int *chanlist;
	enum hostapd_hw_mode hw_mode; /* HOSTAPD_MODE_IEEE80211A, .. */
	enum Preamble preamble;

	int *supported_rates;
	int *basic_rates;

	const struct wpa_driver_ops *driver;

	int ap_table_max_size;
	int ap_table_expiration_time;

	char country[3]; /* first two octets: country code as described in
			  * ISO/IEC 3166-1. Third octet:
			  * ' ' (ascii 32): all environments
			  * 'O': Outdoor environemnt only
			  * 'I': Indoor environment only
			  */

	int ieee80211d;

	int ieee80211h; /* DFS */

	/*
	 * Local power constraint is an octet encoded as an unsigned integer in
	 * units of decibels. Invalid value -1 indicates that Power Constraint
	 * element will not be added.
	 */
	int local_pwr_constraint;

	/* Control Spectrum Management bit */
	int spectrum_mgmt_required;

	struct hostapd_tx_queue_params tx_queue[NUM_TX_QUEUES];

	/*
	 * WMM AC parameters, in same order as 802.1D, i.e.
	 * 0 = BE (best effort)
	 * 1 = BK (background)
	 * 2 = VI (video)
	 * 3 = VO (voice)
	 */
	struct hostapd_wmm_ac_params wmm_ac_params[4];

	int ht_op_mode_fixed;
	u16 ht_capab;
	int noscan;
	int ieee80211n;
	int secondary_channel;
	int require_ht;
	int obss_interval;
	u32 vht_capab;
	int ieee80211ac;
	int require_vht;
	u8 vht_oper_chwidth;
	u8 vht_oper_centr_freq_seg0_idx;
	u8 vht_oper_centr_freq_seg1_idx;

#ifdef CONFIG_TESTING_OPTIONS
	double ignore_probe_probability;
	double ignore_auth_probability;
	double ignore_assoc_probability;
	double ignore_reassoc_probability;
	double corrupt_gtk_rekey_mic_probability;
#endif /* CONFIG_TESTING_OPTIONS */

#ifdef CONFIG_ACS
	unsigned int acs_num_scans;
#endif /* CONFIG_ACS */
};

#endif /* HOSTAPD_CONFIG_H */

