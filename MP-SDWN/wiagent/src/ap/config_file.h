/*
 * hostapd / Configuration file parser
 * Copyright (c) 2003-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CONFIG_FILE_HH
#define CONFIG_FILE_HH
#include "../utils/common.h"

struct hostapd_config * hostapd_config_read(const char *fname);
int hostapd_set_iface(struct hostapd_config *conf,
		      struct hostapd_bss_config *bss, char *field,
		      char *value);
			  
			  
			  
			  
static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}			  
			  
			  
/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
static int hexstr2bin(const char *hex, u8 *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	u8 *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
static int hwaddr_aton(const char *txt, u8 *addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		int a, b;

		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;

}
static size_t printf_decode(u8 *buf, size_t maxlen, const char *str)
{
	const char *pos = str;
	size_t len = 0;
	int val;

	while (*pos) {
		if (len + 1 >= maxlen)
			break;
		switch (*pos) {
		case '\\':
			pos++;
			switch (*pos) {
			case '\\':
				buf[len++] = '\\';
				pos++;
				break;
			case '"':
				buf[len++] = '"';
				pos++;
				break;
			case 'n':
				buf[len++] = '\n';
				pos++;
				break;
			case 'r':
				buf[len++] = '\r';
				pos++;
				break;
			case 't':
				buf[len++] = '\t';
				pos++;
				break;
			case 'e':
				buf[len++] = '\e';
				pos++;
				break;
			case 'x':
				pos++;
				val = hex2byte(pos);
				if (val < 0) {
					val = hex2num(*pos);
					if (val < 0)
						break;
					buf[len++] = val;
					pos++;
				} else {
					buf[len++] = val;
					pos += 2;
				}
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				val = *pos++ - '0';
				if (*pos >= '0' && *pos <= '7')
					val = val * 8 + (*pos++ - '0');
				if (*pos >= '0' && *pos <= '7')
					val = val * 8 + (*pos++ - '0');
				buf[len++] = val;
				break;
			default:
				break;
			}
			break;
		default:
			buf[len++] = *pos++;
			break;
		}
	}
	if (maxlen > len)
		buf[len] = '\0';

	return len;
}
static char * dup_binstr(const void *src, size_t len)
{
	char *res;

	if (src == NULL)
		return NULL;
	res = (char*)os_malloc(len + 1);
	if (res == NULL)
		return NULL;
	os_memcpy(res, src, len);
	res[len] = '\0';

	return res;
}

static char * wpa_config_parse_string(const char *value, size_t *len)
{
	if (*value == '"') {
		const char *pos;
		char *str;
		value++;
		pos = os_strrchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		*len = pos - value;
		str = dup_binstr(value, *len);
		if (str == NULL)
			return NULL;
		return str;
	} else if (*value == 'P' && value[1] == '"') {
		const char *pos;
		char *tstr, *str;
		size_t tlen;
		value += 2;
		pos = os_strrchr(value, '"');
		if (pos == NULL || pos[1] != '\0')
			return NULL;
		tlen = pos - value;
		tstr = dup_binstr(value, tlen);
		if (tstr == NULL)
			return NULL;

		str = (char*)os_malloc(tlen + 1);
		if (str == NULL) {
			os_free(tstr);
			return NULL;
		}

		*len = printf_decode((u8 *) str, tlen + 1, tstr);
		os_free(tstr);

		return str;
	} else {
		u8 *str;
		size_t tlen, hlen = os_strlen(value);
		if (hlen & 1)
			return NULL;
		tlen = hlen / 2;
		str = (u8*)os_malloc(tlen + 1);
		if (str == NULL)
			return NULL;
		if (hexstr2bin(value, str, tlen)) {
			os_free(str);
			return NULL;
		}
		str[tlen] = '\0';
		*len = tlen;
		return (char *) str;
	}
}

#endif /* CONFIG_FILE_H */

