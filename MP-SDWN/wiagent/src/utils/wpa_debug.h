/*
 * wpa_supplicant/hostapd / Debug prints
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_DEBUG_H
#define WPA_DEBUG_H

extern int wpa_debug_level;

/* Debugging function - conditional printf and hex dump. Driver wrappers can
 * use these for debugging purposes. */

enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARN, MSG_ERROR
};

#ifndef CONFIG_MSG_MIN_PRIORITY
#define CONFIG_MSG_MIN_PRIORITY 0
#endif

/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void _wpa_printf(int level, const char *fmt, ...)
PRINTF_FORMAT(2, 3);

#define wpa_printf(level, ...)						\
	do {								\
		if (level >= CONFIG_MSG_MIN_PRIORITY)			\
			_wpa_printf(level, __VA_ARGS__);		\
	} while(0)

/**
 * wpa_debug_printf_timestamp - Print timestamp for debug output
 *
 * This function prints a timestamp in seconds_from_1970.microsoconds
 * format if debug output has been configured to include timestamps in debug
 * messages.
 */
void wpa_debug_print_timestamp(void);

int wpa_debug_open_file(const char *path);
int wpa_debug_reopen_file(void);
void wpa_debug_close_file(void);

#endif
