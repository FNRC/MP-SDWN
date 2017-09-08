/*
 * hostapd / Initialization and configuration
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/byteorder.h>
#include <stdarg.h>

void * os_memset(void *s, int c, size_t n)
{
	char *p = (char *)s;
	while (n--)
		*p++ = c;
	return s;
}

void * os_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

void * os_malloc(size_t size)
{
	return malloc(size);
}

void * os_zalloc(size_t size)
{
	void *n = os_malloc(size);
	if (n)
		os_memset(n, 0, size);
	return n;
}

inline void * os_calloc(size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_zalloc(nmemb * size);
}

int os_memcmp_back(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;

	if (n == 0)
		return 0;

	while (*p1 == *p2) {
		p1++;
		p2++;
		n--;
		if (n == 0)
			return 0;
	}

	return *p1 - *p2;
}

void * os_memcpy(void *dest, const void *src, size_t n)
{
	char *d = (char *)dest;
	const char *s = (char *)src;
	while (n--)
		*d++ = *s++;
	return dest;
}

size_t os_strlcpy(char *dest, const char *src, size_t siz)
{
	const char *s = src;
	size_t left = siz;

	if (left) {
		/* Copy string up to the maximum size of the dest buffer */
		while (--left != 0) {
			if ((*dest++ = *s++) == '\0')
				break;
		}
	}

	if (left == 0) {
		/* Not enough room for the string; force NUL-termination */
		if (siz != 0)
			*dest = '\0';
		while (*s++)
			; /* determine total src string length */
	}

	return s - src - 1;
}

int os_strncmp(const void *s11,const void *s22, size_t n)
{
	const char *s1 = (const char *)s11;
	const char *s2 = (const char *)s22;
	if (n == 0)
		return 0;

	while (*s1 == *s2) {
		if (*s1 == '\0')
			break;
		s1++;
		s2++;
		n--;
		if (n == 0)
			return 0;
	}

	return *s1 - *s2;
}

int os_strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2) {
		if (*s1 == '\0')
			break;
		s1++;
		s2++;
	}

	return *s1 - *s2;
}

size_t os_strlen(const char *s)
{
	const char *p = s;
	while (*p)
		p++;
	return p - s;
}

char * os_strdup(const char *s)
{
	char *res;
	size_t len;
	if (s == NULL)
		return NULL;
	len = os_strlen(s);
	res = (char *)os_malloc(len + 1);
	if (res)
		os_memcpy(res, s, len + 1);
	return res;
}

char * os_strchr(const char *s, int c)
{
	while (*s) {
		if (*s == c)
			return (char *) s;
		s++;
	}
	return NULL;
}

char * os_strrchr(const char *s, int c)
{
	const char *p = s;
	while (*p)
		p++;
	p--;
	while (p >= s) {
		if (*p == c)
			return (char *) p;
		p--;
	}
	return NULL;
}

char * os_strstr(const char *haystack, const char *needle)
{
	size_t len = os_strlen(needle);
	while (*haystack) {
		if (os_strncmp(haystack, needle, len) == 0)
			return (char *) haystack;
		haystack++;
	}

	return NULL;
}

void * os_memmove(void *dest, const void *src, size_t n)
{
	if (dest < src)
		os_memcpy(dest, src, n);
	else {
		/* overlapping areas */
		char *d = (char *) dest + n;
		const char *s = (const char *) src + n;
		while (n--)
			*--d = *--s;
	}
	return dest;
}

size_t merge_byte_arrays(u8 *res, size_t res_len,
			 const u8 *src1, size_t src1_len,
			 const u8 *src2, size_t src2_len)
{
	size_t len = 0;

	os_memset(res, 0, res_len);

	if (src1) {
		if (src1_len >= res_len) {
			os_memcpy(res, src1, res_len);
			return res_len;
		}

		os_memcpy(res, src1, src1_len);
		len += src1_len;
	}

	if (src2) {
		if (len + src2_len >= res_len) {
			os_memcpy(res + len, src2, res_len - len);
			return res_len;
		}

		os_memcpy(res + len, src2, src2_len);
		len += src2_len;
	}

	return len;
}


/**
 * os_remove_in_array - Remove a member from an array by index
 * @ptr: Pointer to the array
 * @nmemb: Current member count of the array
 * @size: The size per member of the array
 * @idx: Index of the member to be removed
 */
inline void os_remove_in_array(void *ptr, size_t nmemb, size_t size,
				      size_t idx)
{
	if (idx < nmemb - 1)
		os_memmove(((unsigned char *) ptr) + idx * size,
			   ((unsigned char *) ptr) + (idx + 1) * size,
			   (nmemb - idx - 1) * size);
}

void os_free(void *ptr)
{
	free(ptr);
}

//输出的操作
inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

int os_snprintf(char *str, size_t size, const char *format, ...)
{
	va_list ap;
	int ret;

	/* See http://www.ijs.si/software/snprintf/ for portable
	 * implementation of snprintf.
	 */

	va_start(ap, format);
	ret = vsnprintf(str, size, format, ap);
	va_end(ap);
	if (size > 0)
		str[size - 1] = '\0';
	return ret;
}

