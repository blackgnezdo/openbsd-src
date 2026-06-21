/*
 * Linux build-compat shim for OpenBSD openrsync.
 * Force-included (cc -include) so the upstream sources stay untouched.
 */
#ifndef OPENRSYNC_LINUX_COMPAT_H
#define OPENRSYNC_LINUX_COMPAT_H

#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* libbsd provides strlcpy/strlcat/reallocarray/strtonum/getprogname/err etc. */
#include <bsd/string.h>
#include <bsd/stdlib.h>
#include <bsd/unistd.h>
#include <bsd/err.h>

/* <util.h> on OpenBSD: not needed for the functions openrsync actually uses. */

/* OpenBSD sticky-bit name. */
#ifndef S_ISTXT
#define S_ISTXT S_ISVTX
#endif

/* recallocarray: zeroing realloc. libbsd lacks it; provide a fallback. */
static inline void *
_compat_recallocarray(void *ptr, size_t oldn, size_t newn, size_t size)
{
	void *p;
	if (newn != 0 && size != 0 && newn > (size_t)-1 / size) {
		errno = ENOMEM;
		return NULL;
	}
	p = realloc(ptr, newn * size);
	if (p == NULL)
		return NULL;
	if (newn > oldn)
		memset((char *)p + oldn * size, 0, (newn - oldn) * size);
	return p;
}
#define recallocarray _compat_recallocarray

/* pledge/unveil: no-op on Linux. */
static inline int _compat_pledge(const char *p, const char *e)
{ (void)p; (void)e; return 0; }
static inline int _compat_unveil(const char *p, const char *e)
{ (void)p; (void)e; return 0; }
#define pledge _compat_pledge
#define unveil _compat_unveil

/*
 * scan_scaled: parse "10", "10K", "4.5M" etc. into a long long.
 * OpenBSD's lives in libutil; libbsd doesn't ship it.
 */
static inline int
_compat_scan_scaled(char *scaled, long long *result)
{
	char *p = scaled;
	long long val = 0;
	int sign = 1, frac = 0;
	long long fracval = 0, fracdiv = 1;
	long long mult = 1;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '-') { sign = -1; p++; }
	else if (*p == '+') p++;
	if (*p == '\0') { errno = EINVAL; return -1; }
	for (; *p != '\0'; p++) {
		if (*p >= '0' && *p <= '9') {
			if (frac) { fracval = fracval*10 + (*p-'0'); fracdiv *= 10; }
			else val = val*10 + (*p-'0');
			continue;
		}
		if (*p == '.' && !frac) { frac = 1; continue; }
		break;
	}
	switch (*p) {
	case '\0': case 'B': case 'b': mult = 1LL; break;
	case 'K': case 'k': mult = 1024LL; break;
	case 'M': case 'm': mult = 1024LL*1024; break;
	case 'G': case 'g': mult = 1024LL*1024*1024; break;
	case 'T': case 't': mult = 1024LL*1024*1024*1024; break;
	case 'P': case 'p': mult = 1024LL*1024*1024*1024*1024; break;
	case 'E': case 'e': mult = 1024LL*1024*1024*1024*1024*1024; break;
	default: errno = EINVAL; return -1;
	}
	if (*p != '\0' && *(p+1) != '\0') { errno = EINVAL; return -1; }
	*result = sign * (val * mult + (fracval * mult) / fracdiv);
	return 0;
}
#define scan_scaled _compat_scan_scaled

#endif /* OPENRSYNC_LINUX_COMPAT_H */
