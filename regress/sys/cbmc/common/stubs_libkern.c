/*
 * libkern string and bit functions that have no body under cbmc.sh:
 * the kernel maps bzero, bcmp and memcmp to compiler builtins
 * (sys/systm.h), and CBMC's library has no model for the others.
 * Without these models each returned an arbitrary value and touched no
 * memory, so an overflow by bzero or strlcpy, or an over-read by strnlen
 * or memcmp, went unreported.
 *
 * Included by common/stubs_alloc.c, so it is linked into every target by
 * both engines; cbmc.sh keeps the bodies (fixed keep list).  Built without
 * kernel headers.  Natively (native.sh, NATIVE_SHIM_H) the __builtin_*
 * names are not defined here (clang reserves them; the kernel's bzero,
 * bcmp, memcmp then come from the C library, checked by the sanitizer);
 * the other models are the same in both engines.
 *
 * Semantics are those of sys/lib/libkern: each function reads and writes
 * exactly the bytes the libkern version does, so the pointer checks
 * report an access outside an object byte by byte.  Functions that touch
 * a whole region up front (bzero, explicit_bzero, timingsafe_bcmp) check
 * it as a region.
 *
 * Loops.  Each model is a byte loop; a target that reaches one bounds it
 * like bcopy, with --unwindset NAME.0:N in opts (N one more than the
 * longest string or region):
 *	__builtin_bcmp.0  __builtin_memcmp.0  timingsafe_bcmp.0  memchr.0
 *	strnlen.0  strlcpy.0 (copy)  strlcpy.1 (rest of src)
 *	strlcat.0 (end of dst)  strlcat.1 (copy)  strlcat.2 (rest of src)
 * bzero and explicit_bzero use CBMC's memset (no loop); ffs, fls, flsl
 * have no loop.
 * Not modelled (they stay on the NOBODY line if reached): strnstr,
 * strncasecmp is CBMC's, scanc, skpc.
 */
#include <stddef.h>

#ifndef NATIVE_SHIM_H
void *memset(void *, int, size_t);

void
__builtin_bzero(void *b, size_t n)
{
	__CPROVER_precondition(__CPROVER_w_ok(b, n),
	    "bzero region writeable");
	if (n > 0)
		memset(b, 0, n);
}

/* libkern bcmp: 0 if equal, 1 at the first difference */
int
__builtin_bcmp(const void *b1, const void *b2, size_t length)
{
	const unsigned char *p1 = b1, *p2 = b2;

	if (length == 0)
		return (0);
	do {
		if (*p1++ != *p2++)
			return (1);
	} while (--length);
	return (0);
}

/* libkern memcmp */
int
__builtin_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = s1, *p2 = s2;

	if (n != 0) {
		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return (0);
}
#endif /* !NATIVE_SHIM_H */

void *memset(void *, int, size_t);

void
explicit_bzero(void *b, size_t n)
{
	__CPROVER_precondition(__CPROVER_w_ok(b, n),
	    "explicit_bzero region writeable");
	if (n > 0)
		memset(b, 0, n);
}

/* reads all n bytes of both regions, 0 if equal, 1 otherwise */
int
timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	int ret = 0;

	__CPROVER_precondition(__CPROVER_r_ok(b1, n) &&
	    __CPROVER_r_ok(b2, n), "timingsafe_bcmp regions readable");
	for (; n > 0; n--)
		ret |= *p1++ ^ *p2++;
	return (ret != 0);
}

void *
memchr(const void *s, int c, size_t n)
{
	const unsigned char *p = s;

	for (; n != 0; n--, p++)
		if (*p == (unsigned char)c)
			return ((void *)p);
	return (NULL);
}

size_t
strnlen(const char *str, size_t maxlen)
{
	size_t i;

	for (i = 0; i < maxlen && str[i] != '\0'; i++)
		;
	return (i);
}

/* libkern strlcpy: copies up to dsize - 1 bytes, terminates if dsize != 0,
 * returns strlen(src) (reads all of src) */
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';
		while (*src++)
			;
	}
	return (src - osrc - 1);
}

/* libkern strlcat */
size_t
strlcat(char *dst, const char *src, size_t dsize)
{
	const char *odst = dst, *osrc = src;
	size_t n = dsize, dlen;

	while (n-- != 0 && *dst != '\0')
		dst++;
	dlen = dst - odst;
	n = dsize - dlen;
	if (n-- == 0) {
		while (*src++)
			;
		return (dlen + (src - osrc - 1));
	}
	while (*src != '\0') {
		if (n != 0) {
			*dst++ = *src;
			n--;
		}
		src++;
	}
	*dst = '\0';
	return (dlen + (src - osrc));
}

/* no loops: bit tests */
int
ffs(int mask)
{
	unsigned int m = (unsigned int)mask;
	int b = 1;

	if (m == 0)
		return (0);
	if ((m & 0xffff) == 0) { m >>= 16; b += 16; }
	if ((m & 0xff) == 0) { m >>= 8; b += 8; }
	if ((m & 0xf) == 0) { m >>= 4; b += 4; }
	if ((m & 0x3) == 0) { m >>= 2; b += 2; }
	if ((m & 0x1) == 0) { b += 1; }
	return (b);
}

int
flsl(long mask)
{
	unsigned long m = (unsigned long)mask;
	int b = 0;

	if (m == 0)
		return (0);
	if (m >> 32) { m >>= 32; b += 32; }
	if (m >> 16) { m >>= 16; b += 16; }
	if (m >> 8) { m >>= 8; b += 8; }
	if (m >> 4) { m >>= 4; b += 4; }
	if (m >> 2) { m >>= 2; b += 2; }
	if (m >> 1) { b += 1; }
	return (b + 1);
}

int
fls(int mask)
{
	return (flsl((long)(unsigned int)mask));
}
