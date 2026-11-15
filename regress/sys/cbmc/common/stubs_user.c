/*
 * User/kernel copy primitives.  Built without kernel headers.
 *
 * User memory is not an object of the model:
 *  - the user address is never dereferenced, so kernel code that
 *    dereferences a user pointer itself is reported as a bad dereference;
 *  - every copyin returns fresh arbitrary bytes, so code that fetches the
 *    same user data twice sees two unrelated values (double fetch);
 *  - any copy may fail with EFAULT.
 * The kernel side of each copy must be valid for the full length.
 */
#include <stddef.h>
#define EFAULT		14
#define ENAMETOOLONG	63
_Bool nondet_bool(void);
size_t nondet_size_t(void);

int copyin(const void *uaddr, void *kaddr, size_t len)
{
	__CPROVER_precondition(__CPROVER_w_ok(kaddr, len),
	    "copyin: kernel buffer writable for len");
	if (nondet_bool())
		return EFAULT;
	if (len > 0)
		__CPROVER_havoc_slice(kaddr, len);
	return 0;
}

int copyout(const void *kaddr, void *uaddr, size_t len)
{
	__CPROVER_precondition(__CPROVER_r_ok(kaddr, len),
	    "copyout: kernel buffer readable for len");
	return nondet_bool() ? EFAULT : 0;
}

int copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	size_t n = nondet_size_t();

	__CPROVER_precondition(__CPROVER_w_ok(kaddr, len),
	    "copyinstr: kernel buffer writable for len");
	if (nondet_bool())
		return EFAULT;
	if (len == 0 || n >= len) {
		/* no NUL within len bytes: buffer filled, unterminated */
		if (len > 0)
			__CPROVER_havoc_slice(kaddr, len);
		if (done)
			*done = len;
		return ENAMETOOLONG;
	}
	/* n non-NUL bytes followed by the terminator */
	if (n > 0)
		__CPROVER_havoc_slice(kaddr, n);
	((char *)kaddr)[n] = '\0';
	if (done)
		*done = n + 1;
	return 0;
}
