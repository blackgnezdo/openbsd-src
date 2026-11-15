/*
 * Harness: msg_copyin, msg_copyout and msg_free on one SysV message of
 * arbitrary length.
 *
 * sysv_msg.c is included so that the message code and sysvmsgpl are
 * visible.  sys_msgsnd guarantees len <= msginfo.msgmax; MAXLEN is a
 * scaled-down stand-in for that bound: two cluster-sized chunks plus one
 * mbuf of data, so a chain holds at most three mbufs.
 *
 * User addresses are arbitrary values; they are never dereferenced
 * (common/stubs_user.c).
 */
#include "sysv_msg.c"

#define MAXLEN	(2 * MCLBYTES + MLEN)

unsigned long nondet_ulong(void);
size_t nondet_size_t(void);
int nondet_int(void);

int
main(void)
{
	struct msg *msg;
	struct mbuf *m;
	const char *ubuf = (const char *)nondet_ulong();
	size_t len = nondet_size_t() % (MAXLEN + 1);
	size_t sum = 0;
	size_t outlen, want;
	int flags, error;

	sysvmsgpl.pr_size = sizeof(struct msg);
	/* as msg_create() does */
	msg = pool_get(&sysvmsgpl, PR_WAITOK|PR_ZERO);
	num_msgs++;

	error = msg_copyin(msg, ubuf, len);
	if (error != 0)
		return (0);	/* msg_copyin has freed msg; do not touch it */

	__CPROVER_assert(msg->msg_len == len,
	    "msg_copyin: msg_len == len");
	for (m = msg->msg_data; m != NULL; m = m->m_next)
		sum += (size_t)m->m_len;
	__CPROVER_assert(sum == len,
	    "msg_copyin: mbuf chain lengths sum to len");

	outlen = nondet_size_t();
	want = outlen;
	flags = nondet_int();
	error = msg_copyout(msg, (char *)nondet_ulong(), &outlen, flags);
	if (error == 0)
		__CPROVER_assert(outlen == (want < len ? want : len),
		    "msg_copyout: *len == min(requested, len)");

	msg_free(msg);
	return (0);
}
