/*
 * Harness: ip6_process_hopopts() of sys/netinet6/ip6_input.c, the option
 * loop of the IPv6 hop-by-hop header, on arbitrary option bytes, on the
 * contract models of the mbuf library (common/mbufcontract.h).
 *
 * Caller contract (ip6_hopopts_input(): IP6_EXTHDR_GET makes the header
 * and its options contiguous, opthead is the first byte after the hbh
 * header, and hbhlen bytes follow it): the option area lies contiguous
 * in the first mbuf's data, which begins with the IPv6 header (the
 * jumbo option reads ip6_plen through mtod(*mp)).  The harness builds
 * one mbuf of 40 + MAXOPT bytes: the IPv6 header, then MAXOPT bytes of
 * data.  The option area is the last hbhlen bytes of the data, so it
 * ends where the data object ends: a read of any option byte past it is
 * out of bounds.  hbhlen is 0..MAXOPT (a header of at most 8 + 32
 * bytes; MAXOPT stands for the largest option area the proof covers).
 *
 * Properties: no out-of-bounds access for arbitrary option bytes; the
 * option walk ends (decreases clause in "loops"); no leak and no double
 * free (icmp6_error consumes the mbuf on its error paths, m_freemp on
 * the others); on return 0 the mbuf is still owned, its chain is well
 * formed, and the harness frees it.
 *
 * Callees: icmp6_error is a model that frees the mbuf, as the real one
 * sends or frees it.  ip6stat_inc (counters_inc) has no body: counters
 * are not allocated here, and the function has no effect on the path.
 */
#define INET6		1
#define MAXOPT		32
#define MC_MAXLEN	(40 + MAXOPT)	/* 40 = sizeof (struct ip6_hdr) */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include "mbufcontract.h"

#include <sys/protosw.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

/*
 * ghost state for the loop invariant (target file "loops"): the end of
 * the option area, the mbuf, and its data object.  The loop may free the
 * mbuf and write *mp (error paths return from the loop); the invariant
 * restates the mbuf fields the loop does not write, so that the state
 * after the loop is the caller's mbuf and not an arbitrary one.
 */
u_char *g_end;		/* one past the last byte of the option area */
struct mbuf *g_m;	/* the mbuf */
u_char *g_buf;		/* its data object (MC_BUF) */

#include "ip6_input.c"

/*
 * ip6_protox (netinet6/in6_proto.c) and inet6sw are referenced by the
 * included file; they are defined here with their declared types, and
 * no code on the path reads them.
 */
u_char ip6_protox[IPPROTO_MAX];
const struct protosw inet6sw[1];

/*
 * m_freem with its loop unrolled.  The loop of the header's m_freem runs
 * at most MC_MAXSEG times, but it is called from inside the contracted
 * loop, and goto-instrument refuses an inner loop there unless it has
 * been unwound before the contracts are applied (cbmc.sh applies the
 * --unwindset only later).  Two mbufs at most; a longer chain is an error.
 */
struct mbuf *
model_m_freem(struct mbuf *m)
{
	if (m != NULL)
		m = m_free(m);
	if (m != NULL)
		m = m_free(m);
	__CPROVER_assert(m == NULL, "m_freem model: chain longer than MC_MAXSEG");
	return (NULL);
}

/* Replacement for icmp6_error: consumes m, as the real function does. */
void
model_icmp6_error(struct mbuf *m, int type, int code, int param)
{
	m_freem(m);
}

int
main(void)
{
	struct mbuf *m;
	u_int8_t *opthead;
	u_int32_t plen, rtalert = ~0;
	int hbhlen, rc;

	hbhlen = mc_upto(MAXOPT);		/* 0..MAXOPT option bytes */
	m = mc_seg(MC_MAXLEN);			/* IPv6 header, then MAXOPT */
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = m->m_len;
	g_end = mtod(m, u_int8_t *) + m->m_len;
	g_m = m;
	g_buf = (u_char *)MC_BUF(m);
	opthead = g_end - hbhlen;		/* option area ends at g_end */
	plen = mc_upto(1);			/* ip6_plen so far: 0 or 1 */

	rc = ip6_process_hopopts(&m, opthead, hbhlen, &rtalert, &plen);
	if (rc == 0) {
		mc_check(m);
		mc_free(m);
	}
	return (0);
}
