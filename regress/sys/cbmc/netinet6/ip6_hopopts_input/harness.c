/*
 * Harness: ip6_hopopts_input() of sys/netinet6/ip6_input.c on an IPv6
 * packet of arbitrary length and content (up to MC_MAXLEN bytes, one or
 * two mbufs), on the contract models of the mbuf library
 * (common/mbufcontract.h).  The option loop, ip6_process_hopopts(), is
 * replaced by a model that asserts the guarantee the proof of the loop
 * (netinet6/ip6_hopopts) assumes: the hbhlen option bytes at opthead are
 * readable, and lie contiguous in one mbuf of the chain.  That is the assume/guarantee split: ip6_hopopts_input has to
 * establish the guarantee, and the loop proof assumes it.
 *
 * Caller contract (ip6_input_if): the packet holds the IPv6 header,
 * contiguous in the first mbuf (the caller's m_pullup); a shorter packet
 * is dropped before this function runs, and the harness does the same.
 *
 * Properties: no out-of-bounds access in the header fetch (ip6_exthdr_get
 * through m_pulldown); the guarantee holds at every call of the option
 * loop; on return 0 the chain is well formed, *offp lies inside the
 * packet, and the harness frees the mbuf; on return -1 the mbuf is freed
 * (*mp is NULL, or the model consumed it: g_freed); no leak.
 *
 * MC_MAXLEN = 56: the IPv6 header (40 bytes) and up to 16 bytes of
 * hop-by-hop header (length byte 0 or 1).  The length byte is arbitrary,
 * so the header fetch also meets longer headers, which it refuses when
 * the packet is too short.  Larger packets (32-byte headers) were run at
 * 72 bytes and timed out in the solver (1.6 million variables): the
 * byte copies of m_pulldown and m_pullup dominate.
 */
#define INET6		1
#define MC_MAXLEN	56
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include "mbufcontract.h"

#include <sys/protosw.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "ip6_input.c"

/*
 * ip6_protox and inet6sw: as in netinet6/ip6_hopopts (declared by the
 * included file; no code on the path reads them).
 */
u_char ip6_protox[IPPROTO_MAX];
const struct protosw inet6sw[1];

/* The mbuf the option-loop model freed on its error return, or NULL. */
struct mbuf *g_freed;

/*
 * Model of ip6_process_hopopts() (the option loop, proved in
 * netinet6/ip6_hopopts).  Its guarantee on the caller: the hbhlen option
 * bytes at opthead are readable; asserted here.  Its effects: either
 * returns 0 with arbitrary outputs, or frees the mbuf and returns -1,
 * as the real one does on its error paths.
 */
/*
 * Does [opthead, opthead + hbhlen) lie in the data of one mbuf of the
 * chain?  ip6_exthdr_get returns a pointer into the mbuf that holds the
 * range, which need not be the first one.  The bounds are the mbuf's
 * m_len, not the storage object: bytes past m_len are not data.
 */
static int
model_in_one_mbuf(struct mbuf *m, const u_int8_t *opthead, int hbhlen)
{
	struct mbuf *t;
	u_char *d;
	long off;
	int i, in = 0;

	for (i = 0, t = m; i < MC_MAXSEG && t != NULL; i++, t = t->m_next) {
		d = mtod(t, u_char *);
		if (!__CPROVER_same_object(opthead, d))
			continue;
		off = (long)(opthead - d);
		if (off >= 0 && off + hbhlen <= t->m_len)
			in = 1;
	}
	return (in);
}

int
model_ip6_process_hopopts(struct mbuf **mp, u_int8_t *opthead, int hbhlen,
    u_int32_t *rtalertp, u_int32_t *plenp)
{
	__CPROVER_assert(hbhlen >= 0 && __CPROVER_r_ok(opthead, hbhlen) &&
	    model_in_one_mbuf(*mp, opthead, hbhlen),
	    "ip6_process_hopopts guarantee: the hbhlen option bytes are readable, contiguous in one mbuf");
	if (mc_upto(1) == 0) {
		*rtalertp = nondet_uint();
		*plenp = nondet_uint();
		return (0);
	}
	g_freed = *mp;
	m_freemp(mp);
	return (-1);
}

int
main(void)
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	u_int32_t plen, rtalert = ~0;	/* as ip6_input_if passes them */
	int off = sizeof(struct ip6_hdr), len, rc;

	len = mc_upto(MC_MAXLEN);
	if (len < (int)sizeof(struct ip6_hdr))	/* ip6_input drops it */
		return (0);
	m = mc_build(len);
	/* the caller's pullup of the IPv6 header */
	if (m->m_len < (int)sizeof(struct ip6_hdr) &&
	    (m = m_pullup(m, sizeof(struct ip6_hdr))) == NULL)
		return (0);
	ip6 = mtod(m, struct ip6_hdr *);
	plen = ntohs(ip6->ip6_plen);

	rc = ip6_hopopts_input(&m, &off, &plen, &rtalert);
	if (rc == 0) {
		__CPROVER_assert(m != NULL,
		    "success: the mbuf is not consumed");
		mc_check(m);
		__CPROVER_assert(off >= (int)sizeof(struct ip6_hdr) &&
		    off <= m->m_pkthdr.len,
		    "success: the header end lies inside the packet");
		mc_free(m);
	} else {
		__CPROVER_assert(m == NULL || m == g_freed,
		    "error: the mbuf is freed (header fetch or option loop)");
	}
	return (0);
}
