/*
 * Harness: route6_input() of sys/netinet6/route6.c, the routing header,
 * on an IPv6 packet of 40 bytes followed by a routing header of 8 to 32
 * bytes with arbitrary content, in one or two mbufs with the IPv6 header
 * in the first (common/mbufcontract.h).  route6.c is included, so the
 * real body runs; ip6_exthdr_get (netinet/ip6.h, inline) and m_pulldown
 * are real or contract models as the caller's mbuf code is; icmp6_error
 * consumes the mbuf (model_icmp6_error), counters_inc has no body.
 *
 * Caller contract (ip6_input and the protocol dispatch): the IPv6 header
 * lies contiguous in the first mbuf, *offp is 40 on entry, and the packet
 * has been trimmed to 40 + ip6_plen bytes.  The harness makes ip6_plen the
 * header length, so the packet is the whole of what is there.
 *
 * The header's length byte (ip6r_len) is arbitrary.  route6_input reads
 * the four byte fixed part of the header (the ip6_rthdr) and never the
 * rest of it, so a header that claims more than the packet holds is not
 * an out-of-bounds access in route6_input: it returns the next header with
 * *offp past the end of the packet, and the protocol after it must check
 * its own bounds (not part of this proof).  The packet's data ends where
 * its objects end, so a read past the last byte of the packet is out of
 * bounds.
 *
 * MAXHDR = 32 stands for the largest routing header the proof covers (the
 * header is a multiple of 8 bytes, 8..32 here).
 *
 * Properties: no out-of-bounds access for arbitrary header bytes; no leak
 * and no double free (icmp6_error consumes the mbuf on the unknown-type,
 * nonzero segments left path, m_pulldown frees it when the fixed part is
 * not in the packet, and the harness frees it on success); on a return of
 * a next header the mbuf is still owned, its chain is well formed, and
 * *offp equals 40 plus the header's length, 8 * (ip6r_len + 1), which the
 * harness reads from the packet before the call.
 *
 * and the ICMPv6 pointer of a Parameter Problem is the offset of
 * ip6r_type, 42 (model_icmp6_error).
 *
 * mutant_prefix/ is the source before the pointer was computed from the
 * offset: when ip6_exthdr_get (m_pulldown) returns the fixed part in the
 * next mbuf (kern/uipc_mbuf2.c, the leading-space case), it subtracted
 * pointers into two mbufs: VIOLATED.  mutant/ fetches the fixed part one
 * byte short: VIOLATED on ip6r_segleft.
 */
#define INET6		1
#define MAXHDR		32
#define MC_MAXLEN	(40 + MAXHDR)	/* 40 = sizeof (struct ip6_hdr) */
#define MC_COPY_LOOP
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include "mbufcontract.h"

#include <sys/protosw.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include "route6.c"

/* The mbuf icmp6_error consumed on its error return, or NULL. */
struct mbuf *g_freed;

/*
 * Replacement for icmp6_error: consumes m, as the real function does
 * (it frees m or sends a new packet built from it).  g_freed keeps the
 * pointer that route6_input still holds in *mp on that path.
 */
void
model_icmp6_error(struct mbuf *m, int type, int code, int param)
{
	/* the pointer names ip6r_type in the packet: 40 + 2 */
	__CPROVER_assert(type != ICMP6_PARAM_PROB ||
	    param == 40 + offsetof(struct ip6_rthdr, ip6r_type),
	    "icmp6_error: pointer is the offset of ip6r_type");
	g_freed = m;
	m_freem(m);
}

/*
 * The packet of len bytes after the caller's pullup of the IPv6 header:
 * the first mbuf holds at least the 40 header bytes, the rest is one more
 * mbuf or none.  Built directly, as in netinet6/dest6_input.
 */
static struct mbuf *
build_packet(int len)
{
	struct mbuf *m;
	int first = sizeof(struct ip6_hdr) +
	    mc_upto(len - sizeof(struct ip6_hdr));

	m = mc_seg(first);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = len;
	if (first < len)
		m->m_next = mc_seg(len - first);
	return (m);
}

/* the byte at packet offset off, which lies inside the packet */
static u_int8_t
pkt_byte(struct mbuf *m, int off)
{
	if (off < m->m_len)
		return (mtod(m, u_int8_t *)[off]);
	return (mtod(m->m_next, u_int8_t *)[off - m->m_len]);
}

int
main(void)
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	int off = sizeof(struct ip6_hdr), hlen, want, rc;

	/* the packet: IPv6 header, then a routing header of 8..32 bytes */
	hlen = 8 * (mc_upto(MAXHDR / 8 - 1) + 1);
	m = build_packet(sizeof(struct ip6_hdr) + hlen);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(hlen);

	/* the length the header asks for, as route6_input will read it */
	want = sizeof(struct ip6_hdr) +
	    8 * (pkt_byte(m, sizeof(struct ip6_hdr) + 1) + 1);

	rc = route6_input(&m, &off, IPPROTO_ROUTING, AF_INET6, NULL);
	if (rc != IPPROTO_DONE) {
		__CPROVER_assert(m != NULL,
		    "success: the mbuf is still owned");
		__CPROVER_assert(off == want,
		    "success: *offp is 40 plus the header length");
		mc_check(m);
		mc_free(m);
	} else {
		__CPROVER_assert(m == NULL || m == g_freed,
		    "error: the mbuf is freed (fixed part not in the packet, or icmp6_error)");
	}
	return (0);
}
