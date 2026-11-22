/*
 * Harness: dest6_input() of sys/netinet6/dest6.c, the destination options
 * header, on an IPv6 packet of 40 bytes followed by a destination options
 * header of 8 to 32 bytes with arbitrary content, in one or two mbufs
 * (common/mbufcontract.h).  The option walk calls ip6_unknown_opt() of
 * sys/netinet6/ip6_input.c for unknown options; that function is real
 * (listed in "keep"), and what it calls below it is modelled: icmp6_error
 * consumes the mbuf (model_icmp6_error), m_freem and m_pulldown are the
 * contract models, counters_inc has no body.
 *
 * Caller contract (ip6_input): the IPv6 header lies contiguous in the
 * first mbuf (the caller's m_pullup), *offp is 40 on entry, and the
 * packet has been trimmed to 40 + ip6_plen bytes, so ip6_plen is the
 * header length here.  dest6_input reads no field of the IPv6 header
 * and no ip6_plen; the harness sets ip6_plen to the header length only
 * to keep the packet as ip6_input leaves it.
 *
 * The header's length byte (ip6d_len) is arbitrary.  When it asks for
 * more than the packet holds, ip6_exthdr_get's m_pulldown fails and
 * the function returns IPPROTO_DONE with the mbuf freed; when it asks
 * for less, the option walk ends inside the packet.  The packet's data
 * ends where its objects end, so a read past the last byte of the
 * packet is out of bounds, and a read past the header is out of bounds
 * when the header ends where the packet ends.
 *
 * MAXHDR = 32 stands for the largest destination options header the
 * proof covers (the header is a multiple of 8 bytes, 8..32 here).
 *
 * Properties: no out-of-bounds access for arbitrary option bytes (the
 * option walk is bounded by "unwindset" in opts: it consumes at least one
 * byte an iteration, so 31 iterations cover 30 option bytes); no leak and
 * no double free (icmp6_error consumes the mbuf on its error paths,
 * m_freemp on the others, and the harness frees it on success); on a
 * return of a next header the mbuf is still owned, its chain is well
 * formed, and *offp equals 40 plus the header's length, 8 * (ip6d_len +
 * 1), which the harness reads from the packet before the call.
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

#include "ip6_input.c"
#include "dest6.c"

/*
 * ip6_protox and inet6sw: declared and used by ip6_input.c, which is
 * compiled here (ip6_init reads them); no code on the path reads them.
 */
u_char ip6_protox[IPPROTO_MAX];
const struct protosw inet6sw[1];

/* The mbuf icmp6_error consumed on its error return, or NULL. */
struct mbuf *g_freed;
/* ghost for the loop invariant ("loops"): the mbuf the caller holds */
struct mbuf *g_m;

/*
 * Replacement for icmp6_error: consumes m, as the real function does
 * (it frees m or sends a new packet built from it).  g_freed keeps the
 * pointer that dest6_input still holds in *mp on that path.
 */
void
model_icmp6_error(struct mbuf *m, int type, int code, int param)
{
	g_freed = m;
	m_freem(m);
}

/*
 * The packet of len bytes after the caller's pullup of the IPv6 header
 * (ip6_input): the first mbuf holds at least the 40 header bytes, the
 * rest is one more mbuf or none.  Built directly, not with mc_build and
 * m_pullup: the pullup's byte copy of up to 72 bytes costs more than the
 * proof of the header.
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

	/* the packet: IPv6 header, then a header of 8..32 bytes */
	hlen = 8 * (mc_upto(MAXHDR / 8 - 1) + 1);
	m = build_packet(sizeof(struct ip6_hdr) + hlen);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(hlen);
	g_m = m;

	/* the length the header asks for, as dest6_input will read it */
	want = sizeof(struct ip6_hdr) +
	    8 * (pkt_byte(m, sizeof(struct ip6_hdr) + 1) + 1);

	rc = dest6_input(&m, &off, IPPROTO_DSTOPTS, AF_INET6, NULL);
	if (rc != IPPROTO_DONE) {
		__CPROVER_assert(m != NULL,
		    "success: the mbuf is still owned");
		__CPROVER_assert(off == want,
		    "success: *offp is 40 plus the header length");
		mc_check(m);
		mc_free(m);
	} else {
		__CPROVER_assert(m == NULL || m == g_freed,
		    "error: the mbuf is freed (header fetch, option check, or icmp6_error)");
	}
	return (0);
}
