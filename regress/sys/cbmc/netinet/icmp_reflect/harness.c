/*
 * Harness: icmp_reflect() of sys/netinet/ip_icmp.c on an arbitrary IP
 * header of 5..15 words (ip_hl; 0..40 option bytes of arbitrary content)
 * followed by an ICMP message, on the contract models of the mbuf
 * library (common/mbufcontract.h), with the option walk under a loop
 * contract (loops).
 *
 * Caller guarantees (sys/netinet/ip_icmp.c):
 *  - icmp_input_if (the only caller with op != NULL, line ~582, for
 *    ICMP_ECHO, TSTAMP, MASKREQ, IREQ) runs m_pullup(m, hlen +
 *    min(icmplen, ICMP_ADVLENMAX)) with icmplen >= ICMP_MINLEN (8), so the
 *    IP header including all its options, and at least 8 bytes behind
 *    it, are contiguous in the first mbuf.  hlen is ip_hl << 2 (ip_input
 *    checked 5 <= ip_hl and hlen <= packet length).  M_PKTHDR is set.
 *    The harness: first mbuf of m_len = hlen + 8..16 bytes ending its
 *    object (so a read past the end is out of bounds), optionally a
 *    second mbuf of 1..8 bytes behind it, m_pkthdr.len their sum.  More
 *    payload would only lengthen the memmove of ip_stripoptions.
 *  - icmp_error (op == NULL, ia == NULL) hands over a packet made by
 *    icmp_do_error: ip_hl 5, hence no options.  The harness covers
 *    ip_hl 5 with op != NULL as well.
 *  - ia: both callers pass NULL (icmp_reflect looks the address up
 *    itself); the harness passes NULL or an address.
 *  - m_pkthdr.ph_loopcnt, ph_rtableid and the addresses are arbitrary.
 *
 * Models: ip_srcroute returns NULL or an mbuf of MLEN bytes of storage
 * whose m_len is (nhops + 1) * 4 + 4 for nhops 1..10 (12..48: save_rte
 * keeps olen <= 3 + 40 bytes, nhops = (olen - 3) / 4), arbitrary
 * content.  In the kernel m_resethdr, called before ip_srcroute in
 * icmp_reflect, deletes the mbuf's tags, so the saved route is gone and
 * ip_srcroute returns NULL; the model keeps the non-NULL case (the
 * function is also right for any other caller of this shape).
 * m_gethdr returns NULL or an mbuf with M_PKTHDR and MHLEN bytes of
 * storage, m_len 0.  m_resethdr does what the kernel's does except
 * deleting tags.  The options mbufs' data lies at the start of an
 * object of exactly their storage size, so a store past it is out of
 * bounds.  rtalloc returns NULL or a static route with a reference,
 * rtfree drops it (balance asserted); rtable_getsource, ifa_ifwithaddr
 * give any answer over static objects.  in_canforward and
 * ip_stripoptions are the kernel's bodies.
 *
 * Properties: no out-of-bounds access (the option walk, the copy into
 * the options mbuf, the padding stores), the options mbuf's m_len within
 * its storage and a multiple of 4, header rewritten as the reply needs
 * (ip_hl 5, dst = old src, ttl MAXTTL, lengths reduced by the options,
 * payload moved), route references balanced, no leak or double free: on
 * an error return the function freed m, otherwise the harness frees m
 * and the options mbuf (m_free(opts) as icmp_input_if does).
 */
#define MC_MAXLEN	76
#include "mbufcontract.h"

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

/* ghost state for the loop contract (target file "loops") */
u_char *g_end;		/* one past the last header byte */
u_char *g_obuf;		/* storage of the options mbuf */
int g_room;		/* options mbuf m_len at the start + option bytes it may take */

#include "ip_icmp.c"

static struct rtentry model_rt;
static int model_rt_refs;
static struct in_ifaddr model_ia;
static struct ifnet model_ifp;
static struct sockaddr_in model_src;

struct rtentry *
model_rtalloc(const struct sockaddr *dst, int flags, unsigned int tableid)
{
	if (mc_upto(1) == 0)
		return (NULL);
	model_rt.rt_flags = nondet_uint() &
	    (RTF_UP | RTF_GATEWAY | RTF_LOCAL | RTF_BROADCAST);
	model_rt.rt_ifa = &model_ia.ia_ifa;
	model_rt_refs++;
	return (&model_rt);
}

int
model_rtisvalid(struct rtentry *rt)
{
	return (rt != NULL && (rt->rt_flags & RTF_UP) != 0);
}

void
model_rtfree(struct rtentry *rt)
{
	if (rt != NULL) {
		__CPROVER_assert(rt == &model_rt && model_rt_refs > 0,
		    "rtfree: reference held");
		model_rt_refs--;
	}
}

struct sockaddr *
model_rtable_getsource(unsigned int rtableid, int af)
{
	if (mc_upto(1) == 0)
		return (NULL);
	model_src.sin_len = sizeof(model_src);
	model_src.sin_family = AF_INET;
	model_src.sin_addr.s_addr = nondet_uint();
	return (sintosa(&model_src));
}

struct ifaddr *
model_ifa_ifwithaddr(const struct sockaddr *sa, u_int tableid)
{
	if (mc_upto(1) == 0)
		return (NULL);
	model_ia.ia_ifa.ifa_ifp = &model_ifp;
	return (&model_ia.ia_ifa);
}

/* an mbuf whose data is the start of an object of size bytes */
static struct mbuf *
opts_new(int size, int flags)
{
	struct mbuf *m = CBMC_NEW(struct mbuf);
	u_char *buf = MC_ALLOC(size);
#ifdef NATIVE_SHIM_H
	int i;

	for (i = 0; i < size; i++)
		buf[i] = nondet_uchar();
#endif
	m->m_type = MT_HEADER;
	m->m_flags = flags;
	MC_BUF(m) = (caddr_t)buf;
	m->m_data = (caddr_t)buf;
	m->m_len = 0;
	g_obuf = buf;
	return (m);
}

struct mbuf *
model_ip_srcroute(struct mbuf *m0)
{
	struct mbuf *m;
	int nhops;

	if (mc_upto(1) == 0)
		return (NULL);
	m = opts_new(MLEN, 0);
	nhops = 1 + mc_upto(9);			/* 1..10 */
	m->m_len = (nhops + 1) * sizeof(struct in_addr) + 4;
	g_room = 48 + MAX_IPOPTLEN;	/* m_len <= 48 */
	return (m);
}

struct mbuf *
model_m_gethdr(int nowait, int type)
{
	struct mbuf *m;

	if (mc_upto(1) == 0)
		return (NULL);
	m = opts_new(MHLEN, M_PKTHDR);
	m->m_type = type;
	g_room = sizeof(struct in_addr) + MAX_IPOPTLEN;	/* m_len is set to 4 */
	return (m);
}

void
model_m_resethdr(struct mbuf *m)
{
	int len = m->m_pkthdr.len;
	u_int8_t loopcnt = m->m_pkthdr.ph_loopcnt;

	__CPROVER_assert(m->m_flags & M_PKTHDR, "m_resethdr: M_PKTHDR");
	m->m_flags &= (M_EXT|M_PKTHDR|M_EOR|M_EXTWR|M_ZEROIZE);
	memset(&m->m_pkthdr, 0, sizeof(m->m_pkthdr));
	m->m_pkthdr.pf.prio = IFQ_DEFPRIO;
	m->m_pkthdr.len = len;
	m->m_pkthdr.ph_loopcnt = loopcnt;
}

int
main(void)
{
	struct mbuf *m, *opts = NULL, **op;
	struct ip *ip;
	struct in_ifaddr *ia;
	u_char *data, first;
	struct in_addr osrc;
	int ihl, hlen, optlen, len1, len2, plen, ret;

	model_rt_refs = 0;			/* statics start arbitrary */
	ihl = 5 + mc_upto(10);			/* ip_hl 5..15 */
	hlen = ihl << 2;
	optlen = hlen - sizeof(struct ip);
	len1 = hlen + 8 + mc_upto(8);
	len2 = mc_upto(1) ? 1 + mc_upto(7) : 0;	/* a second mbuf or not */
	m = mc_seg(len1);
	m->m_flags = M_PKTHDR;
	if (len2 > 0)
		m->m_next = mc_seg(len2);
	m->m_pkthdr.len = len1 + len2;
	m->m_pkthdr.ph_loopcnt = mc_upto(M_MAXLOOP + 2);
	m->m_pkthdr.ph_rtableid = nondet_uint();
	m->m_pkthdr.pf.flags = nondet_uchar();
	ip = mtod(m, struct ip *);
	data = mtod(m, u_char *);
	g_end = data + hlen;
	ip->ip_v = IPVERSION;
	ip->ip_hl = ihl;
	osrc = ip->ip_src;
	first = data[hlen];			/* first byte behind the options */
	plen = m->m_pkthdr.len;

	op = mc_upto(1) ? &opts : NULL;
	ia = mc_upto(1) ? &model_ia : NULL;
	model_ia.ia_addr.sin_addr.s_addr = nondet_uint();
	model_ifp.if_flags = nondet_uint() & 0xffff;
	ret = icmp_reflect(m, op, ia);
	__CPROVER_assert(model_rt_refs == 0, "route references balanced");
	if (ret != 0)
		return (0);		/* icmp_reflect freed m */

	/* the reply's header */
	__CPROVER_assert(ip->ip_hl == (sizeof(struct ip) >> 2),
	    "reflect: ip_hl is 5");
	__CPROVER_assert(ip->ip_dst.s_addr == osrc.s_addr,
	    "reflect: dst is the old source");
	__CPROVER_assert(ip->ip_ttl == MAXTTL, "reflect: ttl");
	__CPROVER_assert(m->m_len == len1 - optlen, "reflect: m_len");
	__CPROVER_assert(m->m_pkthdr.len == plen - optlen,
	    "reflect: m_pkthdr.len");
#ifdef NATIVE_SHIM_H
	/* CBMC: memmove stores arbitrary bytes (stubflags), nothing to check */
	__CPROVER_assert(data[sizeof(struct ip)] == first,
	    "reflect: payload moved up");
#endif
	__CPROVER_assert((m->m_flags & (M_BCAST|M_MCAST)) == 0,
	    "reflect: flags");
	mc_check(m);
	mc_free(m);

	/* the options mbuf */
	if (op == NULL) {
		__CPROVER_assert(opts == NULL, "reflect: no options for op NULL");
		return (0);
	}
	if (optlen == 0)
		__CPROVER_assert(opts == NULL, "reflect: no options mbuf");
	if (opts != NULL) {
		__CPROVER_assert(opts->m_len >= 4 && opts->m_len <=
		    ((opts->m_flags & M_PKTHDR) ? MHLEN : MLEN),
		    "options mbuf: m_len within its storage");
		__CPROVER_assert(opts->m_len % 4 == 0,
		    "options mbuf: padded to 4");
		__CPROVER_assert(opts->m_len <= g_room + 3,
		    "options mbuf: at most route + options + pad");
		m_free(opts);		/* icmp_input_if */
	}
	return (0);
}
