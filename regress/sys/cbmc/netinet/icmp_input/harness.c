/*
 * Harness: icmp_input_if() of sys/netinet/ip_icmp.c on one IPv4 ICMP
 * packet, from the length checks to the end of the type switch, on the
 * mbuf contract models (common/mbufcontract.h).
 *
 * Why: icmp_input_if() takes the ICMP length from ip_len, pulls the
 * packet up, checksums icmplen bytes, and then reads the message by its
 * type: the error types (UNREACH, TIMXCEED, PARAMPROB, SOURCEQUENCH)
 * read the embedded IP header, ip_hl << 2 + 8 bytes of the offending
 * datagram, and hand it to the protocol's ctlinput; ECHO and TSTAMP
 * rewrite the message and reflect it; MASKREQ reads and writes
 * icmp_mask; REDIRECT reads the embedded destination and the gateway
 * address.  Each of them trusts the length checks before it.
 *
 * The packet: an IP header of 20 bytes (ip_hl 5, *offp 20, no
 * options) followed by 8..56 ICMP bytes of arbitrary content (an
 * embedded header of up to 40 option bytes plus its 8 bytes fits; a
 * 56 byte message is 8 + 20 + 28), 28..76 bytes in one or two mbufs,
 * the first of arbitrary length.  Every mbuf's data ends where its
 * object ends, so a read past m_len is out of bounds.  m_flags has
 * arbitrary M_BCAST and M_MCAST bits, ph_rtableid is arbitrary, the
 * IP addresses are arbitrary, ip_p is IPPROTO_ICMP.  The sysctls
 * icmpmaskrepl, icmpbmcastecho, icmptstamprepl, icmp_rediraccept,
 * icmp_redirtimeout and ip_forwarding are arbitrary (the defaults make
 * MASKREQ and REDIRECT unreachable).
 *
 * Caller contract (sys/netinet/ip_input.c, ipv4_check() 351-442 and
 * ip_input_if(), ip_deliver()): the header is contiguous at mtod(m)
 * (m_pullup to hlen, 356-380), ip_len stays in NETWORK order (409
 * reads it with ntohs; the field is not converted), is not below hlen
 * (416), the chain holds at least ip_len bytes (425) and is trimmed to
 * exactly ip_len (429-434).  So m_pkthdr.len == ntohs(ip_len) == the
 * packet length, icmplen = ip_len - hlen is 8..56 here (a shorter
 * packet is the icmplen < ICMP_MINLEN test).  ip_deliver() passes
 * *offp = hlen (ip_hl << 2); here 20 only: the options of the outer
 * header, and the offsets they move the message to, are not covered
 * (netinet/icmp_reflect proves icmp_reflect for any header length).
 * ifp is non-NULL (icmp_input() frees the packet when if_get fails),
 * proto IPPROTO_ICMP, af AF_INET, ns NULL.
 *
 * Models (icmp_input_if and iptime run as the kernel's):
 *   in4_cksum	NOT the real body.  icmp_input_if calls in4_cksum(m, 0,
 *		hlen, icmplen), not in_cksum.  The model asserts bytes
 *		[off, off + len) are readable in the chain (nxt is 0: no
 *		pseudo header) and returns an arbitrary sum, so a good
 *		and a bad sum are met.
 *   m_pullup	the contract model: the whole packet (i = hlen +
 *		min(icmplen, ICMP_ADVLENMAX) is at most the packet length
 *		here) is in the first mbuf afterwards, or NULL with the
 *		chain freed.
 *   inetsw, ip_protox	the real ones are in in_proto.c; the harness has
 *		a table of two protosw entries, one without pr_ctlinput
 *		(raw, icmp, igmp, ...), one with model_ctlinput (udp,
 *		tcp, ah, esp), and every protocol number maps to ONE of
 *		the two, chosen arbitrarily per run (a reduction: the
 *		256 entries are not independent here).
 *   model_ctlinput  what the real ctlinputs (udp_ctlinput,
 *		tcp_ctlinput, ipsec_common_ctlinput) read: they are called
 *		as (cmd, sa, rdomain, &icp->icmp_ip) and read the embedded
 *		IP header, the transport header at ip + (ip_hl << 2) (8
 *		bytes: ports, tcp seq) and, for PRC_MSGSIZE, the ICMP
 *		header in front of the pointer (tcp_ctlinput: icmp_nextmtu).
 *		The model asserts exactly that readable, the ip_hl >= 5 that
 *		icmp_input_if checked, cmd < PRC_NCMDS and a sockaddr_in.
 *   icmp_reflect	NOT the real body (netinet/icmp_reflect proves
 *		it).  Asserts what that proof assumes: M_PKTHDR, header
 *		(ip_hl << 2) plus ICMP_MINLEN bytes readable in the first
 *		mbuf, ip_hl 5, ia NULL.  Then fails (EHOSTUNREACH or ELOOP,
 *		the chain freed, as the real one) or succeeds with
 *		*op = NULL (no options, proved: "no options mbuf") and
 *		M_BCAST|M_MCAST cleared.
 *   icmp_send	asserts the header and ICMP_MINLEN bytes behind it
 *		writable (icp->icmp_cksum = 0), checks the chain and
 *		consumes it (ip_send).  opts is NULL here.
 *   m_free	the kernel's m_free accepts NULL (icmp_input_if calls it
 *		with the options mbuf that icmp_reflect left, NULL); the
 *		contract model asserts non-NULL, so the harness wraps it.
 *   rip_input	frees the chain, returns IPPROTO_DONE.
 *   rtredirect	asserts the three sockaddrs readable (sa_len, AF_INET,
 *		16 bytes); *rtp is NULL or the one route with a reference.
 *   rt_timer_add, rtfree, pfctlinput  the route reference is held and
 *		dropped (balance asserted); pfctlinput's sockaddr readable.
 *   ifaof_ifpforaddr  the sockaddr readable, NULL or the one address,
 *		with arbitrary mask, broadcast and destination.
 *   microtime	arbitrary time, 0 <= t < 2^40, usec < 10^6.
 * Not modelled, no body (NOBODY line): counters_inc (statistics).
 *
 * Reduced: CBMC checks icp->icmp_rtime, icp->icmp_ttime and
 * icp->icmp_mask as an access to the whole union icmp_dun (20 bytes at
 * offset 8; README, Known limits), which fails for the 20..27 byte
 * TSTAMP and 12..27 byte MASKREQ messages the length tests accept.
 * model_in4_cksum turns those two types into ECHO when icmplen < 28
 * (the packet bytes are arbitrary, this removes cases): the
 * ICMP_TSLEN and ICMP_MASKLEN tests are not covered.
 *
 * Left out: the outer header's options, packets above 56 ICMP bytes
 * (so the IPv6-in-IPv4 length test, needing 68, always frees),
 * pf (NPF 0), carp (NCARP 0), the real checksum.
 *
 * Asserted: no out-of-bounds access (the models above, the reads and
 * writes of ip_icmp.c, --bounds-check, --pointer-check), no leak and no
 * double free (--memory-leak-check, free checks of the models), the
 * return value is IPPROTO_DONE, route references balanced.
 *
 * Bug variants: mutant/ (ip_hl test of the embedded header one short),
 * mutant_advlen/ (ICMP_ADVLEN test one short), mutant_pullup/ (the
 * m_pullup length one short), mutant_redirect/ (the redirect length
 * test removed).  ICMP_ADVLENMIN one short is NOT a mutant: it is
 * redundant with ip_hl >= 5 and the ICMP_ADVLEN test (measured:
 * no failure).
 */
#define INET6
#define MC_MAXLEN	76	/* 20 byte IP header + 56 bytes of ICMP */
#define ICMP_EXTRA_MAX	48	/* ICMP bytes above ICMP_MINLEN */
#define m_free		mc_m_free
#define m_pullup	mc_m_pullup
#include "mbufcontract.h"
#undef m_free
#undef m_pullup

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/*
 * m_pullup(): what mc_m_pullup promises, without its byte copies (four
 * forall copies of up to 76 bytes at symbolic offsets were most of
 * 3.6 million variables): NULL and the chain freed if the packet is
 * shorter than len or on an arbitrary failure; m itself if it already
 * holds len bytes; otherwise a NEW chain, an arbitrary first length in
 * [len, total], the old mbufs freed.  The new data are fresh arbitrary
 * bytes, not copies, except the 20 bytes of struct ip the harness
 * sets (the packet's content is arbitrary and nothing else here
 * compares it with the old; a pointer kept across the call is a use
 * after free, as with the contract model).
 */
struct mbuf *
m_pullup(struct mbuf *m, int len)
{
	struct mbuf *n;
	int total, first;

	__CPROVER_assert(m != NULL && len >= 0, "m_pullup: arguments");
	total = mc_total(m);
	if (len > total || mc_fails()) {
		m_freem(m);
		return (NULL);
	}
	if (m->m_len >= len)
		return (m);
	first = len + mc_upto(total - len);
	n = mc_seg(first);
	n->m_flags = m->m_flags;
	n->m_pkthdr = m->m_pkthdr;
	if (len >= (int)sizeof(struct ip) && m->m_len >= (int)sizeof(struct ip))
		*mtod(n, struct ip *) = *mtod(m, struct ip *);
	if (first < total)
		n->m_next = mc_seg(total - first);
	m_freem(m);
	return (n);
}

/* the kernel's m_free(NULL) is a no-op; the contract model asserts */
struct mbuf *
m_free(struct mbuf *m)
{
	if (m == NULL)
		return (NULL);
	return (mc_m_free(m));
}

#include <sys/socket.h>
#include <sys/protosw.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/*
 * What the protocols' ctlinput functions read of &icp->icmp_ip (see the
 * header comment).  The caller promises the embedded header and 8
 * bytes behind it are in the packet: icmplen >= ICMP_ADVLEN(icp).
 */
static void
model_ctlinput(int cmd, struct sockaddr *sa, u_int rdomain, void *v)
{
	struct ip *ip = v;
	int hl;

	__CPROVER_assert(cmd >= 0 && cmd < PRC_NCMDS, "ctlinput: cmd");
	__CPROVER_assert(sa != NULL && __CPROVER_r_ok(sa, sizeof(struct sockaddr_in)) &&
	    sa->sa_family == AF_INET && sa->sa_len == sizeof(struct sockaddr_in),
	    "ctlinput: sockaddr_in readable");
	__CPROVER_assert(__CPROVER_r_ok(v, sizeof(struct ip)),
	    "ctlinput: embedded IP header readable");
	hl = ip->ip_hl << 2;
	__CPROVER_assert(hl >= (int)sizeof(struct ip),
	    "ctlinput: embedded ip_hl at least 5");
	__CPROVER_assert(__CPROVER_r_ok(v, hl + 8),
	    "ctlinput: transport header readable");
	/* tcp_ctlinput reads icmp_nextmtu: the icmp header before v */
	__CPROVER_assert(__CPROVER_r_ok((char *)v - offsetof(struct icmp, icmp_ip),
	    offsetof(struct icmp, icmp_ip) + hl + 8),
	    "ctlinput: icmp header readable");
}

const struct protosw inetsw[2] = {
	{ .pr_ctlinput = NULL },
	{ .pr_ctlinput = model_ctlinput },
};
u_char ip_protox[IPPROTO_MAX];

#include "ip_icmp.c"

#define NONDET_TIME()	(nondet_long() & 0xffffffffffL)

int ip_forwarding;		/* the real one is in ip_input.c */

static struct ifnet model_ifp;
static struct in_ifaddr model_ia;
static struct rtentry model_rt;
static int model_rt_refs;

/* the chain holds n bytes behind off, all readable (the real sum reads them) */
static void
check_range(struct mbuf *m, int off, int n)
{
	struct mbuf *c;

	for (c = m; c != NULL && off >= c->m_len; c = c->m_next)
		off -= c->m_len;
	for (; c != NULL && n > 0; c = c->m_next) {
		int k = c->m_len - off;

		if (k > n)
			k = n;
		if (k > 0)
			__CPROVER_assert(__CPROVER_r_ok(mtod(c, u_char *) + off, k),
			    "cksum: bytes readable");
		n -= k;
		off = 0;
	}
	__CPROVER_assert(n == 0, "cksum: chain shorter than off + len");
}

int
model_in4_cksum(struct mbuf *m, u_int8_t nxt, int off, int len)
{
	__CPROVER_assert(m != NULL && off >= 0 && len >= 0, "in4_cksum: args");
	__CPROVER_assert(nxt == 0, "in4_cksum: no pseudo header expected");
	/*
	 * Reduction (union limit, see the header comment): a TSTAMP or
	 * MASKREQ message of 12..27 ICMP bytes is made an ECHO.  Here the
	 * packet is in the first mbuf (icmp_input_if pulled it up).
	 */
	if (off == (int)sizeof(struct ip) && len >= ICMP_MINLEN && len < 28 &&
	    m->m_len >= off + len) {
		u_char *tp = mtod(m, u_char *) + off;

		if (tp[0] == ICMP_TSTAMP || tp[0] == ICMP_MASKREQ)
			tp[0] = ICMP_ECHO;
	}
	check_range(m, off, len);
	return (nondet_int());
}

/* icmp_reflect(): see the header comment */
int
model_icmp_reflect(struct mbuf *m, struct mbuf **op, struct in_ifaddr *ia)
{
	struct ip *ip = mtod(m, struct ip *);
	int hlen;

	__CPROVER_assert(m->m_flags & M_PKTHDR, "icmp_reflect: M_PKTHDR");
	__CPROVER_assert(m->m_len >= (int)sizeof(struct ip) &&
	    __CPROVER_r_ok(ip, sizeof(struct ip)), "icmp_reflect: IP header");
	hlen = ip->ip_hl << 2;
	__CPROVER_assert(hlen == (int)sizeof(struct ip),
	    "icmp_reflect: harness has no outer options");
	__CPROVER_assert(m->m_len >= hlen + ICMP_MINLEN &&
	    __CPROVER_r_ok(ip, hlen + ICMP_MINLEN),
	    "icmp_reflect: ICMP header contiguous");
	__CPROVER_assert(ia == NULL, "icmp_reflect: ia");
	mc_check(m);
	if (nondet_bool()) {
		m_freem(m);		/* bad source or loop count */
		return (nondet_bool() ? EHOSTUNREACH : ELOOP);
	}
	m->m_flags &= ~(M_BCAST | M_MCAST);
	if (op != NULL)
		*op = NULL;
	return (0);
}

void
model_icmp_send(struct mbuf *m, struct mbuf *opts)
{
	struct ip *ip = mtod(m, struct ip *);
	int hlen;

	__CPROVER_assert(m->m_len >= (int)sizeof(struct ip) &&
	    __CPROVER_r_ok(ip, sizeof(struct ip)), "icmp_send: IP header");
	hlen = ip->ip_hl << 2;
	__CPROVER_assert(m->m_len >= hlen + ICMP_MINLEN &&
	    __CPROVER_w_ok(mtod(m, u_char *) + hlen, ICMP_MINLEN),
	    "icmp_send: ICMP header writable");
	__CPROVER_assert(opts == NULL, "icmp_send: opts");
	mc_check(m);
	m_freem(m);
}

int
model_rip_input(struct mbuf **mp, int *offp, int proto, int af,
    struct netstack *ns)
{
	m_freem(*mp);
	return (IPPROTO_DONE);
}

#define check_sa(sa, what)						\
	__CPROVER_assert((sa) != NULL &&				\
	    __CPROVER_r_ok((sa), sizeof(struct sockaddr_in)) &&		\
	    (sa)->sa_family == AF_INET &&				\
	    (sa)->sa_len == sizeof(struct sockaddr_in), what)

void
model_rtredirect(struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *src, struct rtentry **rtp, unsigned int rdomain)
{
	check_sa(dst, "rtredirect: dst readable");
	check_sa(gateway, "rtredirect: gateway readable");
	check_sa(src, "rtredirect: src readable");
	if (rtp != NULL && nondet_bool()) {
		model_rt_refs++;
		*rtp = &model_rt;
	}
}

int
model_rt_timer_add(struct rtentry *rt, struct rttimer_queue *queue,
    u_int rdomain)
{
	__CPROVER_assert(rt == &model_rt && model_rt_refs > 0,
	    "rt_timer_add: reference held");
	__CPROVER_assert(queue == &icmp_redirect_timeout_q, "rt_timer_add: queue");
	return (nondet_bool() ? 0 : ENOBUFS);
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

void
model_pfctlinput(int cmd, struct sockaddr *sa)
{
	check_sa(sa, "pfctlinput: sockaddr readable");
}

struct ifaddr *
model_ifaof_ifpforaddr(const struct sockaddr *addr, struct ifnet *ifp)
{
	check_sa(addr, "ifaof_ifpforaddr: address readable");
	__CPROVER_assert(ifp == &model_ifp, "ifaof_ifpforaddr: ifp");
	if (mc_upto(1) == 0)
		return (NULL);
	return (&model_ia.ia_ifa);
}

void
model_microtime(struct timeval *tv)
{
	unsigned int us = nondet_uint() & 0xfffff;

	tv->tv_sec = NONDET_TIME();
	tv->tv_usec = us > 999999 ? 999999 : us;
}

int
main(void)
{
	struct mbuf *m;
	struct ip *ip;
	int len, off, ret;

	model_rt_refs = 0;			/* statics start arbitrary */
	model_ifp.if_index = 1;
	model_ifp.if_flags = nondet_uint() & 0xffff;
	model_ia.ia_sockmask.sin_addr.s_addr = nondet_uint();
	model_ia.ia_broadaddr.sin_addr.s_addr = nondet_uint();
	model_ia.ia_dstaddr.sin_addr.s_addr = nondet_uint();
	icmpmaskrepl = mc_upto(1);
	icmpbmcastecho = mc_upto(1);
	icmptstamprepl = mc_upto(1);
	icmp_rediraccept = mc_upto(1);
	icmp_redirtimeout = mc_upto(1) ? 10 * 60 : 0;
	ip_forwarding = mc_upto(1);
	memset(ip_protox, mc_upto(1), sizeof(ip_protox));

	len = sizeof(struct ip) + ICMP_MINLEN + mc_upto(ICMP_EXTRA_MAX);
	m = mc_build(len);
	/* ipv4_check: the IP header is contiguous */
	if (m->m_len < sizeof(struct ip)) {
		m = m_pullup(m, sizeof(struct ip));
		if (m == NULL)
			return (0);		/* m_pullup freed the chain */
	}
	if (mc_upto(1))
		m->m_flags |= M_BCAST;
	if (mc_upto(1))
		m->m_flags |= M_MCAST;
	m->m_pkthdr.ph_rtableid = nondet_ushort();
	ip = mtod(m, struct ip *);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_len = htons(len);		/* ip_input.c:409-434 */
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_src.s_addr = nondet_uint();
	ip->ip_dst.s_addr = nondet_uint();

	off = sizeof(struct ip);
	ret = icmp_input_if(&model_ifp, &m, &off, IPPROTO_ICMP, AF_INET, NULL);
	__CPROVER_assert(ret == IPPROTO_DONE, "icmp_input_if: IPPROTO_DONE");
	__CPROVER_assert(model_rt_refs == 0, "route references balanced");
	return (0);
}
