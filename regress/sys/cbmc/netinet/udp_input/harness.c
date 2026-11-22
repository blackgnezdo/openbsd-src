/*
 * Harness: udp_input() of sys/netinet/udp_usrreq.c on one unicast UDP
 * datagram, IPv4 or IPv6, from the header fetch to the delivery
 * decision, on the mbuf contract models (common/mbufcontract.h).
 *
 * Why: udp_input() takes the UDP length from the packet, compares it
 * with what the IP layer left in the mbuf chain, trims the chain
 * (m_adj, IPv4 only), checksums len bytes behind the header
 * (in4_cksum / in6_cksum), looks the socket up, and either answers with
 * an ICMP port unreachable or strips the headers (udp_sbappend: m_adj
 * by iphlen + 8) and queues the datagram with sbappendaddr().  Every
 * one of those steps trusts the length checks before it.
 *
 * The packet: an IP header (IPv4: 20 bytes, *offp 20; IPv6: 40 bytes,
 * *offp 40, no extension header) followed by 0..16 UDP bytes of
 * arbitrary content (header and data; 0..7 bytes is a truncated UDP
 * header), one or two mbufs, the first of arbitrary length.  Every
 * mbuf's data ends where its object ends, so a read past m_len is out
 * of bounds.  m_pkthdr.csum_flags is arbitrary (checksum already
 * verified, known bad, or to be computed), ph_rtableid arbitrary.  The
 * mbuf has neither M_BCAST nor M_MCAST: the multicast/broadcast
 * delivery loop is not covered.
 *
 * Caller contract (af = AF_INET):  sys/netinet/ip_input.c ipv4_check()
 * 351-442: the header is contiguous at mtod(m) (m_pullup to hlen,
 * 356-380), ip_len is in network order (409) and not below hlen (416),
 * the chain holds at least ip_len bytes (425) and is trimmed to exactly
 * ip_len (429-434).  So m_pkthdr.len == ntohs(ip_len) == the packet
 * length here, and ip_hl is 5 (offp 20).  ip_p is IPPROTO_UDP.
 * Caller contract (af = AF_INET6): sys/netinet6/ip6_input.c 266
 * (m_pullup to the IPv6 header) and ip6_hbhchcheck() 650-715: plen is
 * ntohs(ip6_plen), the chain holds at least 40 + plen bytes (702) and
 * is trimmed to exactly 40 + plen (707-714), so ip6_plen == total - 40
 * and m_pkthdr.len == 40 + plen (including plen 0).  Jumbograms
 * (ip6_plen 0 with more than 65535 bytes) need a packet far above the
 * bound and are not covered.  ip6_nxt is IPPROTO_UDP.  ip_deliver()
 * passes proto IPPROTO_UDP, af, and ns NULL (the netstack is not read
 * by anything left in the path).
 *
 * Models (every one of them; udp_input, udp_sbappend and the real
 * mbuf-independent code run as the kernel's):
 *   in4_cksum / in6_cksum  NOT the real bodies (the real sum loops over
 *		the chain).  They assert what the real ones need: the
 *		pseudo header's source (IPv4: m_len >= 20, off >= 20; IPv6:
 *		m_len >= 40, m_pkthdr.len >= off + len, the kernel panics
 *		otherwise) and that bytes [off, off + len) are readable in
 *		the chain.  The result is arbitrary, so both a good and a
 *		bad sum are met.
 *   in_pcblookup, in_pcblookup_listen, in6_pcblookup,
 *   in6_pcblookup_listen	NULL or the one inpcb with a reference
 *		(counted); the inpcb has a socket, arbitrary inp_flags, TTL
 *		limit, so_options, so_state, no upcall (encapsulation not
 *		covered).  The table is not read.
 *   in_pcbunref	NULL ok, asserts a reference is held, drops it;
 *		the object is static.  References are asserted balanced.
 *   icmp_error, icmp6_error	assert the original header is readable
 *		in the first mbuf and the chain is well formed, free the
 *		packet (the real ones send a reply built from a copy).
 *   sbappendaddr	asserts the address is readable for sa_len, the
 *		chain well formed with M_PKTHDR and the socket buffer
 *		mutex held; then arbitrarily refuses (0: the caller frees
 *		m and opts) or takes ownership of m and opts (frees them).
 *   sbcreatecontrol	NULL or one empty mbuf.  ip_savecontrol,
 *		ip6_savecontrol	assert their header readable; set *mp to
 *		NULL or one empty mbuf.
 *   in6_recoverscope	asserts the 16 address bytes readable.
 *   mtx_enter/mtx_leave	track the owner (MUTEX_ASSERT_LOCKED).
 * Not modelled, no body (NOBODY line): counters_inc (statistics),
 * sorwakeup (wakes the reader), soassertlocked_readonly (assertion).
 *
 * Left out: the multicast/broadcast loop, IPsec (udpencap and the
 * policy check), PIPEX, pf (NPF 0), inp_upcall (vxlan, wireguard, ...:
 * NULL), IPv6 jumbograms.
 *
 * Asserted: no out-of-bounds access (contract models, models above,
 * reads of udp_usrreq.c), no leak and no double free
 * (--memory-leak-check, free checks), the return value is
 * IPPROTO_DONE, inpcb references balanced.
 *
 * Bug variant: mutant/udp_usrreq.c accepts a UDP length one larger than
 * the data (see the README entry).
 */
#define INET6
#define MC_MAXLEN	56	/* 40 byte IPv6 header + 16 bytes of UDP */
#define UDP_EXTRA_MAX	16
#include "mbufcontract.h"

#include "udp_usrreq.c"

static struct ifnet model_ifp;
static struct socket model_so;
static struct inpcb model_inp;
static int model_refs;

/* the chain holds n bytes behind off, all readable (the real sums read them) */
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
	if (nxt != 0) {
		__CPROVER_assert(off >= (int)sizeof(struct ipovly),
		    "in4_cksum: offset too short");
		__CPROVER_assert(m->m_len >= (int)sizeof(struct ip),
		    "in4_cksum: pseudo header contiguous");
		__CPROVER_assert(__CPROVER_r_ok(mtod(m, u_char *),
		    sizeof(struct ip)), "in4_cksum: pseudo header readable");
	}
	check_range(m, off, len);
	return (nondet_int());
}

int
model_in6_cksum(struct mbuf *m, uint8_t nxt, uint32_t off, uint32_t len)
{
	__CPROVER_assert(m != NULL && off < 0x10000 && len < 0x10000,
	    "in6_cksum: args");
	__CPROVER_assert(m->m_pkthdr.len >= (int)(off + len),
	    "in6_cksum: mbuf len < off + len (panic)");
	if (nxt != 0) {
		__CPROVER_assert(m->m_len >= (int)sizeof(struct ip6_hdr),
		    "in6_cksum: pseudo header contiguous");
		__CPROVER_assert(__CPROVER_r_ok(mtod(m, u_char *),
		    sizeof(struct ip6_hdr)), "in6_cksum: pseudo header readable");
	}
	check_range(m, off, len);
	return (nondet_int());
}

/* the pcb lookups: NULL or the one pcb, with a reference */
static struct inpcb *
model_lookup(void)
{
	if (mc_upto(1) == 0)
		return (NULL);
	model_refs++;
	return (&model_inp);
}

struct inpcb *
model_in_pcblookup(struct inpcbtable *table, struct in_addr faddr, u_int fport,
    struct in_addr laddr, u_int lport, u_int rtable)
{
	return (model_lookup());
}

struct inpcb *
model_in_pcblookup_listen(struct inpcbtable *table, struct in_addr laddr,
    u_int lport, struct mbuf *m, u_int rtable)
{
	__CPROVER_assert(m != NULL, "in_pcblookup_listen: mbuf");
	return (model_lookup());
}

struct inpcb *
model_in6_pcblookup(struct inpcbtable *table, const struct in6_addr *faddr,
    u_int fport, const struct in6_addr *laddr, u_int lport, u_int rtable)
{
	__CPROVER_assert(__CPROVER_r_ok(faddr, sizeof(*faddr)) &&
	    __CPROVER_r_ok(laddr, sizeof(*laddr)), "in6_pcblookup: addresses");
	return (model_lookup());
}

struct inpcb *
model_in6_pcblookup_listen(struct inpcbtable *table, struct in6_addr *laddr,
    u_int lport, struct mbuf *m, u_int rtable)
{
	__CPROVER_assert(m != NULL && __CPROVER_r_ok(laddr, sizeof(*laddr)),
	    "in6_pcblookup_listen: arguments");
	return (model_lookup());
}

void
model_in_pcbunref(struct inpcb *inp)
{
	if (inp == NULL)
		return;
	__CPROVER_assert(inp == &model_inp && model_refs > 0,
	    "in_pcbunref: reference held");
	model_refs--;
}

void
model_in6_recoverscope(struct sockaddr_in6 *sin6, const struct in6_addr *in6)
{
	__CPROVER_assert(__CPROVER_r_ok(in6, sizeof(*in6)),
	    "in6_recoverscope: address readable");
}

/* the original packet is quoted: header readable, chain well formed */
void
model_icmp_error(struct mbuf *n, int type, int code, u_int32_t dest,
    int destmtu)
{
	__CPROVER_assert(n != NULL && (n->m_flags & M_PKTHDR),
	    "icmp_error: packet header");
	__CPROVER_assert(n->m_len >= (int)sizeof(struct ip) &&
	    __CPROVER_r_ok(mtod(n, u_char *), sizeof(struct ip)),
	    "icmp_error: IP header readable");
	mc_check(n);
	m_freem(n);
}

void
model_icmp6_error(struct mbuf *m, int type, int code, int param)
{
	__CPROVER_assert(m != NULL && (m->m_flags & M_PKTHDR),
	    "icmp6_error: packet header");
	__CPROVER_assert(m->m_len >= (int)sizeof(struct ip6_hdr) &&
	    __CPROVER_r_ok(mtod(m, u_char *), sizeof(struct ip6_hdr)),
	    "icmp6_error: IPv6 header readable");
	mc_check(m);
	m_freem(m);
}

/* socket layer: a datagram with its address, queued or refused */
int
model_sbappendaddr(struct sockbuf *sb, const struct sockaddr *asa,
    struct mbuf *m0, struct mbuf *control)
{
	__CPROVER_assert(sb == &model_so.so_rcv, "sbappendaddr: socket buffer");
	__CPROVER_assert(mtx_owner(&sb->sb_mtx) == mtx_curcpu(),
	    "sbappendaddr: sb_mtx held");
	__CPROVER_assert(__CPROVER_r_ok(asa, asa->sa_len) && asa->sa_len > 0,
	    "sbappendaddr: address readable");
	__CPROVER_assert(m0 != NULL && (m0->m_flags & M_PKTHDR),
	    "sbappendaddr: packet header");
	mc_check(m0);
	if (control != NULL)
		mc_check(control);
	if (nondet_bool())
		return (0);	/* socket full: the caller frees both */
	m_freem(control);
	m_freem(m0);
	return (1);
}

struct mbuf *
model_sbcreatecontrol(const void *p, size_t size, int type, int level)
{
	__CPROVER_assert(__CPROVER_r_ok(p, size), "sbcreatecontrol: data");
	if (mc_upto(1) == 0)
		return (NULL);
	return (mc_seg(0));
}

void
model_ip_savecontrol(struct inpcb *inp, struct mbuf **mp, struct ip *ip,
    struct mbuf *m)
{
	__CPROVER_assert(__CPROVER_r_ok(ip, sizeof(*ip)),
	    "ip_savecontrol: header readable");
	if (mc_upto(1))
		*mp = mc_seg(0);
}

void
model_ip6_savecontrol(struct inpcb *inp, struct mbuf *m, struct mbuf **mp)
{
	__CPROVER_assert(__CPROVER_r_ok(mtod(m, u_char *),
	    sizeof(struct ip6_hdr)), "ip6_savecontrol: header readable");
	if (mc_upto(1))
		*mp = mc_seg(0);
}

/* mutex(9): the owner field MUTEX_ASSERT_LOCKED and the model read */
void
model_mtx_enter(struct mutex *mtx)
{
	__CPROVER_assert(mtx->mtx_owner == 0, "mtx_enter: not held");
	mtx->mtx_owner = mtx_curcpu();
}

void
model_mtx_leave(struct mutex *mtx)
{
	__CPROVER_assert(mtx_owner(mtx) == mtx_curcpu(), "mtx_leave: held");
	mtx->mtx_owner = 0;
}

int
main(void)
{
	struct mbuf *m;
	struct ip *ip;
	struct ip6_hdr *ip6;
	int len, off, hl, af, ret;

	model_ifp.if_index = 1;
	model_inp.inp_socket = &model_so;
	model_inp.inp_flags = nondet_int();
	model_inp.inp_ip_minttl = nondet_uchar();
	model_inp.inp_upcall = NULL;
	model_so.so_options = nondet_short();
	model_so.so_state = nondet_uint();

	af = mc_upto(1) ? AF_INET6 : AF_INET;
	hl = af == AF_INET ? sizeof(struct ip) : sizeof(struct ip6_hdr);
	len = hl + mc_upto(UDP_EXTRA_MAX);
	m = mc_build(len);
	/* ipv4_check / ip6_input: the IP header is contiguous */
	if (m->m_len < hl) {
		m = m_pullup(m, hl);
		if (m == NULL)
			goto out;	/* m_pullup freed the chain */
	}
	m->m_pkthdr.csum_flags = nondet_ushort();
	m->m_pkthdr.ph_rtableid = nondet_ushort();
	if (af == AF_INET) {
		ip = mtod(m, struct ip *);
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(struct ip) >> 2;
		ip->ip_len = htons(len);	/* ip_input.c:409-436 */
		ip->ip_p = IPPROTO_UDP;
	} else {
		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_vfc = IPV6_VERSION;
		ip6->ip6_plen = htons(len - hl);	/* ip6_input.c:702-715 */
		ip6->ip6_nxt = IPPROTO_UDP;
	}

	off = hl;
	ret = udp_input(&m, &off, IPPROTO_UDP, af, NULL);
	__CPROVER_assert(ret == IPPROTO_DONE, "udp_input: IPPROTO_DONE");
	__CPROVER_assert(model_refs == 0, "inpcb references balanced");
 out:
	return (0);
}
