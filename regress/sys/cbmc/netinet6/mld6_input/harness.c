/*
 * Harness: mld6_input() of sys/netinet6/mld6.c on one MLD Query or Report,
 * on the mbuf contract models (common/mbufcontract.h).
 *
 * Caller contract (sys/netinet6/icmp6.c, icmp6_input, MLD_LISTENER_QUERY
 * and MLD_LISTENER_REPORT): icmp6len = m_pkthdr.len - off, and
 * icmp6len >= sizeof(struct mld_hdr) (icmp6.c:613, 24 bytes) or the
 * packet is dropped; the type is one of the two cases, so the packet's
 * ICMPv6 type is 130 or 131.  The caller passes either a copy of the
 * packet (m_copym, icmp6.c:615-621; the copy goes to mld6_input at
 * icmp6.c:621, the packet itself at icmp6.c:617 when the copy fails);
 * mld6_input owns and frees its argument on every path (m_freem at
 * mld6.c:372, if_put and the early returns; the failing
 * ip6_exthdr_get sets the local chain to NULL after m_pulldown freed it).
 * off is 40: ip6_input (ip6_input.c:266) has the IPv6 header contiguous
 * at mtod(m), and no extension header is walked here.  ip6_plen is
 * total - 40, as ip6_input (ip6_input.c:702-712) leaves it for a packet
 * of that length; mld6_input does not read ip6_plen.
 *
 * The packet: an IPv6 header (40 bytes), an MLD message of 24 bytes (the
 * minimum the caller checks) plus 0..24 more bytes of arbitrary content,
 * 64..88 bytes in one or two mbufs.  The first mbuf holds the IPv6
 * header, its length arbitrary above that, so the MLD message may be
 * split anywhere, including exactly after the 23rd byte of the address
 * (the length guard at mld6.c:189 is what keeps that read in bounds).
 * Every mbuf's data ends where its object ends (MC_MAXLEN bytes), so a
 * read or write past m_len is out of bounds.  The content is arbitrary,
 * except the ICMPv6 type, which is QUERY or REPORT (see above), and
 * m_flags M_LOOP, which is arbitrary (a report looped back is dropped).
 * The source address is link-local in 3 of 4 inputs (a nondet choice, so
 * the other branch stays covered; mld6.c:197 drops the rest) and the
 * destination, the hop limit and the rest of the header are arbitrary.
 *
 * Interface: model_ifp, one static ifnet.  if_index, if_flags and
 * if_rdomain are arbitrary.  The IPv6 multicast list is empty, or holds
 * one in6_multi with arbitrary group address (equal to the message's
 * group in 1 of 2 of those, so the report path meets it), arbitrary
 * state and an arbitrary timer (bounded to 8 bits: unsigned arithmetic
 * on it is what the kernel does with a timer).
 *
 * Models below mld6_input (every one stated):
 *   if_get   NULL (interface detached) or the interface with a reference;
 *            if_put asserts the reference and drops it; the count is 0 at
 *            the end.
 *   rw_enter_write, rw_exit_write   the if_maddrlock write lock as a flag:
 *            enter asserts it is free, exit asserts it is held; the flag is
 *            clear at the end.
 *   in6_lookupmulti   the list walk of in6.c over model_ifp, asserting that
 *            the lock is held (rw_assert_anylock in in6.c).
 *   mld6_sendpkt   a model that consumes nothing: it asserts the report
 *            packet mld6_input builds (MLD_LISTENER_REPORT).  mld6_input
 *            frees the packet after the call (mld6.c:314-315).
 *   m_pulldown, m_freem, m_free, m_copydata, m_pullup: mbufcontract.h.
 *   counters_inc (statistics, icmp6stat_inc), arc4random_uniform (the
 *            MLD_RANDOM_DELAY timer): nobody, no ownership or out
 *            parameter.
 *   malloc/free of the report packet: the common allocator (kmalloc may
 *            fail with M_NOWAIT, and mld6_input then skips the report).
 *
 * Asserted: no out-of-bounds access, no leak and no double free
 * (--memory-leak-check, the free checks of the models), the lock and
 * reference models, and the report packets' type.
 *
 * Bug variant: mutant_hdr/mld6.c takes the length guard of the MLD
 * header one byte short (sizeof(*mldh) - 1 at mld6.c:189): a packet
 * whose first mbuf ends exactly at the 23rd byte of the group address
 * is then read one byte past that mbuf.  See the README entry.
 */
#define MC_MAXLEN	88	/* 40 IPv6 + 24 MLD + 24 bytes of MLD content */
#define MLD_EXTRA_MAX	24
#include "mbufcontract.h"

#include "mld6.c"

/* the interface, and the write lock of its multicast list */
static struct ifnet model_ifp;
static int g_ifrefs;
static int g_maddr_held;

/* the packet's byte at off, in whichever mbuf holds it */
static u_char *
packet_byte(struct mbuf *m, int off)
{
	while (off >= m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}
	return ((u_char *)mtod(m, u_char *) + off);
}

/* if_get(9): the interface, or NULL when it was detached */
struct ifnet *
model_if_get(unsigned int index)
{
	if (nondet_bool())
		return (NULL);
	g_ifrefs++;
	return (&model_ifp);
}

void
model_if_put(struct ifnet *ifp)
{
	__CPROVER_assert(ifp == &model_ifp && g_ifrefs > 0,
	    "if_put model: a reference is held");
	g_ifrefs--;
}

/* rw(9): if_maddrlock is taken for writing only where mld6_input does */
void
model_rw_enter_write(struct rwlock *rwl)
{
	__CPROVER_assert(!g_maddr_held, "rw_enter_write: not held");
	g_maddr_held = 1;
}

void
model_rw_exit_write(struct rwlock *rwl)
{
	__CPROVER_assert(g_maddr_held, "rw_exit_write: held");
	g_maddr_held = 0;
}

/* in6.c's in6_lookupmulti(): the list walk, with the lock asserted */
struct in6_multi *
model_in6_lookupmulti(const struct in6_addr *addr, struct ifnet *ifp)
{
	struct ifmaddr *ifma;

	__CPROVER_assert(g_maddr_held, "in6_lookupmulti: lock held");
	TAILQ_FOREACH(ifma, &ifp->if_maddrlist, ifma_list) {
		if (ifma->ifma_addr->sa_family == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(&ifmatoin6m(ifma)->in6m_addr, addr))
			return (ifmatoin6m(ifma));
	}
	return (NULL);
}

/* the report packet: consumed by the caller, which frees it */
void
model_mld6_sendpkt(const struct mld6_pktinfo *pkt)
{
	__CPROVER_assert(pkt->mpi_type == MLD_LISTENER_REPORT,
	    "mld6_sendpkt: a report");
}

/* a packet of total bytes in one or two mbufs, the first holding the IPv6
 * header (ip6_input's m_pullup) and of arbitrary length above it */
static struct mbuf *
build_packet(int total)
{
	struct mbuf *m;
	int first;

	first = sizeof(struct ip6_hdr) +
	    mc_upto(total - (int)sizeof(struct ip6_hdr));
	m = mc_seg(first);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = total;
	m->m_pkthdr.ph_ifidx = nondet_ushort();
	if (first < total)
		m->m_next = mc_seg(total - first);
	return (m);
}

/* true in 3 of 4 inputs: the usual choice, so the accepting path stays covered */
static int
usual(void)
{
	return ((nondet_uchar() & 3) != 0);
}

int
main(void)
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct in6_multi *in6m = NULL;
	int total, off;

	TAILQ_INIT(&model_ifp.if_maddrlist);
	model_ifp.if_index = nondet_ushort();
	model_ifp.if_flags = nondet_uint();
	model_ifp.if_rdomain = nondet_uint();

	if (nondet_bool()) {
		in6m = CBMC_NEW(struct in6_multi);
		in6m->in6m_sin.sin6_len = sizeof(in6m->in6m_sin);
		in6m->in6m_sin.sin6_family = AF_INET6;
		in6m->in6m_addr.s6_addr32[0] = nondet_uint();
		in6m->in6m_addr.s6_addr32[1] = nondet_uint();
		in6m->in6m_addr.s6_addr32[2] = nondet_uint();
		in6m->in6m_addr.s6_addr32[3] = nondet_uint();
		in6m->in6m_ifidx = nondet_ushort();
		in6m->in6m_state = nondet_uint();
		in6m->in6m_timer = nondet_uint() & 0xff;
		in6m->in6m_ifma.ifma_addr = sin6tosa(&in6m->in6m_sin);
		TAILQ_INSERT_HEAD(&model_ifp.if_maddrlist,
		    &in6m->in6m_ifma, ifma_list);
	}

	/* ICMPv6 length >= sizeof(struct mld_hdr): the caller's check */
	total = sizeof(struct ip6_hdr) + sizeof(struct mld_hdr) +
	    mc_upto(MLD_EXTRA_MAX);
	m = build_packet(total);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(total - sizeof(struct ip6_hdr));
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = nondet_uchar();
	ip6->ip6_src.s6_addr32[0] = nondet_uint();
	ip6->ip6_src.s6_addr32[1] = nondet_uint();
	ip6->ip6_src.s6_addr32[2] = nondet_uint();
	ip6->ip6_src.s6_addr32[3] = nondet_uint();
	if (usual()) {
		ip6->ip6_src.s6_addr[0] = 0xfe;	/* link-local */
		ip6->ip6_src.s6_addr[1] = 0x80;
	}
	ip6->ip6_dst.s6_addr32[0] = nondet_uint();
	ip6->ip6_dst.s6_addr32[1] = nondet_uint();
	ip6->ip6_dst.s6_addr32[2] = nondet_uint();
	ip6->ip6_dst.s6_addr32[3] = nondet_uint();

	/* the ICMPv6 type the caller dispatches on: QUERY or REPORT */
	off = sizeof(struct ip6_hdr);
	*packet_byte(m, off) = MLD_LISTENER_QUERY + (nondet_uchar() & 1);
	if (nondet_bool())
		m->m_flags |= M_LOOP;

	/* the group address of the message equals the entry's, sometimes */
	if (in6m != NULL && nondet_bool())
		m_copydata(m, off + 8, sizeof(struct in6_addr),
		    &in6m->in6m_addr);

	/* the copy or the packet itself: mld6_input owns m either way */
	mld6_input(m, off);

	__CPROVER_assert(g_ifrefs == 0, "mld6_input: interface references");
	__CPROVER_assert(!g_maddr_held, "mld6_input: lock released");
	if (in6m != NULL) {
		TAILQ_REMOVE(&model_ifp.if_maddrlist, &in6m->in6m_ifma,
		    ifma_list);
		mc_release(in6m);
	}
	return (0);
}
