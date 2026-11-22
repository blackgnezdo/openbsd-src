/*
 * Harness: igmp_input_if() of sys/netinet/igmp.c on one IPv4 packet,
 * on the mbuf contract models (common/mbufcontract.h).
 *
 * The packet: an IP header of 20 bytes (no options, *offp 20) followed
 * by 0..16 IGMP bytes of arbitrary content: 20..36 bytes, one or two
 * mbufs, the first of arbitrary length.  Every mbuf's data ends where
 * its object ends, so a read or write past the packet's m_len is out of
 * bounds (the reason for the contract models rather than mbufkit: the
 * kit's storage is MLEN or a cluster, so a read past m_len is not seen).
 *
 * Caller contract (sys/netinet/ip_input.c, ipv4_check and ipintr):
 * ip_len is in network order and equals the packet length; the packet
 * is at least the header length, and the header is contiguous at
 * mtod(m) (ipv4_check's m_pullup to hlen).  Here ip_len is therefore
 * not arbitrary: it is set to the packet length, 20..36.  proto is
 * IPPROTO_IGMP, af AF_INET, ns NULL.
 *
 * The interface's multicast list is empty, or holds one in_multi with
 * an arbitrary group address, a valid state (IGMP_DELAYING_MEMBER ..
 * IGMP_AWAKENING_MEMBER) and an arbitrary timer.  The router table
 * starts empty; rti_reset() may add one entry, removed by rti_delete()
 * at the end.  in_ifp2ia() and in_lookupmulti() are models that do what
 * in.c does over the same objects.  rip_input() consumes the packet as
 * the real one does: a model that frees it and returns IPPROTO_DONE.
 *
 * in_cksum(): the body is not kept.  The model asserts that the chain
 * holds len bytes and that each is readable, and returns an arbitrary
 * value, except for len < 2, where the real sum is never zero (the
 * empty sum is 0xffff; one byte b gives ~(b << 8), never zero).
 *
 * Asserted: no out-of-bounds access (the contract models and the reads
 * of igmp.c), no leak and no double free (--memory-leak-check and the
 * free checks of the models), and the return value is IPPROTO_DONE.
 *
 * Bug variant: mutant/igmp.c drops the IGMP_MINLEN check (see the
 * README entry and the report).
 */
#define MC_MAXLEN	36	/* 20 byte IP header + 16 bytes of IGMP */
#define IGMP_EXTRA_MAX	16
#include "mbufcontract.h"

#include "igmp.c"

/* the interface and its address: static, one object each */
static struct ifnet model_ifp;
static struct in_ifaddr model_ia;

/* in_cksum(): reads len bytes of the chain (see above) */
int
model_in_cksum(struct mbuf *m, int len)
{
	struct mbuf *n;
	int left = len, k;

	__CPROVER_assert(len >= 0, "in_cksum: length");
	for (n = m; n != NULL && left > 0; n = n->m_next) {
		k = n->m_len < left ? n->m_len : left;
		if (k > 0)
			__CPROVER_assert(__CPROVER_r_ok(mtod(n, u_char *), k),
			    "in_cksum: bytes readable");
		left -= k;
	}
	__CPROVER_assert(left == 0, "in_cksum: chain shorter than len");
	if (len < 2)
		return (0xffff);
	return (nondet_int());
}

/* in.c's in_ifp2ia(): an address of the interface, or none */
struct in_ifaddr *
model_in_ifp2ia(struct ifnet *ifp)
{
	if (mc_upto(1) == 0)
		return (NULL);
	return (&model_ia);
}

/* in.c's in_lookupmulti(): the list walk of in.c */
struct in_multi *
model_in_lookupmulti(const struct in_addr *addr, struct ifnet *ifp)
{
	struct ifmaddr *ifma;

	TAILQ_FOREACH(ifma, &ifp->if_maddrlist, ifma_list) {
		if (ifma->ifma_addr->sa_family == AF_INET &&
		    ifmatoinm(ifma)->inm_addr.s_addr == addr->s_addr)
			return (ifmatoinm(ifma));
	}
	return (NULL);
}

/*
 * mutex(9): igmp_mtx is the only mutex on the path.  The models keep
 * the owner field the kernel's MUTEX_ASSERT_LOCKED (DIAGNOSTIC) reads,
 * and assert that it is not taken twice or left twice.
 */
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

/* raw_ip.c's rip_input(): the packet is consumed */
int
model_rip_input(struct mbuf **mp, int *offp, int proto, int af,
    struct netstack *ns)
{
	m_freem(*mp);
	return (IPPROTO_DONE);
}

int
main(void)
{
	struct mbuf *m;
	struct ip *ip;
	struct in_multi *inm = NULL;
	int len, off, ret;

	TAILQ_INIT(&model_ifp.if_maddrlist);
	model_ifp.if_index = 1;
	model_ifp.if_flags = mc_upto(IFF_LOOPBACK);
	model_ia.ia_net = nondet_uint();
	if (mc_upto(1)) {
		inm = CBMC_NEW(struct in_multi);
		inm->inm_sin.sin_len = sizeof(inm->inm_sin);
		inm->inm_sin.sin_family = AF_INET;
		inm->inm_sin.sin_addr.s_addr = nondet_uint();
		inm->inm_state = 1 + mc_upto(4);	/* IGMP_DELAYING_MEMBER..AWAKENING */
		inm->inm_timer = mc_upto(255);
		inm->inm_ifma.ifma_addr = sintosa(&inm->inm_sin);
		TAILQ_INSERT_HEAD(&model_ifp.if_maddrlist,
		    &inm->inm_ifma, ifma_list);
	}

	len = sizeof(struct ip) + mc_upto(IGMP_EXTRA_MAX);
	m = mc_build(len);
	/* ipv4_check: the IP header is contiguous */
	if (m->m_len < sizeof(struct ip)) {
		m = m_pullup(m, sizeof(struct ip));
		if (m == NULL)
			goto out;	/* m_pullup freed the chain */
	}
	ip = mtod(m, struct ip *);
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_len = htons(len);		/* the packet length */
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src.s_addr = nondet_uint();
	ip->ip_dst.s_addr = nondet_uint();
	/*
	 * The group field of a report is arbitrary, and so is the
	 * destination; the two are equal, and equal to the interface's
	 * entry, only in some runs: they are made so here, as one more
	 * choice among the arbitrary ones (a fuzzer does not find the
	 * equality by itself).
	 */
	if (len >= sizeof(struct ip) + IGMP_MINLEN) {
		if (mc_upto(1))
			m_copydata(m, sizeof(struct ip) + 4, 4, &ip->ip_dst);
		if (inm != NULL && mc_upto(1))
			m_copydata(m, sizeof(struct ip) + 4, 4,
			    &inm->inm_addr);
	}

	off = sizeof(struct ip);
	ret = igmp_input_if(&model_ifp, &m, &off, IPPROTO_IGMP, AF_INET, NULL);
	__CPROVER_assert(ret == IPPROTO_DONE, "igmp_input_if: IPPROTO_DONE");

	/* the packet was consumed on every path; rti_reset's entry is freed */
	rti_delete(&model_ifp);
 out:
	/* the multicast entry is the harness's */
	if (inm != NULL)
		mc_release(inm);
	return (0);
}
