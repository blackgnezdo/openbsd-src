/*
 * Harness: nd6_ns_input() of sys/netinet6/nd6_nbr.c on a Neighbor
 * Solicitation for a target that is not one of our addresses, so that
 * the proxy NDP branch (RTF_ANNOUNCE route) and nd6_na_output() run.
 *
 * Why: nd6_ns_input() takes the link-layer address of a proxy NA from
 * the gateway of a route found by rtalloc(), and nd6_na_output() reads
 * if_addrlen bytes at LLADDR(sdl0) when sdl0->sdl_alen == if_addrlen.
 * Before 089ef3708 any RTF_ANNOUNCE route with an AF_LINK gateway was
 * used, also one whose gateway nd6_rtrequest() had rejected (no llinfo,
 * sdl_nlen and sa_len unchecked): the read leaves the gateway object.
 * The tree requires rt_llinfo != NULL, which nd6_rtrequest() sets only
 * for a gateway with room for sdl_nlen + if_addrlen bytes
 * (netinet6/nd6_rtrequest proves that invariant).  This target is the
 * consumer half: the real nd6_rtrequest() builds the route, the real
 * nd6_ns_input() and nd6_na_output() use it.
 *
 * Route table (as netinet/arp_proxy, one route).  One route, built as
 * netinet6/nd6_rtrequest builds it: arbitrary rt_flags (all 32 bits,
 * drawn before the gateway), an arbitrary gateway sockaddr (sa_len
 * 0..255, any family, any sdl_nlen and sdl_alen, exactly ROUNDUP(sa_len)
 * bytes at the end of a 264 byte object), the interface with an
 * arbitrary if_addrlen 0..255, if_type, if_index, if_flags, if_rdomain.
 * The route goes through the real nd6_rtrequest(RTM_ADD), or
 * RTM_RESOLVE without the flags rtrequest1 clears for a clone
 * (RTF_CLONING, RTF_CONNECTED, RTF_STATIC) and without RTF_LOCAL (no
 * clone has it; nd6_llinfo_settimer KASSERTs).  So only states the
 * kernel can produce are used.  The teardown is the real
 * nd6_rtrequest(RTM_DELETE).
 *   rtalloc  (model) with flags 0 (nd6_ns_input's proxy lookup): NULL or
 *            the route, with a reference.  With RT_RESOLVE (the source
 *            address selection of nd6_na_output): NULL or a second route
 *            "src_rt" with arbitrary flags, rt_ifa an in6_ifaddr, rt_gwroute
 *            NULL, with a reference.  Both cases check that the key is a
 *            sockaddr_in6.
 *   rtfree   (model) asserts a reference is held and drops it.
 *   rtisvalid (model) the kernel's body.
 *   Every reference taken is dropped: r_refs is back to 1 on both routes
 *   before the teardown.
 *
 * The packet.  The mbuf contract models (common/mbufcontract.h), not the
 * real mbuf code: the real m_pulldown of ip6_exthdr_get is about a
 * million variables (README, "Writing a packet parser target"), and
 * nothing below nd6_ns_input depends on the mbuf library.  MC_MAXLEN 72:
 * an IPv6 header (40 bytes, arbitrary content), a Neighbor Solicitation
 * (24 bytes, arbitrary target and content) and 0..8 option bytes
 * (arbitrary: none, one 8 byte option, or a fragment that nd6_options
 * refuses), in one or two mbufs, the first holding at least the IPv6
 * header (what icmp6_input's caller guarantees: nd6_ns_input does
 * mtod(m, struct ip6_hdr *) without a pullup), the split arbitrary.
 * off is 40, icmp6len is 24..32 (icmp6_input drops anything below 24).
 * m_pkthdr.ph_ifidx and ph_rtableid are arbitrary.  The packet bytes are
 * not constrained (except that, by a nondet choice each, the hop limit
 * may be set to 255 and the destination's first byte to 0xff, for the
 * fuzzer): the hop limit test, the source address tests, the target not
 * multicast and the option parse run as the kernel's on arbitrary
 * bytes.  What runs for real: all of nd6_ns_input (hop limit, source
 * address, multicast target, scope embedding, nd6_options, source
 * lladdr length test, DAD tests, the proxy branch, both nd6_na_output
 * calls) and nd6_na_output's body down to ip6_output.
 *
 * Models below nd6_ns_input (every one is stated):
 *   nd6_isneighbor    (nobody) arbitrary result, no effect: its route
 *                     lookup and if_isconnected are not this target's.
 *   nd6_cache_lladdr  (nobody) does nothing.  The real one updates
 *                     the sender's llinfo route (and may nd6_free it).
 *                     See "proxydl after rtfree" below.
 *   nd6_dad_ns_input  (nobody) the DAD queue is not modelled; the call
 *                     itself is reached.
 *   in6ifa_ifpwithaddr  NULL while the packet is processed (the target
 *                     is not one of our addresses, the proxy branch is
 *                     taken; the non-proxy NA reads ifp + 1, which is an
 *                     arpcom's 6 byte ac_enaddr, not modelled); a static
 *                     in6_ifaddr or NULL while the route is built
 *                     (nd6_rtrequest only tests it against NULL).
 *   in6ifa_ifpforlinklocal  NULL or a static in6_ifaddr with arbitrary
 *                     address and ia6_flags (anycast, tentative,
 *                     duplicated), so proxy = 1 and i_am_router = 0 are
 *                     reached, and so are the DAD and anycast exits.
 *   in6_addmulti, in6_lookupmulti, in6_delmulti  as netinet6/nd6_rtrequest.
 *   if_get, if_put    the one interface or NULL; nothing.
 *   m_gethdr, m_clget, m_align  (nd6_na_output's reply mbuf) a typed mbuf
 *                     whose data area is a MHLEN byte object (kept in
 *                     m_ext.ext_buf like mbufcontract.h's) or, after
 *                     m_clget, a MCLBYTES cluster that may fail; m_align puts the
 *                     data at the START of the area (the kernel puts it
 *                     at the end, at an offset that depends on
 *                     if_addrlen).  With the kernel's placement the run
 *                     was VERIFIED too, but 158 s and 3.4 million
 *                     variables against 62 s and 0.9 million.  The model
 *                     asserts what m_align KASSERTs.  The write side of
 *                     the reply is bounded by the area, with the data at
 *                     its start.
 *   bcopy             the common byte loop (--unwindset __builtin_bcopy.0:256):
 *                     nd6_na_output's bcopy(mac, ..., if_addrlen) reads the
 *                     if_addrlen bytes at LLADDR(sdl0) one by one, so an
 *                     over-read of the gateway is found at the first byte
 *                     outside it.
 *   ip6_output        frees the mbuf (m_freem) and returns 0.
 *   mq_init, mq_purge the hold queue stays empty (nothing here enqueues);
 *                     mq_purge asserts that.
 *   refcnt_init, refcnt_rele  single threaded, as the other nd6 targets.
 *   m_pulldown, m_freem, m_free, m_copydata: mbufcontract.h.
 * Kernel bodies: all of nd6.c and nd6_nbr.c (included), among them
 * nd6_rtrequest, nd6_llinfo_settimer, nd6_need_cache, nd6_options,
 * nd6_ns_input, nd6_na_output, nd6_ifptomac.  pool_get/pool_put are the
 * common model.  max_linkhdr is 64 (domaininit's minimum).
 *
 * Bounds and reductions: packet 64..72 bytes; one route; option area
 * 0..8 bytes (nd6_options: --unwind 3 covers its loop, the unwinding
 * assertion proves it); if_addrlen is arbitrary, so the lladdr length
 * test of nd6_ns_input and the option write of nd6_na_output meet all of
 * 0..255; packet content unconstrained.  Not covered: nd6_cache_lladdr,
 * nd6_na_input, the non-proxy NA (sdl0 == NULL), a second route, the
 * route being deleted between rtalloc and the use of proxydl.
 *
 * proxydl after rtfree.  nd6_ns_input stores satosdl(rt->rt_gateway) in
 * proxydl, drops its reference with rtfree(rt), and passes proxydl to
 * nd6_na_output, which reads it.  If that rtfree dropped the last
 * reference the gateway would be freed (route.c rtfree: rt_putgwroute,
 * free(rt_gateway)) and this is a use after free of the gateway.  Here
 * the table keeps its own reference (r_refs 1), so the model cannot show
 * it; it shows only that the gateway is intact for the proxy decision
 * and the read, and that no reference is lost.  What keeps the route
 * alive in the kernel: the routing table's reference, which only
 * rtrequest(RTM_DELETE) under the exclusive net lock drops, and
 * nd6_ns_input runs with the net lock held and does not sleep.
 * nd6_cache_lladdr, called in between, takes the lock too and may call
 * nd6_free() -> rtdeletemsg() for the SENDER's route, which is the proxy
 * route if the sender's address equals the target; this model does not
 * run it.  Its failure path is taken only for a route with RTF_GATEWAY
 * or without llinfo or an AF_LINK gateway, none of which a proxy route
 * that passed the tests has (RTF_GATEWAY is not in RTF_FMASK), so no
 * path is known, but the harness cannot exclude one.
 *
 * Properties: no out-of-bounds access (the read at LLADDR, the packet
 * reads), no leak or double free (--memory-leak-check), every reference
 * taken is dropped, nd6_rtrequest's teardown removes the llinfo, no
 * KASSERT/panic on the path.
 *
 * Mutant: mutant_prefix/nd6_nbr.c is the source before 089ef3708 (no
 * rt_llinfo test).
 */
#define MC_MAXLEN	72
#define MC_COPY_LOOP
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/timeout.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include "mbufcontract.h"

#define log	kern_log_model
#include "nd6.c"
/*
 * Native only: nd6_ns_input takes &in6ifa_ifpwithaddr(...)->ia_ifa and
 * &in6ifa_ifpforlinklocal(...)->ia_ifa of a NULL result (ia_ifa is the
 * first member, the address of NULL is NULL), which UBSan's null check
 * reports as "member access within null pointer" although nothing is
 * read.  The check is switched off for the functions of nd6_nbr.c; ASan still
 * stops at any real null dereference.  CBMC has no such check.
 */
#ifdef NATIVE_SHIM_H
#pragma clang attribute push (__attribute__((no_sanitize("null"))), apply_to = function)
#endif
#include "nd6_nbr.c"
#ifdef NATIVE_SHIM_H
#pragma clang attribute pop
#endif

#define GATE_OBJ	264	/* ROUNDUP(255) */
#define ROUNDUP8(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)

int max_linkhdr = 64;

static struct in6_ifaddr harness_ia6;
static struct in6_ifaddr harness_ia6_ll;
static struct in6_multi harness_in6m;
static int ns_phase;		/* 1 while the packet is processed */

static struct ifnet *the_ifp;
static struct rtentry *table0;	/* the proxy route */
static struct rtentry *src_rt;	/* nd6_na_output's source route */

/* free for objects of CBMC_NEW (kernel free(9) is kfree here) */
static void
harness_release(void *p)
{
	mc_release(p);
}

/* ---- models below nd6_ns_input ---- */

struct in6_ifaddr *
in6ifa_ifpwithaddr(struct ifnet *ifp, struct in6_addr *addr)
{
	if (ns_phase)
		return (NULL);
	return (nondet_bool() ? &harness_ia6 : NULL);
}

struct in6_ifaddr *
in6ifa_ifpforlinklocal(struct ifnet *ifp, int ignoreflags)
{
	return (nondet_bool() ? &harness_ia6_ll : NULL);
}

struct in6_multi *
in6_addmulti(const struct in6_addr *addr, struct ifnet *ifp, int *error)
{
	*error = 0;
	return (NULL);
}

struct in6_multi *
in6_lookupmulti(const struct in6_addr *addr, struct ifnet *ifp)
{
	return (nondet_bool() ? &harness_in6m : NULL);
}

void
in6_delmulti(struct in6_multi *in6m)
{
}

struct ifnet *
if_get(unsigned int index)
{
	return (nondet_bool() ? the_ifp : NULL);
}

void
if_put(struct ifnet *ifp)
{
}

void
refcnt_init(struct refcnt *r)
{
	r->r_refs = 1;
}

int
refcnt_rele(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs > 0, "refcnt_rele: count is positive");
	r->r_refs--;
	return (r->r_refs == 0);
}

void
mq_init(struct mbuf_queue *mq, u_int maxlen, int ipl)
{
	mq->mq_list.ml_head = NULL;
	mq->mq_list.ml_tail = NULL;
	mq->mq_list.ml_len = 0;
	mq->mq_maxlen = maxlen;
}

unsigned int
mq_purge(struct mbuf_queue *mq)
{
	__CPROVER_assert(mq->mq_list.ml_head == NULL && mq->mq_list.ml_len == 0,
	    "mq_purge model: the hold queue is empty");
	return (0);
}

struct mbuf *
m_gethdr(int how, int type)
{
	struct mbuf *m;

	if (nondet_bool())
		return (NULL);
	m = CBMC_NEW(struct mbuf);
	m->m_type = type;
	m->m_flags = M_PKTHDR;
	/* the data area is kept in m_ext.ext_buf like mc_seg's, so that
	 * mbufcontract.h's m_free releases it; M_EXT is not set */
	MC_BUF(m) = (caddr_t)CBMC_NEW_ARRAY(u_char, MHLEN);
	m->m_data = MC_BUF(m);
	return (m);
}

struct mbuf *
m_clget(struct mbuf *m, int how, u_int pktlen)
{
	u_char *buf;

	__CPROVER_assert(m != NULL && pktlen == MCLBYTES, "m_clget model");
	if (nondet_bool())
		return (NULL);
	mc_release(MC_BUF(m));
	buf = CBMC_NEW_ARRAY(u_char, MCLBYTES);
	MC_BUF(m) = (caddr_t)buf;
	m->m_ext.ext_size = MCLBYTES;
	m->m_flags |= M_EXT;
	m->m_data = (caddr_t)buf;
	return (m);
}

void
m_align(struct mbuf *m, int len)
{
	int size;

	size = (m->m_flags & M_EXT) ? m->m_ext.ext_size : MHLEN;
	__CPROVER_assert(len >= 0, "m_align: KASSERT len >= 0");
	__CPROVER_assert(((len + sizeof(long) - 1) & ~(sizeof(long) - 1)) <=
	    size, "m_align: KASSERT len fits the area");
}

int
ip6_output(struct mbuf *m, struct ip6_pktopts *opt, struct route *ro,
    int flags, struct ip6_moptions *im6o, const struct ipsec_level *seclevel)
{
	m_freem(m);
	return (0);
}

struct rtentry *
rtalloc(const struct sockaddr *dst, int flags, unsigned int rtableid)
{
	struct rtentry *rt;

	__CPROVER_assert(dst->sa_family == AF_INET6 &&
	    dst->sa_len == sizeof(struct sockaddr_in6), "rtalloc: key");
	rt = (flags & RT_RESOLVE) ? src_rt : table0;
	if (nondet_bool())
		return (NULL);
	rt->rt_refcnt.r_refs++;
	return (rt);
}

void
rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt->rt_refcnt.r_refs > 1, "rtfree: a reference held");
	rt->rt_refcnt.r_refs--;
}

int
rtisvalid(struct rtentry *rt)
{
	if (rt == NULL)
		return (0);
	if (!ISSET(rt->rt_flags, RTF_UP))
		return (0);
	if (ISSET(rt->rt_flags, RTF_GATEWAY)) {
		if (rt->rt_gwroute == NULL)
			return (0);
		if (!ISSET(rt->rt_gwroute->rt_flags, RTF_UP))
			return (0);
	}
	return (1);
}

/* ---- the route, the interface, the packet ---- */

/*
 * A gateway as rt_setgate() leaves it: ROUNDUP(sa_len) bytes at the end
 * of a GATE_OBJ byte object (*objp, freed by the caller).
 */
static struct sockaddr *
build_gate(unsigned char **objp)
{
	struct sockaddr *gate;
	unsigned int sa_len;
	int rounded;

	sa_len = nondet_uchar();
	rounded = ROUNDUP8(sa_len);
	*objp = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(*objp + GATE_OBJ - rounded);
	gate->sa_len = sa_len;
	if (sa_len >= 2)
		gate->sa_family = nondet_bool() ? AF_LINK : nondet_uchar();
	if (sa_len >= 6)
		satosdl(gate)->sdl_nlen = nondet_uchar();
	if (sa_len >= 7)
		satosdl(gate)->sdl_alen = nondet_uchar();
	return (gate);
}

/*
 * The packet: total bytes (>= 64) in one or two mbufs, the first holding
 * the IPv6 header at least, arbitrary content (mc_seg).
 */
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
	m->m_pkthdr.ph_rtableid = nondet_uint();
	if (first < total)
		m->m_next = mc_seg(total - first);
	return (m);
}

/*
 * For the fuzzer: an arbitrary byte tested, so that the "usual" choice
 * is made in 3 of 4 inputs (still a nondet choice for CBMC, which
 * explores both).
 */
static int
usual(void)
{
	return ((nondet_uchar() & 3) != 0);
}

static void
init_ia6(struct in6_ifaddr *ia)
{
	ia->ia_addr.sin6_len = sizeof(ia->ia_addr);
	ia->ia_addr.sin6_family = AF_INET6;
	ia->ia_addr.sin6_addr.s6_addr32[0] = nondet_uint();
	ia->ia_addr.sin6_addr.s6_addr32[1] = nondet_uint();
	ia->ia_addr.sin6_addr.s6_addr32[2] = nondet_uint();
	ia->ia_addr.sin6_addr.s6_addr32[3] = nondet_uint();
	ia->ia_ifa.ifa_addr = sin6tosa(&ia->ia_addr);
	ia->ia6_flags = nondet_int();
	if (usual())
		ia->ia6_flags = 0;
}

int
main(void)
{
	struct ifnet *ifp;
	struct rtentry *rt;
	struct sockaddr_in6 *dst;
	unsigned char *obj;
	struct mbuf *m;
	int req, total;

	nd6_pool.pr_size = sizeof(struct llinfo_nd6);

	init_ia6(&harness_ia6);
	init_ia6(&harness_ia6_ll);

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_addrlen = nondet_uchar();
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_uint();
	ifp->if_rdomain = nondet_uint();
	ifp->if_flags = nondet_ushort();
	the_ifp = ifp;

	dst = CBMC_NEW(struct sockaddr_in6);
	dst->sin6_len = sizeof(*dst);
	dst->sin6_family = AF_INET6;

	/* the proxy route, through the real nd6_rtrequest */
	rt = CBMC_NEW(struct rtentry);
	rt->rt_refcnt.r_refs = 1;		/* the table's */
	rt->rt_flags = nondet_uint();
	rt->rt_dest = sin6tosa(dst);
	rt->rt_gateway = build_gate(&obj);
	/*
	 * For the fuzzer, by nondet choices (the arbitrary values stay
	 * covered): the usual proxy route and interface, sdl_alen equal
	 * to if_addrlen, sdl_nlen 0, an Ethernet interface.
	 */
	if (usual())
		rt->rt_flags = RTF_UP | RTF_HOST | RTF_ANNOUNCE;
	if (usual())
		ifp->if_type = IFT_ETHER;
	if (rt->rt_gateway->sa_len >= 7 && usual())
		satosdl(rt->rt_gateway)->sdl_alen = ifp->if_addrlen;
	if (rt->rt_gateway->sa_len >= 6 && usual())
		satosdl(rt->rt_gateway)->sdl_nlen = 0;
	rt->rt_llinfo = NULL;
	req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
	if (req == RTM_RESOLVE)
		rt->rt_flags &= ~(RTF_CLONING | RTF_CONNECTED | RTF_STATIC |
		    RTF_LOCAL);
	nd6_rtrequest(ifp, req, rt);
	table0 = rt;

	/* nd6_na_output's source route */
	src_rt = CBMC_NEW(struct rtentry);
	src_rt->rt_refcnt.r_refs = 1;
	src_rt->rt_flags = nondet_uint();
	src_rt->rt_ifa = &harness_ia6.ia_ifa;

	/* the packet: IPv6 header, NS, 0..8 option bytes */
	total = sizeof(struct ip6_hdr) + sizeof(struct nd_neighbor_solicit) +
	    mc_upto(8);
	m = build_packet(total);
	/*
	 * The content is arbitrary; two fields are, in half of the cases
	 * (a nondet choice, so the arbitrary content stays covered), set
	 * to what the proxy path needs: hop limit 255 and a multicast
	 * destination (tlladdr).  CBMC finds both by itself; the fuzzer
	 * natively needs it to reach the proxy branch within seconds.
	 */
	if (usual())
		mtod(m, struct ip6_hdr *)->ip6_hlim = 255;
	if (usual())
		mtod(m, struct ip6_hdr *)->ip6_dst.s6_addr[0] = 0xff;
	ns_phase = 1;
	nd6_ns_input(m, sizeof(struct ip6_hdr), total - sizeof(struct ip6_hdr));
	ns_phase = 0;

	__CPROVER_assert(rt->rt_refcnt.r_refs == 1,
	    "every reference taken is dropped (proxy route)");
	__CPROVER_assert(src_rt->rt_refcnt.r_refs == 1,
	    "every reference taken is dropped (source route)");

	/* teardown by the kernel's own code, then what the harness made */
	nd6_rtrequest(ifp, RTM_DELETE, rt);
	__CPROVER_assert(rt->rt_llinfo == NULL, "teardown: llinfo removed");

	harness_release(src_rt);
	harness_release(rt);
	harness_release(dst);
	harness_release(obj);
	harness_release(ifp);
	return (0);
}
