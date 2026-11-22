/*
 * Harness: the consumers of a neighbour cache entry on a route that
 * satisfies the invariant netinet6/nd6_rtrequest proves: nd6_cache_lladdr()
 * and nd6_resolve() of sys/netinet6/nd6.c and nd6_na_input() of
 * sys/netinet6/nd6_nbr.c.  nd6.c, nd6_nbr.c and kern/uipc_mbuf.c are
 * #included (one translation unit: static inline functions of headers
 * defined in two units get a "$link1" name that "nobody" cannot reach;
 * counters_inc did) and their objects (nd6_pool, nd6_list, nd6_inuse)
 * match, as in netinet6/nd6_rtrequest, whose build_gate this target
 * builds on.
 *
 * Why: nd6_rtrequest guarantees that every route with an llinfo (and not
 * RTF_GATEWAY) has an AF_LINK gateway of sa_len >= sizeof(struct
 * sockaddr_dl) with offsetof(sdl_data) + sdl_nlen + ifp->if_addrlen <=
 * sa_len, the gateway being exactly ROUNDUP(sa_len) bytes (rt_setgate).
 * This target is the other half of that assume/guarantee split: given
 * such a route, the consumers stay inside the gateway.  nd6_cache_lladdr
 * compares and stores if_addrlen bytes at LLADDR(sdl) (bcmp, bcopy) and
 * sets sdl_alen; nd6_resolve copies sdl_alen == ETHER_ADDR_LEN bytes from
 * LLADDR(sdl).  nd6_na_input makes the same bcmp and bcopy with a lladdr
 * that comes out of the packet.
 *
 * The route (rt, one object, CBMC_NEW):
 *  - gateway: AF_LINK, sa_len in [max(32, 8 + sdl_nlen + if_addrlen),
 *    255], sdl_nlen and sdl_alen arbitrary bytes (sdl_nlen as far as
 *    the room allows, see below), exactly ROUNDUP(sa_len) bytes at the
 *    END of a constant 264 byte object, built with arithmetic (clamps,
 *    no __CPROVER_assume).  sdl_alen is arbitrary: nd6_rtrequest does
 *    not constrain it (a route added from userland carries the alen it
 *    came with).  The first byte of LLADDR is arbitrary, so bcmp finds
 *    a difference or not.
 *  - rt_flags: arbitrary except RTF_LLINFO set and RTF_GATEWAY clear
 *    (what nd6_lookup requires; RTF_GATEWAY and RTF_MULTICAST are not in
 *    RTF_FMASK, route_output clears RTF_MPLS from the mask, and nd6_rtrequest
 *    returns before creating an llinfo for any of the three, so no llinfo
 *    route has them; with them its RTM_DELETE would not remove the llinfo
 *    either).  An interface that needs no cache (nd6_need_cache) only gets
 *    llinfo on RTF_HOST routes, so RTF_HOST is set then.  For nd6_resolve rt0 is rt or an RTF_GATEWAY route
 *    whose rt_gwroute is rt (rt_getll).
 *  - rt_llinfo: a real llinfo_nd6, built as nd6_rtrequest builds it
 *    (pool_get, nd6_inuse++, refcnt_init, mq_init, ln_rt, nd6_list head),
 *    ln_state, ln_router, ln_asked, rt_expire arbitrary.  With RTF_LOCAL
 *    the entry is REACHABLE with rt_expire 0 (what nd6_rtrequest makes of
 *    an interface address; nd6_llinfo_settimer KASSERTs !RTF_LOCAL and a
 *    local entry never reaches it).  That narrows ln_state for RTF_LOCAL
 *    routes only.
 *  - ifp: if_addrlen arbitrary in 0..247 (the code must not depend on it
 *    being 6).  248..255 are not reachable with an entry: the gateway needs
 *    8 + sdl_nlen + if_addrlen <= sa_len <= 255, so nd6_rtrequest creates
 *    no llinfo and no consumer finds a route; the clamp drops them.
 *    rt_ifidx == if_index (nd6_lookup tests it).
 *
 * nd6_cache_lladdr(ifp, from, lladdr, lladdrlen, type, code, i_am_router):
 * from a non-NULL, arbitrary address (the unspecified one returns early),
 * type, code, i_am_router arbitrary, lladdr NULL or a buffer.
 * Caller guarantee, nd6_ns_input (nd6_nbr.c:244), nd6_rs_input/ra
 * (nd6_rtr.c:124), icmp6_redirect_input (icmp6.c:1285): if lladdr is not
 * NULL then lladdrlen == ((if_addrlen + 2 + 7) & ~7) (nd6_options has
 * proved lladdr = option + 2 lies inside the packet, with the option of
 * lladdrlen bytes: netinet6/nd6_options).  So lladdrlen - 2 bytes are
 * readable at lladdr, at least if_addrlen and at least 6 (ether_sprintf
 * reads 6).  The buffer here is exactly lladdrlen - 2 bytes at the end of
 * a constant 262 byte object (262 = 264 - 2).  nd6_cache_lladdr does not
 * use lladdrlen itself.
 *
 * nd6_resolve(ifp, rt0, m, dst, desten): called by ether_resolve
 * (if_ethersubr.c:265, 291) only, on an Ethernet ifp: ether_ifattach sets
 * if_addrlen = ETHER_ADDR_LEN.  GUARANTEE ASSUMED HERE: nd6_resolve is
 * called only when if_addrlen == ETHER_ADDR_LEN.  It reads 6 bytes at
 * LLADDR when sdl_alen == 6 whatever if_addrlen is; with if_addrlen < 6
 * the invariant leaves no room for them (see README gap in the report:
 * the scratch variant without the guard is VIOLATED).  desten is a 6 byte
 * object, m an mbuf with arbitrary m_flags (M_MCAST included), m_len in
 * 0..128 and m_data at the end of a 128 byte object (so mtod reads past
 * m_len are out of bounds).  Ownership: the caller frees m iff the result
 * is 0 (the M_MCAST and resolved paths); otherwise nd6_resolve freed or
 * queued it (the teardown purges the queue).
 *
 * nd6_na_input(m, off, icmp6len): a packet built by the contract models of
 * the mbuf library (common/mbufcontract.h, MC_MAXLEN 72: an IPv6 header of
 * 40 bytes, the 24 byte neighbour advertisement and 0 to 8 option bytes,
 * one or two mbufs, arbitrary content, the first 40 bytes made contiguous
 * as ip6_input does), off = 40, icmp6len = length - 40 >= 24 (icmp6.c:681
 * drops a shorter message before the call).  nd6_options and the
 * lladdr test (nd6_nbr.c:617, lladdrlen == (if_addrlen + 9) & ~7) are the
 * real code: lladdr points into the packet only if an 8 byte option of the
 * right type fits, so the bcopy/bcmp source regions are checked against the
 * packet (mc_seg puts each segment's data at the end of its own object).
 * if_get returns ifp or NULL, in6ifa_ifpwithaddr NULL or an address
 * (always one for an RTF_LOCAL entry, whose address is ours),
 * nd6_dad_find NULL, ip6_forwarding is the undefined extern (arbitrary,
 * so both the router and the host path run).  The mbuf is always consumed.
 *
 * Properties: no out-of-bounds access, no leak or double free
 * (--memory-leak-check), the lookup reference taken by the model is
 * dropped exactly once by the caller (g_refs), no KASSERT/panic, the
 * teardown leaves rt_llinfo NULL.
 *
 * Reductions, all deliberate:
 *  - if_addrlen 0..247, see above.  The harness has no other bound than
 *    that: the bcmp/bcopy loops run up to 255 iterations
 *    (a byte loop of 256 unwindings cost too much, see model_bcmp: region
 *    checks instead).
 *  - Only bytes the code looks at are symbolic: sa_len, sdl_nlen,
 *    sdl_alen, the first byte of LLADDR, the first byte of lladdr; the
 *    rest of the gateway and of the buffer is zero.  The hold queue is
 *    empty at the start; nd6_resolve may put one mbuf in it.
 *  - ln_hold_total is arbitrary, as is every field read by nd6_resolve's
 *    decisions; nd6_init() is not called (nd6_pool.pr_size is set).
 *  - nd6_na_input: packets of at most 72 bytes with the header in the first
 *    40, so a lladdr option only of 8 bytes: if_addrlen 0..6 reach the
 *    stores with a lladdr, the larger ones only the paths without (the
 *    lladdr test rejects an 8 byte option for them); no extension headers
 *    (off 40); one nd6_na_input call per run, either that or the two steps
 *    above (a step before it would add nothing: the entry is arbitrary
 *    already; both in one run, and nd6_na_input in each of three steps,
 *    were 1.4 and 4.1 million variables before the split of the steps).
 *    Cost: check phase about 4 minutes, 1.8 million variables (the
 *    steps alone: 5 s, 160,000), hence the timeout file; nd6_na_input
 *    alone in a scratch target was 260,000 variables and 11 s.
 *  - icmp6_redirect_output and the proxy path (nd6_ns_input, nd6_na_output)
 *    are not covered.
 *
 * Models (replace file, all stated here):
 *  nd6_lookup  returns NULL or rt, taking one reference (g_refs++).  rt
 *              satisfies everything nd6_lookup tests (RTF_LLINFO, not
 *              RTF_GATEWAY, AF_LINK, rt_llinfo, rt_ifidx).  With create
 *              (a new route, never RTF_LOCAL) the state is set to
 *              ND6_LLINFO_NOSTATE as nd6_lookup does; any other entry
 *              is an arbitrary existing one.
 *  rtfree      drops one reference (g_refs--), asserts it was held; the
 *              object stays (the harness owns it).
 *  nd6_free    asserts it is not reached: nd6_cache_lladdr only calls it
 *              when rt_flags lacks RTF_LLINFO or has RTF_GATEWAY, when
 *              rt_llinfo or the gateway is NULL or not AF_LINK, all of
 *              which nd6_lookup excludes.  Natively the same.
 *  rt_getll    the kernel's body (route.c): rt, or rt_gwroute for RTF_GATEWAY.
 *  if_output_mq  the packets are consumed by if_output: mq_purge, as the
 *              kernel's does for what comes back; ln_hold_total reduced.
 *              Natively the same.
 *  ether_sprintf  asserts 6 readable bytes at its argument (and reads
 *              them), returns a static string.
 *  nd6_ns_output  asserts the two address arguments readable, does
 *              nothing else.
 *  nd6_need_cache  not needed: nd6_rtrequest is not called except as the
 *              teardown (RTM_DELETE), which does not call it.
 *  getuptime   arbitrary, 0 <= t < 2^40 (NONDET_TIME), as in
 *              netinet/arp_consumers.
 *  bcmp, bcopy  region checks instead of byte loops, see above.
 *  m_freem, m_pulldown  the contract models mc_m_freem, mc_m_pulldown of
 *              common/mbufcontract.h (renamed, see the includes: the real
 *              kern/uipc_mbuf.c is linked for the hold queue).  m_freem frees
 *              a chain of up to two mbufs; m_pulldown is what m_pulldown
 *              promises (proved by net/mbuf_pulldown).
 *  if_get, if_put, in6ifa_ifpwithaddr, nd6_dad_find, nd6_dad_duplicated
 *              as stated above for nd6_na_input; nd6_dad_duplicated does
 *              nothing (only reached for a tentative address of ours).
 *  refcnt_init, refcnt_rele, in6_lookupmulti, in6_delmulti as in
 *              netinet6/nd6_rtrequest (the teardown is the real RTM_DELETE).
 *  pool_get/pool_put are the common model (malloc/free, pr_size).
 * Kept bodies: all of nd6.c, nd6_nbr.c and kern/uipc_mbuf.c (included;
 * of the last only mq_init, mq_push, mq_purge, mq_delist, ml_init,
 * ml_enqueue, ml_dequeue, ml_purge are called).  Bodiless (nobody): log
 * (#defined to kern_log_model), timeout_set_flags,
 * timeout_add_sec, mtx_enter, mtx_leave, counters_inc (statistics).  Bodiless
 * by default, none with an out-parameter that is used: inet_ntop (its
 * result goes to log, itself bodiless), rt6_flush and rtm_send (no result
 * used; the route they would touch is not changed by them here),
 * rw_status, splassert_fail (NET_ASSERT_LOCKED only reports), __mtx_init.
 *
 * Mutants (suite.sh -m): mutant/ nd6_resolve without the sdl_alen test
 * (bcopy of sdl_alen bytes, up to 255, into the 6 byte desten, from past
 * the gateway).
 */
#define INET6		1
#define MC_MAXLEN	72
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
/*
 * The contract models of the mbuf library keep the kernel's names; here
 * they get others (and are bound with replace), because kern/uipc_mbuf.c
 * is also linked, for the hold queue (mq_*, ml_*) of the llinfo.
 */
#define m_free		mc_m_free
#define m_freem		mc_m_freem
#define m_pullup	mc_m_pullup
#define m_pulldown	mc_m_pulldown
#define m_copydata	mc_m_copydata
#define m_getptr	mc_m_getptr
#define m_adj		mc_m_adj
#define MC_COPY_LOOP
#include "mbufcontract.h"
#undef m_free
#undef m_freem
#undef m_pullup
#undef m_pulldown
#undef m_copydata
#undef m_getptr
#undef m_adj
#define log	kern_log_model
#include "uipc_mbuf.c"
#include "nd6.c"
#include "nd6_nbr.c"

/* CBMC's free for objects of CBMC_NEW (kernel free(9) is kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

#define GATE_OBJ	264	/* ROUNDUP(255) */
#define LL_OBJ		262	/* largest lladdrlen - 2 */
#define ROUNDUP8(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)

/*
 * Times: seconds since boot or 0, never negative and far below 2^40:
 * nd6_llinfo_settimer adds to the uptime, which overflows (UBSan, native
 * engine) for values near the limits of time_t.  Masked, not assumed.
 */
#define NONDET_TIME()	(nondet_long() & 0xffffffffffL)

time_t
model_getuptime(void)
{
	return (NONDET_TIME());
}

static struct rtentry *g_rt;
static struct ifnet *g_ifp;
static int g_refs;
static struct in6_multi harness_in6m;

struct rtentry *
model_nd6_lookup(const struct in6_addr *addr6, int create, struct ifnet *ifp,
    u_int rtableid)
{
	__CPROVER_assert(__CPROVER_r_ok(addr6, sizeof(*addr6)),
	    "nd6_lookup model: address readable");
	__CPROVER_assert(ifp == g_ifp, "nd6_lookup model: the interface");
	if (nondet_bool())
		return (NULL);
	if (create) {
		/* a new route: RTF_HOST | RTF_LLINFO, never local */
		if (ISSET(g_rt->rt_flags, RTF_LOCAL))
			return (NULL);
		((struct llinfo_nd6 *)g_rt->rt_llinfo)->ln_state =
		    ND6_LLINFO_NOSTATE;
	}
	g_refs++;
	return (g_rt);
}

void
model_rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt == g_rt, "rtfree model: the route");
	__CPROVER_assert(g_refs > 0, "rtfree model: a reference is held");
	g_refs--;
}

void
model_nd6_free(struct rtentry *rt, struct ifnet *ifp, int i_am_router)
{
	__CPROVER_assert(0, "nd6_free reached: nd6_lookup excludes its callers");
}

struct rtentry *
model_rt_getll(struct rtentry *rt)
{
	if (ISSET(rt->rt_flags, RTF_GATEWAY))
		return (rt->rt_gwroute);
	return (rt);
}

int
model_if_output_mq(struct ifnet *ifp, struct mbuf_queue *mq,
    unsigned int *total, struct sockaddr *dst, struct rtentry *rt)
{
	atomic_sub_int(total, mq_purge(mq));
	return (0);
}

/*
 * bcmp and bcopy of up to 255 bytes: the README's byte loops
 * (--unwindset __builtin_bcmp.0:256, __builtin_bcopy.0:256) over regions
 * at symbolic offsets of 262/264 byte objects were 2.8 million variables
 * and did not finish in 300 s (measured).  The models check the whole
 * region up front, which is the same bounds property as the loop's byte
 * accesses (a loop over [p, p + n) is in bounds iff the region is), and
 * leave the contents alone: bcmp returns an arbitrary 0 or 1 (both
 * outcomes are reached), bcopy stores nothing.  Nothing in the target
 * depends on bytes of the gateway data (sdl_alen, sdl_nlen and sa_len are
 * not written by them).  Natively both are the real loops.
 */
int
model_bcmp(const void *b1, const void *b2, size_t n)
{
#ifdef NATIVE_SHIM_H
	const unsigned char *p1 = b1, *p2 = b2;

	for (; n > 0; n--)
		if (*p1++ != *p2++)
			return (1);
	return (0);
#else
	__CPROVER_assert(__CPROVER_r_ok(b1, n) && __CPROVER_r_ok(b2, n),
	    "bcmp model: both regions readable");
	return (n == 0 ? 0 : nondet_bool());
#endif
}

void
model_bcopy(const void *src, void *dst, size_t n)
{
#ifdef NATIVE_SHIM_H
	const unsigned char *s = src;
	unsigned char *d = dst;

	if (d < s)
		for (; n > 0; n--)
			*d++ = *s++;
	else
		for (s += n, d += n; n > 0; n--)
			*--d = *--s;
#else
	if (n == 0)
		return;
	__CPROVER_assert(__CPROVER_r_ok(src, n),
	    "bcopy model: source readable");
	__CPROVER_assert(__CPROVER_w_ok(dst, n),
	    "bcopy model: destination writable");
#endif
}

static volatile unsigned char sink;

char *
model_ether_sprintf(u_char *ap)
{
	static char buf[18];

	__CPROVER_assert(__CPROVER_r_ok(ap, ETHER_ADDR_LEN),
	    "ether_sprintf model: 6 bytes readable");
	sink = ap[0] ^ ap[1] ^ ap[2] ^ ap[3] ^ ap[4] ^ ap[5];
	return (buf);
}

void
model_nd6_ns_output(struct ifnet *ifp, const struct in6_addr *daddr6,
    const struct in6_addr *taddr6, const struct in6_addr *hsrc, int tentative)
{
	__CPROVER_assert(__CPROVER_r_ok(taddr6, sizeof(*taddr6)),
	    "nd6_ns_output model: target readable");
	if (hsrc != NULL)
		__CPROVER_assert(__CPROVER_r_ok(hsrc, sizeof(*hsrc)),
		    "nd6_ns_output model: source readable");
}

struct ifnet *
model_if_get(unsigned int idx)
{
	return (nondet_bool() ? NULL : g_ifp);
}

void
model_if_put(struct ifnet *ifp)
{
}

/* the address is ours, or not; a local route's address always is */
static struct in6_ifaddr harness_ia6;

struct in6_ifaddr *
model_in6ifa_ifpwithaddr(struct ifnet *ifp, struct in6_addr *addr)
{
	if (ISSET(g_rt->rt_flags, RTF_LOCAL) || nondet_bool())
		return (&harness_ia6);
	return (NULL);
}

struct dadq *
model_nd6_dad_find(struct ifaddr *ifa)
{
	return (NULL);
}

void
model_nd6_dad_duplicated(struct dadq *dp)
{
}

struct in6_multi *
model_in6_lookupmulti(const struct in6_addr *addr, struct ifnet *ifp)
{
	return (nondet_bool() ? &harness_in6m : NULL);
}

void
model_in6_delmulti(struct in6_multi *in6m)
{
}

void
model_refcnt_init(struct refcnt *r)
{
	r->r_refs = 1;
}

int
model_refcnt_rele(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs > 0, "refcnt_rele: count is positive");
	r->r_refs--;
	return (r->r_refs == 0);
}

/*
 * A gateway as rt_setgate() leaves it, satisfying the invariant for an
 * interface with if_addrlen alen: ROUNDUP(sa_len) bytes at the end of a
 * GATE_OBJ byte object (*objp, freed by the caller).  Arithmetic only.
 */
static struct sockaddr *
build_gate(unsigned char **objp, unsigned int alen)
{
	struct sockaddr *gate;
	unsigned int sa_len, nlen, maxn, lo;
	int rounded;

	maxn = 247 - alen;		/* 8 + nlen + alen <= 255 */
	nlen = nondet_uchar();
	if (nlen > maxn)
		nlen = maxn;
	lo = 8 + nlen + alen;
	if (lo < sizeof(struct sockaddr_dl))
		lo = sizeof(struct sockaddr_dl);
	sa_len = nondet_uchar();
	if (sa_len < lo)
		sa_len = lo;
	rounded = ROUNDUP8(sa_len);
	*objp = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(*objp + GATE_OBJ - rounded);
	gate->sa_len = sa_len;
	gate->sa_family = AF_LINK;
	satosdl(gate)->sdl_nlen = nlen;
	satosdl(gate)->sdl_alen = nondet_uchar();
	if (alen > 0)
		LLADDR(satosdl(gate))[0] = nondet_uchar();
	return (gate);
}

/*
 * One step of the life of the entry: nothing, nd6_cache_lladdr on an
 * inbound ND packet, or nd6_resolve from ether_resolve.  Called twice in
 * a row, so a resolve may queue a packet that a later
 * cache_lladdr flushes, and a cache_lladdr stores the address that a
 * later resolve reads.
 */
static void
step(struct ifnet *ifp, struct rtentry *rt, struct sockaddr_in6 *dst,
    unsigned int alen)
{
	struct in6_addr *from;
	unsigned char *llobj = NULL, *desten;
	char *lladdr = NULL;
	struct rtentry *gw0 = NULL;
	struct mbuf *m;

	if (nondet_bool()) {
		/* nd6_cache_lladdr on an inbound ND packet */
		unsigned int lladdrlen = (alen + 2 + 7) & ~7;

		from = CBMC_NEW(struct in6_addr);
		from->s6_addr32[0] = nondet_uint();
		from->s6_addr32[1] = nondet_uint();
		from->s6_addr32[2] = nondet_uint();
		from->s6_addr32[3] = nondet_uint();
		if (nondet_bool()) {
			llobj = CBMC_NEW_ARRAY(unsigned char, LL_OBJ);
			lladdr = (char *)(llobj + LL_OBJ - (lladdrlen - 2));
			lladdr[0] = nondet_uchar();
		}
		nd6_cache_lladdr(ifp, from, lladdr, lladdr ? lladdrlen : 0,
		    nondet_int(), nondet_int(), nondet_int());
		__CPROVER_assert(g_refs == 1,
		    "nd6_cache_lladdr drops its lookup reference");
		harness_release(from);
		if (llobj != NULL)
			harness_release(llobj);
	} else if (nondet_bool() && ifp->if_addrlen == ETHER_ADDR_LEN) {
		/* nd6_resolve from ether_resolve: Ethernet interfaces only */
		struct rtentry *rt0 = rt;
		int error;

		if (nondet_bool()) {
			gw0 = CBMC_NEW(struct rtentry);
			gw0->rt_flags = RTF_GATEWAY;
			gw0->rt_gwroute = rt;
			rt0 = gw0;
		}
		m = mc_seg(mc_upto(MC_MAXLEN));	/* one mbuf, no packet header */
		if (nondet_bool())
			m->m_flags |= M_MCAST;
		desten = CBMC_NEW_ARRAY(unsigned char, ETHER_ADDR_LEN);
		error = nd6_resolve(ifp, rt0, m, sin6tosa(dst), desten);
		if (error == 0)
			m_freem(m);
		if (gw0 != NULL)
			harness_release(gw0);
		harness_release(desten);
	}
}

/*
 * The last step: nothing, or nd6_na_input on a packet.  Only once: three
 * copies of the packet path (mbuf models and loops) were 4.1 million
 * variables and did not finish in 300 s (measured).
 */
static void
na_step(struct ifnet *ifp)
{
	struct mbuf *m;

	if (nondet_bool()) {
		/*
		 * nd6_na_input as icmp6_input calls it: the IPv6 header (no
		 * extension headers, off 40) contiguous in the first mbuf,
		 * icmp6len >= sizeof(struct nd_neighbor_advert), here 24 to
		 * 32 bytes: no option, or one of 8 bytes.
		 */
		int len = sizeof(struct ip6_hdr) +
		    sizeof(struct nd_neighbor_advert) + mc_upto(8);

		m = mc_build(len);
		if (m->m_len < (int)sizeof(struct ip6_hdr) &&
		    (m = mc_m_pullup(m, sizeof(struct ip6_hdr))) == NULL)
			return;
		m->m_pkthdr.ph_ifidx = ifp->if_index;
		nd6_na_input(m, sizeof(struct ip6_hdr),
		    len - sizeof(struct ip6_hdr));
		__CPROVER_assert(g_refs == 1,
		    "nd6_na_input drops its lookup references");
	}
}

int
main(void)
{
	struct ifnet *ifp;
	struct rtentry *rt;
	struct sockaddr_in6 *dst;
	struct llinfo_nd6 *ln;
	unsigned char *obj;
	unsigned int alen;

	nd6_pool.pr_size = sizeof(struct llinfo_nd6);
	ln_hold_total = nondet_uint();

	alen = nondet_uchar();
	if (alen > 247)
		alen = 247;
	ifp = CBMC_NEW(struct ifnet);
	g_ifp = ifp;
	ifp->if_addrlen = alen;
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_ushort();
	ifp->if_rdomain = nondet_uchar();
	ifp->if_flags = nondet_ushort();
	ifp->if_nd = CBMC_NEW(struct nd_ifinfo);
	ifp->if_nd->reachable = nondet_uint();

	dst = CBMC_NEW(struct sockaddr_in6);
	dst->sin6_len = sizeof(*dst);
	dst->sin6_family = AF_INET6;

	rt = CBMC_NEW(struct rtentry);
	g_rt = rt;
	g_refs = 1;			/* the routing table's */
	rt->rt_flags = nondet_uint();
	rt->rt_flags |= RTF_LLINFO;
	rt->rt_flags &= ~(RTF_GATEWAY | RTF_MULTICAST | RTF_MPLS);
	if (nd6_need_cache(ifp) == 0)
		rt->rt_flags |= RTF_HOST;
	rt->rt_dest = sin6tosa(dst);
	rt->rt_ifidx = ifp->if_index;
	rt->rt_gateway = build_gate(&obj, alen);

	/* the llinfo, as nd6_rtrequest RTM_ADD builds it */
	ln = pool_get(&nd6_pool, PR_WAITOK | PR_ZERO);
	nd6_inuse++;
	refcnt_init(&ln->ln_refcnt);
	mq_init(&ln->ln_mq, LN_HOLD_QUEUE, IPL_SOFTNET);
	rt->rt_llinfo = (caddr_t)ln;
	ln->ln_rt = rt;
	TAILQ_INSERT_HEAD(&nd6_list, ln, ln_list);
	ln->ln_state = nondet_short();
	ln->ln_router = nondet_short();
	ln->ln_asked = nondet_long();
	rt->rt_expire = NONDET_TIME();
	if (ISSET(rt->rt_flags, RTF_LOCAL)) {
		ln->ln_state = ND6_LLINFO_REACHABLE;
		rt->rt_expire = 0;
	}

	/*
	 * either two arbitrary steps (nd6_cache_lladdr, nd6_resolve or
	 * nothing) or one nd6_na_input: the entry is an arbitrary one to
	 * begin with, so a step before nd6_na_input adds no state
	 */
	if (nondet_bool()) {
		step(ifp, rt, dst, alen);
		step(ifp, rt, dst, alen);
	} else
		na_step(ifp);

	/* teardown by the kernel's own code, then what the harness made */
	nd6_rtrequest(ifp, RTM_DELETE, rt);
	__CPROVER_assert(rt->rt_llinfo == NULL, "teardown: llinfo removed");
	__CPROVER_assert(g_refs == 1, "no reference left");

	harness_release(rt);
	harness_release(dst);
	harness_release(obj);
	harness_release(ifp->if_nd);
	harness_release(ifp);
	return (0);
}
