/*
 * Harness: nd6_rtrequest() of sys/netinet6/nd6.c on the life of one
 * route in two phases, then the teardown nd6_rtrequest(ifp, RTM_DELETE,
 * rt).  nd6.c is #included so that its objects (nd6_pool, nd6_list,
 * nd6_mtx, nd6_inuse) match.  Same shape as netinet/arp_rtrequest.
 *
 * Why: consumers of a neighbour cache entry reach it through
 * nd6_lookup(), which requires RTF_LLINFO, rt_llinfo != NULL, an
 * AF_LINK gateway and not RTF_GATEWAY.  nd6_cache_lladdr() and
 * nd6_na_input() then compare and store ifp->if_addrlen bytes at
 * LLADDR(satosdl(rt->rt_gateway)), and icmp6_redirect_output() reads
 * them.  So an entry with rt_llinfo set must have room for if_addrlen
 * bytes at LLADDR.  Before the change under test nd6_rtrequest accepted
 * any AF_LINK gateway with sa_len >= sizeof(struct sockaddr_dl) whatever
 * sdl_nlen was, and a gateway it rejected on RTM_CHANGE left an existing
 * llinfo in place.
 *
 * Phase 1, a new route: req is RTM_ADD (rtrequest1) or RTM_RESOLVE
 * (a clone), rt_llinfo NULL, rt_flags arbitrary (all 32 bits, drawn
 * before the gateway), rt_dest a valid struct sockaddr_in6.
 *
 * Phase 2 (optional), RTM_CHANGE as route_output() does it (sys/net/
 * rtsock.c): maybe a new arbitrary gateway (rt_setgate replaces the old
 * object, which is freed), then the flags in RTF_FMASK except RTF_MPLS
 * are toggled to arbitrary values (route_output clears RTF_MPLS from
 * rtm_fmask and rtm_flags first), the other flags stay; then
 * if_rtrequest(RTM_ADD), that is nd6_rtrequest(ifp, RTM_ADD, rt), on the
 * same rt, which may by now hold an llinfo from phase 1.  The gateway
 * comparison, the family check and rtm_getifa before rt_setgate are not
 * modelled: the new gateway is arbitrary.
 *
 * The gateway comes from rt_setgate() (sys/net/route.c): a fresh
 * malloc(ROUNDUP(sa_len), M_ZERO) object into which sa_len bytes are
 * copied; ROUNDUP rounds up to a multiple of 8 and gives 8 for sa_len
 * 0.  Nothing ties sdl_nlen and sdl_alen to sa_len.  So: sa_len any of
 * 0..255, family AF_LINK or any other byte, sdl_nlen and sdl_alen any
 * bytes, bytes past sa_len zero, the object exactly ROUNDUP(sa_len)
 * bytes.  The gateway lives at the END of a constant 264 byte object
 * (264 = ROUNDUP(255)), at offset 264 - ROUNDUP(sa_len), so a read past
 * ROUNDUP(sa_len) is out of bounds under both engines (no object of
 * symbolic size).
 *
 * ifp: if_addrlen is arbitrary in 0..255 (the code under test must not
 * depend on it being 6), if_type, if_index, if_flags arbitrary.
 *
 * Invariant (check_entry, after each phase), what nd6_lookup's callers
 * rely on: if rt_llinfo != NULL and RTF_GATEWAY is not set, the gateway
 * has sa_family AF_LINK, sa_len >= sizeof(struct sockaddr_dl) and
 * offsetof(struct sockaddr_dl, sdl_data) + sdl_nlen + ifp->if_addrlen
 * <= sa_len.  (nd6_lookup also tests RTF_LLINFO and rt_gateway's family;
 * the code under test keeps RTF_LLINFO set only together with an
 * llinfo, except the clear on RTM_RESOLVE of an interface that needs no
 * cache, so rt_llinfo is the property that matters.)
 * RTF_GATEWAY|RTF_MULTICAST|RTF_MPLS return before the gateway is
 * looked at; with them no llinfo is ever created here (phase 2 cannot
 * set them: only RTF_FMASK minus RTF_MPLS is toggled).
 *
 * Properties: no out-of-bounds access, no leak or double free
 * (--memory-leak-check), the invariant after each phase, the teardown
 * leaves rt_llinfo NULL, no KASSERT/panic on the path.
 *
 * Not covered: the nd6_ns_input proxy change in sys/netinet6/nd6_nbr.c
 * (089ef3708, "rt->rt_llinfo != NULL &&" before the AF_LINK test of an
 * RTF_ANNOUNCE route) is NOT covered by this target; nor are
 * nd6_cache_lladdr, nd6_na_input, nd6_lookup and icmp6_redirect_output
 * themselves: only the invariant they rely on is.
 *
 * Reductions, all deliberate:
 *  - For req RTM_RESOLVE the flags RTF_CLONING and RTF_LOCAL are
 *    cleared (rt_flags is otherwise arbitrary).  rtrequest1 clears
 *    RTF_CLONING on the clone (route.c, case RTM_RESOLVE); without that,
 *    phase 2's RTM_ADD of an llinfo route that has RTF_CLONING breaks
 *    out before the gateway test (the invariant then fails on the
 *    current source; RTF_CLONING is not in RTF_FMASK, so no caller
 *    can toggle it).  RTF_LOCAL: nd6_llinfo_settimer() has
 *    KASSERT(!ISSET(rt_flags, RTF_LOCAL)) and RTM_RESOLVE reaches it;
 *    userland cannot set RTF_LOCAL (rtsock.c, "kernel-only flags") and
 *    the kernel makes RTF_LOCAL routes with RTF_HOST only, never
 *    cloning, so a clone of one does not exist.  With RTF_LOCAL left in,
 *    the KASSERT fails; not a path any caller reaches.  Also
 *    in the tree the RESOLVE gateway is a fixed local sockaddr_dl
 *    (sa_len 20, nlen 0, alen 0, route.c rtrequest1); it is arbitrary
 *    here, which includes it (the brief asked for it).
 *  - Only the bytes of the gateway the code looks at are symbolic:
 *    sa_len, sa_family, sdl_nlen, sdl_alen (each only if within sa_len;
 *    the others are zero as rt_setgate leaves them).  sdl_type and
 *    sdl_index are overwritten by the code, sdl_data is never read.
 *  - ifp and rt are zero except for what is set below.
 *  - Phase 2 changes only the gateway and the flags; metrics, rt_ifa and
 *    the interface are not touched.
 *  - The hold queue ln_mq stays empty (nothing here enqueues), so
 *    mq_purge in the teardown frees nothing.
 *  - nd6_init() is not called: nd6_pool.pr_size is set directly (what the
 *    common pool model needs), the timers are not set up.  nd6_inuse
 *    starts at 0 and nd6_list empty; ip6_neighborgcthresh is the
 *    undefined extern of in6_proto.c, an arbitrary value, so the garbage
 *    collection loop is reached (it stops at once: the list holds only
 *    ln).
 *  - Unwinding: --unwind 3 (nd6_rtrequest recurses once on a rejected
 *    gateway; the gc loop ends in its first iteration).
 *
 * Models (replace file; every one is stated here):
 *  nd6_need_cache  returns need_cache, drawn once in main (nondet), so
 *              both early returns of nd6_rtrequest are explored.  The
 *              real function is a pure function of ifp->if_type; one
 *              value per run keeps all calls consistent, as the real
 *              one is.  Natively: the same.
 *  in6ifa_ifpwithaddr  NULL or a pointer to a static struct in6_ifaddr,
 *              nondet; the caller only tests it against NULL.
 *  in6_addmulti  stores 0 in *error and does nothing else (no multicast
 *              membership is created: its result is ignored by the
 *              caller and nothing here reads the interface's list).
 *  in6_lookupmulti  NULL or a pointer to a static struct in6_multi.
 *  in6_delmulti  does nothing (the object is static).
 *  m_freem     frees a single mbuf (asserts it is not chained); reached
 *              from mq_purge's ml_purge, the queue is empty.
 *  refcnt_init, refcnt_rele  single threaded versions of the kernel's:
 *              the teardown frees the llinfo only when refcnt_rele
 *              returns 1.
 *  pool_get/pool_put are the common model (malloc/free, pr_size).
 * Kernel bodies kept: all of nd6.c (included; nd6_llinfo_settimer and
 * its KASSERT are real), and from kern/uipc_mbuf.c: m_align, mq_init,
 * mq_purge, mq_delist, ml_init, ml_purge.  Bodiless (nobody): log is
 * #defined to kern_log_model (CBMC's builtin log(double) clashes),
 * getuptime, timeout_set_flags, timeout_add_sec, mtx_enter, mtx_leave
 * (and __mtx_init, rw_status, splassert_fail through the default).  None
 * has an out-parameter or ownership; the mutexes protect nothing in a
 * single thread; the timeout is never run; rw_status and
 * splassert_ctl only feed NET_ASSERT_LOCKED, which only reports.
 * KERNEL_LOCK/KERNEL_UNLOCK are empty macros (no MULTIPROCESSOR here).
 *
 * Mutants (suite.sh -m, all VIOLATED): mutant_prefix/ the source before
 * the change (no room test, no delete of an existing llinfo); mutant/ the
 * current source without "+ ifp->if_addrlen" (sdl_nlen only);
 * mutant_nodel/ without "if (rt->rt_llinfo != NULL)
 * nd6_rtrequest(ifp, RTM_DELETE, rt);".
 */
#define log	kern_log_model
#include "nd6.c"
#include "cbmc_harness.h"

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
#define ROUNDUP8(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)

static int need_cache;
static struct in6_ifaddr harness_ia6;
static struct in6_multi harness_in6m;

int
model_nd6_need_cache(struct ifnet *ifp)
{
	return (need_cache);
}

struct in6_ifaddr *
model_in6ifa_ifpwithaddr(struct ifnet *ifp, struct in6_addr *addr)
{
	return (nondet_bool() ? &harness_ia6 : NULL);
}

struct in6_multi *
model_in6_addmulti(const struct in6_addr *addr, struct ifnet *ifp,
    int *error)
{
	*error = 0;
	return (NULL);
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

struct mbuf *
model_m_freem(struct mbuf *m)
{
	if (m != NULL) {
		__CPROVER_assert(m->m_next == NULL && m->m_nextpkt == NULL,
		    "m_freem model: single mbuf");
		harness_release(m);
	}
	return (NULL);
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
 * What nd6_lookup's callers (nd6_cache_lladdr, nd6_na_input,
 * icmp6_redirect_output) rely on when rt_llinfo is set: an AF_LINK
 * gateway with room for if_addrlen bytes at LLADDR.
 */
static void
check_entry(struct ifnet *ifp, struct rtentry *rt)
{
	struct sockaddr *gate = rt->rt_gateway;

	if (rt->rt_llinfo == NULL || ISSET(rt->rt_flags, RTF_GATEWAY))
		return;
	__CPROVER_assert(gate->sa_family == AF_LINK,
	    "post: llinfo gateway is AF_LINK");
	__CPROVER_assert(gate->sa_len >= sizeof(struct sockaddr_dl),
	    "post: llinfo gateway holds a sockaddr_dl");
	if (gate->sa_len >= sizeof(struct sockaddr_dl))
		__CPROVER_assert(offsetof(struct sockaddr_dl, sdl_data) +
		    satosdl(gate)->sdl_nlen + ifp->if_addrlen <=
		    gate->sa_len,
		    "post: llinfo gateway has room for LLADDR .. + if_addrlen");
}

#define FMASK_NO_MPLS	(RTF_FMASK & ~RTF_MPLS)

int
main(void)
{
	struct ifnet *ifp;
	struct rtentry *rt;
	struct sockaddr_in6 *dst;
	unsigned char *obj, *nobj;
	int req;

	nd6_pool.pr_size = sizeof(struct llinfo_nd6);
	need_cache = nondet_bool();

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_addrlen = nondet_uchar();
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_uint();
	ifp->if_flags = nondet_ushort();

	dst = CBMC_NEW(struct sockaddr_in6);
	dst->sin6_len = sizeof(*dst);
	dst->sin6_family = AF_INET6;

	rt = CBMC_NEW(struct rtentry);
	rt->rt_flags = nondet_uint();
	rt->rt_dest = sin6tosa(dst);
	rt->rt_gateway = build_gate(&obj);
	rt->rt_llinfo = NULL;

	/* rtrequest: a new route, RTM_ADD, or a clone, RTM_RESOLVE */
	req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
	if (req == RTM_RESOLVE)
		rt->rt_flags &= ~(RTF_CLONING | RTF_LOCAL);
	nd6_rtrequest(ifp, req, rt);
	check_entry(ifp, rt);

	/*
	 * route_output RTM_CHANGE (rtsock.c): rt_setgate() installs a new
	 * gateway, the flags in RTF_FMASK but RTF_MPLS may be toggled, then
	 * if_rtrequest(RTM_ADD).
	 */
	if (nondet_bool()) {
		unsigned int fmask, nflags;

		if (nondet_bool()) {
			rt->rt_gateway = build_gate(&nobj);
			harness_release(obj);
			obj = nobj;
		}
		fmask = nondet_uint() & FMASK_NO_MPLS;
		nflags = nondet_uint();
		rt->rt_flags = (rt->rt_flags & ~fmask) | (nflags & fmask);
		nd6_rtrequest(ifp, RTM_ADD, rt);
		check_entry(ifp, rt);
	}

	/* teardown by the kernel's own code, then what the harness made */
	nd6_rtrequest(ifp, RTM_DELETE, rt);
	__CPROVER_assert(rt->rt_llinfo == NULL, "teardown: llinfo removed");

	harness_release(rt);
	harness_release(dst);
	harness_release(obj);
	harness_release(ifp);
	return (0);
}
