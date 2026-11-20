/*
 * Harness: arp_rtrequest() of sys/netinet/if_ether.c, with arprequest()
 * which it calls, on the life of one route in two phases, then the
 * teardown arp_rtrequest(ifp, RTM_DELETE, rt).  if_ether.c is
 * #included so that its static and global objects (arp_pool, arp_list,
 * arp_mtx) match.
 *
 * Phase 1, a new route: req is RTM_ADD (rtrequest1) or RTM_RESOLVE
 * (rtable_match, a clone), on an arbitrary gateway (build_gate) and
 * arbitrary rt_flags (all 32 bits, drawn before the gateway).
 *
 * Phase 2 (optional), RTM_CHANGE as route_output() does it (sys/net/
 * rtsock.c, case RTM_CHANGE): maybe a new arbitrary gateway (rt_setgate
 * replaces the old object), then the flags in RTF_FMASK, except
 * RTF_MPLS, are toggled to arbitrary values (route_output clears
 * RTF_MPLS from rtm_fmask and rtm_flags first, "set by rt_mpls_set()"),
 * the other flags stay; then if_rtrequest(RTM_ADD), that is
 * arp_rtrequest(ifp, RTM_ADD, rt), is called on the same rt, which
 * may by now hold an llinfo from phase 1.  RTF_LLINFO is in RTF_FMASK,
 * so a toggle can set it on a route that has no llinfo, or clear it on
 * one that has.  The gateway comparison, the family check and rtm_getifa
 * before rt_setgate are not modelled: the new gateway is arbitrary.
 *
 * What the callers guarantee, checked against the source:
 *  - The gateway comes from rt_setgate() (sys/net/route.c): a fresh
 *    malloc(ROUNDUP(sa_len), M_ZERO) object into which gate->sa_len
 *    bytes are copied.  ROUNDUP (route.c) rounds up to a multiple of 8
 *    (sizeof(long)), and gives 8 for sa_len 0.  From a routing socket
 *    (rtm_xaddrs, harness net/rtm_xaddrs, P3) an AF_LINK gateway only
 *    has sa_len >= sizeof(struct sockaddr_dl); other families have no
 *    length promise.  Nothing ties sdl_nlen and sdl_alen to sa_len.
 *    So: sa_len any of 0..255, family AF_LINK or any other value,
 *    sdl_nlen and sdl_alen any bytes, bytes past sa_len zero, the
 *    object exactly ROUNDUP(sa_len) bytes.
 *  - rt is fresh in phase 1: rt_llinfo NULL, rt_flags arbitrary,
 *    rt_dest a valid sockaddr_in (rt_key), rt_gateway as above.
 *
 * Why RTF_LLINFO, not only rt_llinfo, is the key.  route_output
 * (rtsock.c, about line 822) sets RTF_LLINFO in rti_flags for every
 * route whose gateway has sa_family AF_LINK (unless RTF_CLONING),
 * before rtrequest1() calls the hook, so the flag is set whether or not
 * arp_rtrequest accepts the gateway.  arplookup() and arpresolve()
 * test the flag (not rt_llinfo) and then read the gateway as a
 * sockaddr_dl; arpcache() writes an Ethernet address at LLADDR.  So a
 * route with RTF_LLINFO whose gateway is not a usable sockaddr_dl is
 * a wild read or write, even if no llinfo was allocated.  The code
 * therefore clears RTF_LLINFO (and deletes an existing llinfo) when it
 * rejects the gateway.
 *
 * Postcondition (check_entry, after each phase): when RTF_LLINFO is set
 * or rt_llinfo is not NULL, the gateway is AF_LINK, sa_len >=
 * sizeof(struct sockaddr_dl), sdl_alen is 0 or ETHER_ADDR_LEN, and
 * offsetof(sdl_data) + sdl_nlen + ETHER_ADDR_LEN <= sa_len (room for
 * the address arpcache stores).  It holds for every route, also those
 * arp_rtrequest returns early for (RTF_GATEWAY, RTF_BROADCAST,
 * RTF_MULTICAST, RTF_MPLS, an RTM_ADD of RTF_CLONING): route_output
 * passes userland's rtm_flags through, RTF_LLINFO included, so these
 * can carry the flag too, and arplookup (in_arpinput's proxy path,
 * arpproxy) and arpresolve would read their gateway.  For RTM_RESOLVE
 * the harness clears RTF_CLONING, RTF_CONNECTED and RTF_STATIC, as
 * rtrequest does for a clone (route.c).
 *
 * Sizes: the gateway lives at the END of a constant 264 byte object
 * (264 = ROUNDUP(255)), at offset 264 - ROUNDUP(sa_len), so a read
 * past ROUNDUP(sa_len) is out of bounds under both engines; no object
 * of symbolic size (README, "When a run exhausts time or memory", 1).
 *
 * Reductions, all deliberate:
 *  - Only the bytes of the gateway that the code compares are
 *    symbolic: sa_len, sa_family, sdl_nlen, sdl_alen (each only if it
 *    lies within sa_len; the others are zero, as rt_setgate leaves
 *    them).  sdl_type and sdl_index are overwritten by the code, and
 *    sdl_data (link and name bytes) is copied into an mbuf by
 *    arprequest and never read back, so its values are irrelevant to
 *    every property checked; they are zero here.
 *  - The ifp and rt objects are zero except for what is set below
 *    (rt_flags, if_type, if_index, if_rdomain, if_llprio arbitrary).
 *  - Phase 2 changes only the gateway and the flags; metrics, labels,
 *    rt_ifa and the interface are not touched (rtm_getifa and the
 *    RTM_DELETE for a changed ifa are not modelled; the delete is
 *    exercised by the teardown).  The new gateway object replaces the
 *    old, which is freed, as rt_setgate does.
 *  - The hold queue la_mq stays empty (nothing here enqueues), so
 *    mq_purge in the teardown frees nothing.
 *  - arplookup(), arpresolve(), arpcache() and the rtable are not
 *    modelled: the fix to arplookup (proxy entries must carry ARP
 *    information, 12a68fffb) is NOT covered by this target; only the
 *    gateway invariant they rely on is.
 *
 * Models (replace file):
 *  pool_init   sets pr_size only, as the common pool model needs
 *              (arpinit() is called and reaches pool_init).
 *  m_gethdr    one mbuf from CBMC_NEW, or NULL (M_DONTWAIT may fail);
 *              M_PKTHDR set, m_data = m_pktdat, as m_inithdr does.
 *  m_freem     frees a single mbuf (asserts it is not chained).
 *  refcnt_init, refcnt_rele
 *              single threaded versions of the kernel's (plain
 *              counter instead of atomics): the teardown frees the
 *              llinfo only when refcnt_rele returns 1.
 *  model_if_output (bound through fptargets)
 *              consumes the mbuf like a driver: m_freem.
 * Kernel bodies kept (keep): m_align, mq_init, mq_purge, mq_delist,
 * ml_init, ml_purge.  Bodiless (nobody): kern_log_model (log is
 * #defined to it, CBMC's builtin log(double) clashes), getuptime,
 * timeout_set_flags, timeout_add_sec, mtx_enter, mtx_leave (and
 * __mtx_init through the default); none has an out-parameter or
 * ownership; the mutex protects nothing in a single thread.
 *
 * Properties: no out-of-bounds access (in particular the memcpy from
 * enaddr in arprequest); no leak or double free (--memory-leak-check);
 * the postcondition above after each phase; teardown leaves rt_llinfo
 * NULL.
 *
 * Mutants (suite.sh -m, all VIOLATED): mutant_prefix/ source before
 * e3dbf8882 (arprequest called before the gateway check, which has no
 * sdl_nlen bound and no sdl_alen test); mutant_prefix2/ source before
 * 96dde7faa (bound sdl_nlen + sdl_alen, no sdl_alen test, no
 * RTM_DELETE and no CLR of RTF_LLINFO on a rejected gateway);
 * mutant_prefix3/ source before 569b20305 (early-return paths keep
 * RTF_LLINFO whatever the gateway).  Built from the current source:
 * mutant/ without the "+ ETHER_ADDR_LEN" room (sdl_nlen only);
 * mutant_noclr/ without CLR(rt_flags, RTF_LLINFO) for a rejected
 * gateway; mutant_nodel/ without the RTM_DELETE of an existing llinfo;
 * mutant_noearly/ and mutant_nocloning/ without the CLR on the
 * early-return and RTF_CLONING paths.
 */
#define log	kern_log_model
#include "if_ether.c"
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

void
model_pool_init(struct pool *pp, size_t size, u_int align, int ipl,
    int flags, const char *wchan, struct pool_allocator *palloc)
{
	pp->pr_size = size;
}

struct mbuf *
model_m_gethdr(int nowait, int type)
{
	struct mbuf *m;

	if (nondet_bool())
		return (NULL);
	m = CBMC_NEW(struct mbuf);
	m->m_type = type;
	m->m_data = m->m_pktdat;
	m->m_flags = M_PKTHDR;
	return (m);
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

int
model_if_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	m_freem(m);
	return (0);
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
 * What the consumers of an ARP entry (arpresolve, arpcache, arpproxy,
 * in_arpinput through arplookup) rely on when RTF_LLINFO is set: an
 * AF_LINK gateway whose sdl_alen is 0 or ETHER_ADDR_LEN and that has
 * room for an Ethernet address at LLADDR, which arpcache stores there.
 */
static void
check_entry(struct rtentry *rt, int req)
{
	struct sockaddr *gate = rt->rt_gateway;
	struct sockaddr_dl *sdl = satosdl(gate);

	if (rt->rt_llinfo == NULL && !ISSET(rt->rt_flags, RTF_LLINFO))
		return;
	__CPROVER_assert(gate->sa_family == AF_LINK,
	    "post: RTF_LLINFO gateway is AF_LINK");
	__CPROVER_assert(gate->sa_len >= sizeof(struct sockaddr_dl),
	    "post: RTF_LLINFO gateway holds a sockaddr_dl");
	__CPROVER_assert(sdl->sdl_alen == 0 || sdl->sdl_alen == ETHER_ADDR_LEN,
	    "post: RTF_LLINFO sdl_alen is 0 or ETHER_ADDR_LEN");
	__CPROVER_assert(offsetof(struct sockaddr_dl, sdl_data) +
	    sdl->sdl_nlen + ETHER_ADDR_LEN <= gate->sa_len,
	    "post: RTF_LLINFO gateway has room for LLADDR .. + 6");
}

#define FMASK_NO_MPLS	(RTF_LLINFO | RTF_PROTO1 | RTF_PROTO2 | \
	RTF_PROTO3 | RTF_BLACKHOLE | RTF_REJECT | RTF_STATIC | RTF_BFD)

int
main(void)
{
	struct ifnet *ifp;
	struct rtentry *rt;
	struct sockaddr_in *dst;
	unsigned char *obj, *nobj;
	int req;

	arpinit();

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_output = model_if_output;
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_uint();
	ifp->if_rdomain = nondet_uint();
	ifp->if_llprio = nondet_uchar();

	dst = CBMC_NEW(struct sockaddr_in);
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;

	rt = CBMC_NEW(struct rtentry);
	rt->rt_flags = nondet_uint();
	rt->rt_dest = sintosa(dst);
	rt->rt_gateway = build_gate(&obj);
	rt->rt_llinfo = NULL;

	/* rtrequest: a new route, RTM_ADD, or a clone, RTM_RESOLVE */
	req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
	/* rtrequest RTM_RESOLVE: a clone never has these (route.c) */
	if (req == RTM_RESOLVE)
		rt->rt_flags &= ~(RTF_CLONING|RTF_CONNECTED|RTF_STATIC);
	arp_rtrequest(ifp, req, rt);
	check_entry(rt, req);

	/*
	 * route_output RTM_CHANGE (rtsock.c): rt_setgate() installs a new
	 * gateway when its bytes differ (the family check before it only
	 * runs when they do not), the flags in RTF_FMASK but RTF_MPLS may
	 * be toggled, then if_rtrequest(RTM_ADD).
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
		arp_rtrequest(ifp, RTM_ADD, rt);
		check_entry(rt, RTM_ADD);
	}

	/* teardown by the kernel's own code, then what the harness made */
	arp_rtrequest(ifp, RTM_DELETE, rt);
	__CPROVER_assert(rt->rt_llinfo == NULL, "teardown: llinfo removed");

	harness_release(rt);
	harness_release(dst);
	harness_release(obj);
	harness_release(ifp);
	return (0);
}
