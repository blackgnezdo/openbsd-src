/*
 * Harness: rtm_output() of sys/net/rtsock.c, RTM_ADD that finds an
 * existing RTF_CACHED entry (the L2 entry of a gateway route, an ARP
 * entry), and so takes "goto change" with newgate 0.  rtsock.c is
 * #included so that its static declarations match (listed in "included").
 *
 * The code under test (rtsock.c, rtm_output, case RTM_ADD, then label
 * change:): for a cached entry the L2 entry is updated in place instead
 * of through delete/create/insert.  The gateway of the message replaces
 * the entry's gateway, after
 *	if (!newgate && rt->rt_gateway->sa_family !=
 *	    info->rti_info[RTAX_GATEWAY]->sa_family) { error = EINVAL; break; }
 * which refuses a gateway of another address family (3bb04c23e89, "Prevent
 * bgpd(8) to corrupt ARP entries").  newgate is 0 on this path (it is set
 * only in RTM_CHANGE), so the check is always made.  9264ea9da limited it
 * to newgate != 0, which never holds here: the check was gone (reverted in
 * 81bf8c4f0); that file is mutant/.
 *
 * Property (asserted after the call):
 *  P-A  return 0 => the entry's gateway is AF_LINK (the brief);
 *  P-B  on every return the entry's gateway is AF_LINK and holds a
 *       sockaddr_dl (sa_len >= 32): the consumers (arpresolve, arplookup,
 *       arpcache) read it as one.  P-A is the case error == 0 of P-B, kept
 *       as its own message;
 *  P-C  exact result: ESRCH when if_get failed (before the check); else
 *       EINVAL for a gateway of another family than AF_LINK, 0 or ENOBUFS
 *       (rt_setgate's malloc failed) for an AF_LINK one;
 *  P-D  the interface hook ran exactly once on success and not at all on
 *       an error return (all "break"s that fail come before it);
 *  P-E  reference counts: the entry keeps the table's reference, and rt
 *       returned in *prt holds exactly the one taken by rtable_match (NULL
 *       when rtm_output released it); the interface reference is returned;
 *  and: no out-of-bounds access, no leak or double free
 *  (--memory-leak-check), including the gateway the entry holds at the
 *  end (the harness frees it).
 *
 * What the callers guarantee (checked against the source):
 *  route_output (rtsock.c, by line at the time of writing):
 *   - rtm_type is RTM_ADD (the case under test).
 *   - ~766: RTF_LOCAL and RTF_BROADCAST in rtm_flags => EINVAL before
 *     rtm_output; so rtm_flags here has neither.
 *   - ~783: rtm_flags &= ~(RTF_DONE|RTF_CLONED|RTF_CACHED); rtm_fmask &=
 *     RTF_FMASK.  rtm_output then clears RTF_MPLS from both (the line
 *     before the toggle), so MPLS needs no handling; RTF_FMASK has no
 *     RTF_GATEWAY and no RTF_CACHED: the toggle cannot add them.
 *   - ~810: info.rti_flags = rtm_flags (after the masking above).
 *   - ~812: rti_info[DST] != NULL with sa_family < AF_MAX; a gateway has
 *     sa_family < AF_MAX; rti_info[GENMASK] == NULL.  RTAX_NETMASK may be
 *     set by a user; here it is NULL (the path reads it only for
 *     if_group_routechange, which is a model).
 *   - ~822: info.rti_flags |= RTF_LLINFO for a gateway with sa_family
 *     AF_LINK unless RTF_CLONING is in rti_flags.  Modelled exactly so.
 *     It is only read by route_arp_conflict (which returns 0 for a cached
 *     entry whatever the flags are: RTF_CACHED => 0, no RTF_LLINFO => 0).
 *   - rtm_xaddrs (net/rtm_xaddrs P3): DST and GATEWAY of family AF_INET
 *     have sa_len >= 16, AF_LINK >= 32, AF_INET6 >= 28, other families no
 *     promise; sa + sa_len <= cplim and at least sizeof(socklen_t) = 4
 *     bytes lie in the message (P1).  So the gateway here has an
 *     arbitrary family < AF_MAX, a length clamped up to the family's
 *     minimum, and lies at the END of an object of max(sa_len, 4) bytes
 *     (the message buffer ends there; a longer message would only hide
 *     an over-read), at the end of a 264 byte constant object.  The bytes
 *     other than sa_len and sa_family are zero: nothing on the path reads
 *     them, the copy in rt_setgate copies them.  The DST is a sockaddr_in
 *     (sa_len 16).  Other rti_info slots are NULL.
 *   - tableid: rtm_output is called with 0; the models ignore it.
 *  The entry (an ARP entry used as the L2 entry of a RTF_GATEWAY route,
 *  rt_setgwroute/rt_putgwroute in route.c):
 *   - rt_flags RTF_UP|RTF_CACHED|RTF_LLINFO|RTF_HOST (rt_putgwroute sets
 *     CACHED; ARP entries are host routes with LLINFO) and an arbitrary
 *     subset of CLONED, STATIC, PROTO1, PROTO2 (ANNOUNCE), PROTO3,
 *     BLACKHOLE, REJECT, MPATH, DYNAMIC, MODIFIED.  Not GATEWAY or
 *     CLONING (rt_setgwroute refuses a next hop with either, route.c ~545),
 *     not LOCAL, BROADCAST, MULTICAST, CONNECTED (own routes, other
 *     kinds), no MPLS, no BFD (not compiled).
 *   - rt_gateway: what arp_rtrequest guarantees for an entry with
 *     RTF_LLINFO (netinet/arp_rtrequest check_entry): AF_LINK, sa_len >=
 *     sizeof(struct sockaddr_dl), sdl_alen 0 or 6, offsetof(sdl_data) +
 *     sdl_nlen + 6 <= sa_len; built by arithmetic, at the end of a 264
 *     byte object, ROUNDUP(sa_len) bytes, as rt_setgate leaves it.
 *   - rt_llinfo: NULL or a non-NULL object (the la of arp_rtrequest, not
 *     read by this path), rt_ifidx the interface's index (arbitrary),
 *     rt_dest a sockaddr_in, rt_ifa NULL (nothing here releases it),
 *     rt_refcnt 1: the routing table's reference.
 *
 * Configuration: INET6 is defined as config(8) would for the kernel
 * (cbmc.sh cannot pass -D).  MPLS, BFD and IPSEC are not defined, as in
 * net/rtm_xaddrs: their branches (rt_mpls_set, rt_mpls_clear, bfdset,
 * bfdclear) are not compiled and the code after the gateway change runs
 * without them.
 *
 * Models (replace file); each model is the same function natively:
 *  rtable_match   returns the entry and takes a reference (refcnt + 1);
 *                 never NULL (a NULL result is the other path, rtrequest,
 *                 not under test); checks it got the message's DST.
 *  rtfree         the real one frees at 0; the entry has the table's
 *                 reference, so the model asserts the count stays >= 1
 *                 and decrements (an entry freed here would be a bug).
 *  if_get/if_put  the ifp (CBMC_NEW) with a reference count, or NULL
 *                 (arbitrary: the interface went away, ESRCH); if_put
 *                 checks the ifp and returns the reference.  The ifp's
 *                 if_rtrequest is model_if_rtrequest, bound through
 *                 fptargets for every call site of rtm_output: it records
 *                 the call (req and rt checked) and does nothing else;
 *                 arp_rtrequest itself is the target netinet/arp_rtrequest.
 *  rt_setgate     route.c: glen = ROUNDUP(sa_len); malloc(glen, M_NOWAIT |
 *                 M_ZERO) may fail (ENOBUFS, old gateway kept); memcpy
 *                 sa_len bytes; install; free the old one with ROUNDUP of
 *                 its sa_len.  No RTF_GATEWAY handling (rt_setgwroute):
 *                 the entry never has RTF_GATEWAY (above).  The object
 *                 is a constant 264 bytes with the gateway at its end
 *                 (ROUNDUP(sa_len) bytes, as the real malloc gives), not a
 *                 malloc of symbolic size (README, "When a run exhausts
 *                 time or memory", 1); the old gateway is freed through
 *                 the base pointer the harness keeps, and the model
 *                 asserts that it lies exactly ROUNDUP(sa_len) bytes
 *                 before the end, which is what free(9)'s size
 *                 argument claims.
 *  if_group_routechange  does nothing, checks DST.
 *  gettime, getuptime  a 32 bit unsigned value (see model_gettime).
 * Kept: rtm_output, route_arp_conflict, rtm_setmetrics (all in the
 * included file).  rtlabel_unref and rtlabel_name2id are not reached:
 * rti_info[RTAX_LABEL] is NULL, so no model is needed.  Bodiless (NOBODY
 * line of a run): the locks (rw_enter_write, rw_exit_write); they
 * protect nothing in a single thread, as in the other targets.
 *
 * Mutants (suite.sh -m, both VIOLATED): mutant/ is 9264ea9da's rtsock.c
 * (the family check limited to newgate != 0); mutant_nocheck/ has the
 * whole check removed.
 */
#define INET6	1
#include "rtsock.c"
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

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN	6
#endif
#define GATE_OBJ	64	/* ROUNDUP(sa_len) of at most 64 (real: 255) */
#define MAXSALEN	64
/* ROUNDUP of route.c */
#define RT_ROUNDUP(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)

static struct rtentry	*g_rt;		/* the cached entry */
static struct ifnet	*g_ifp;
static unsigned char	*g_gate_base;	/* object holding rt->rt_gateway */
static int		 g_ifp_refs;
static int		 g_rtreq;	/* calls of the interface hook */
static int		 g_ifget_failed;	/* if_get returned NULL */

struct rtentry *
model_rtable_match(unsigned int tableid, const struct sockaddr *dst,
    uint32_t *src)
{
	__CPROVER_assert(dst != NULL && dst->sa_family == AF_INET,
	    "rtable_match model: DST of the message");
	g_rt->rt_refcnt.r_refs++;
	return (g_rt);
}

void
model_rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt == g_rt, "rtfree model: the entry");
	__CPROVER_assert(rt->rt_refcnt.r_refs >= 2,
	    "rtfree model: the table's reference stays");
	rt->rt_refcnt.r_refs--;
}

struct ifnet *
model_if_get(unsigned int ifidx)
{
	__CPROVER_assert(ifidx == g_rt->rt_ifidx, "if_get model: rt_ifidx");
	if (nondet_bool()) {
		g_ifget_failed = 1;
		return (NULL);
	}
	g_ifp_refs++;
	return (g_ifp);
}

void
model_if_put(struct ifnet *ifp)
{
	if (ifp == NULL)
		return;
	__CPROVER_assert(ifp == g_ifp && g_ifp_refs > 0,
	    "if_put model: the ifp, a reference held");
	g_ifp_refs--;
}

void
model_if_rtrequest(struct ifnet *ifp, int req, struct rtentry *rt)
{
	__CPROVER_assert(ifp == g_ifp && rt == g_rt && req == RTM_ADD,
	    "if_rtrequest model: RTM_ADD on the entry");
	g_rtreq++;
}

void
model_if_group_routechange(const struct sockaddr *dst,
    const struct sockaddr *mask)
{
	__CPROVER_assert(dst != NULL && dst->sa_family == AF_INET &&
	    mask == NULL, "if_group_routechange model: DST, no netmask");
}

/*
 * rtm_setmetrics does "expire -= gettime(); expire += getuptime()" on
 * the 64 bit rmx_expire of the message: signed overflow (undefined) for
 * rmx_expire near INT64_MIN with a positive time, which the code does
 * not prevent.  Not what this target is about (and no effect on the
 * gateway): the harness keeps rmx_expire to 32 bits and the clocks
 * (bodiless: arbitrary values, in particular arbitrary 64 bit ones
 * natively) to 32 bits, so that UBSan (native.sh) does not stop on it.
 */
time_t
model_gettime(void)
{
	return ((time_t)nondet_uint());
}

int
model_rt_setgate(struct rtentry *rt, const struct sockaddr *gate,
    u_int rtableid)
{
	int glen = RT_ROUNDUP(gate->sa_len);
	struct sockaddr *sa, *osa;
	unsigned char *obj;

	__CPROVER_assert(!ISSET(rt->rt_flags, RTF_GATEWAY),
	    "rt_setgate model: no RTF_GATEWAY handling needed");
	if (rt->rt_gateway == gate)
		return (0);
	if (nondet_bool())
		return (ENOBUFS);		/* M_NOWAIT */
	obj = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	sa = (struct sockaddr *)(obj + GATE_OBJ - glen);
	memcpy(sa, gate, gate->sa_len);
	osa = rt->rt_gateway;
	rt->rt_gateway = sa;
	if (osa != NULL) {
		__CPROVER_assert((unsigned char *)osa == g_gate_base +
		    GATE_OBJ - RT_ROUNDUP(osa->sa_len),
		    "rt_setgate model: old gateway size is ROUNDUP(sa_len)");
		harness_release(g_gate_base);
	}
	g_gate_base = obj;
	return (0);
}

/* flags an ARP entry that serves as a gateway's L2 entry can have */
#define ENTRY_OPT	(RTF_CLONED | RTF_STATIC | RTF_PROTO1 | RTF_PROTO2 | \
	RTF_PROTO3 | RTF_BLACKHOLE | RTF_REJECT | RTF_MPATH | RTF_DYNAMIC | \
	RTF_MODIFIED)

int
main(void)
{
	struct rt_msghdr *rtm;
	struct rt_addrinfo info;
	struct rtentry *rt, *prt;
	struct sockaddr_in *dst;
	struct sockaddr *gate;
	struct sockaddr_dl *sdl;
	unsigned char *gobj, *mobj;
	unsigned int sa_len, nlen, glen, fam, minlen;
	int error, expect_gate_af_link;

	g_ifp = CBMC_NEW(struct ifnet);
	g_ifp->if_rtrequest = model_if_rtrequest;
	g_ifp->if_index = nondet_uint();
	g_ifp_refs = 0;
	g_rtreq = 0;
	g_ifget_failed = 0;

	/* the existing entry, as the ARP code leaves a cache entry */
	dst = CBMC_NEW(struct sockaddr_in);
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;

	rt = CBMC_NEW(struct rtentry);
	g_rt = rt;
	rt->rt_dest = sintosa(dst);
	rt->rt_flags = RTF_UP | RTF_CACHED | RTF_LLINFO | RTF_HOST |
	    (nondet_uint() & ENTRY_OPT);
	rt->rt_ifidx = g_ifp->if_index;
	rt->rt_refcnt.r_refs = 1;		/* the table's reference */
	if (nondet_bool())
		rt->rt_llinfo = CBMC_NEW_ARRAY(char, 64);

	/* AF_LINK gateway: sa_len >= 32, alen 0 or 6, 8 + nlen + 6 <= sa_len */
	sa_len = nondet_uchar();
	if (sa_len < sizeof(struct sockaddr_dl))
		sa_len = sizeof(struct sockaddr_dl);
	if (sa_len > MAXSALEN)
		sa_len = MAXSALEN;
	nlen = nondet_uchar();
	if (nlen > sa_len - (offsetof(struct sockaddr_dl, sdl_data) +
	    ETHER_ADDR_LEN))
		nlen = sa_len - (offsetof(struct sockaddr_dl, sdl_data) +
		    ETHER_ADDR_LEN);
	g_gate_base = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(g_gate_base + GATE_OBJ -
	    RT_ROUNDUP(sa_len));
	gate->sa_len = sa_len;
	gate->sa_family = AF_LINK;
	sdl = satosdl(gate);
	sdl->sdl_nlen = nlen;
	sdl->sdl_alen = nondet_bool() ? ETHER_ADDR_LEN : 0;
	rt->rt_gateway = gate;

	/* the message, as route_output hands it on (see the header) */
	rtm = CBMC_NEW(struct rt_msghdr);
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_flags = nondet_int();
	rtm->rtm_flags &= ~(RTF_DONE | RTF_CLONED | RTF_CACHED |
	    RTF_LOCAL | RTF_BROADCAST);
	rtm->rtm_fmask = nondet_int() & RTF_FMASK;
	rtm->rtm_inits = nondet_uint();
	rtm->rtm_rmx.rmx_locks = nondet_uint();
	rtm->rtm_rmx.rmx_mtu = nondet_uint();
	/* 32 bit range: see model_gettime */
	rtm->rtm_rmx.rmx_expire = nondet_int();

	/* gateway of the message: any family < AF_MAX, rtm_xaddrs P1, P3 */
	fam = nondet_uchar() % AF_MAX;
	switch (fam) {
	case AF_INET:
		minlen = sizeof(struct sockaddr_in);
		break;
	case AF_LINK:
		minlen = sizeof(struct sockaddr_dl);
		break;
	case AF_INET6:
		minlen = sizeof(struct sockaddr_in6);
		break;
	default:
		minlen = 0;
		break;
	}
	sa_len = nondet_uchar();
	if (sa_len < minlen)
		sa_len = minlen;
	if (sa_len > MAXSALEN)
		sa_len = MAXSALEN;
	glen = sa_len < sizeof(socklen_t) ? sizeof(socklen_t) : sa_len;
	gobj = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(gobj + GATE_OBJ - glen);
	gate->sa_len = sa_len;
	gate->sa_family = fam;

	bzero(&info, sizeof(info));
	info.rti_addrs = (1 << RTAX_DST) | (1 << RTAX_GATEWAY);
	info.rti_info[RTAX_DST] = sintosa(CBMC_NEW(struct sockaddr_in));
	((struct sockaddr_in *)info.rti_info[RTAX_DST])->sin_len =
	    sizeof(struct sockaddr_in);
	((struct sockaddr_in *)info.rti_info[RTAX_DST])->sin_family = AF_INET;
	info.rti_info[RTAX_GATEWAY] = gate;
	info.rti_flags = rtm->rtm_flags;
	/* route_output, rtsock.c ~822 */
	if (info.rti_info[RTAX_GATEWAY]->sa_family == AF_LINK &&
	    (info.rti_flags & RTF_CLONING) == 0)
		info.rti_flags |= RTF_LLINFO;

	prt = NULL;
	error = rtm_output(rtm, &prt, &info, nondet_uchar(), 0);

	/* what route_output does next with the entry: rtfree(rt) */
	if (prt != NULL)
		rtfree(prt);

	/* properties */
	if (error == 0)
		__CPROVER_assert(rt->rt_gateway->sa_family == AF_LINK,
		    "P-A: RTM_ADD to a cached entry returned 0, gateway AF_LINK");
	__CPROVER_assert(rt->rt_gateway->sa_family == AF_LINK,
	    "P-B: cached entry's gateway is AF_LINK");
	__CPROVER_assert(rt->rt_gateway->sa_len >= sizeof(struct sockaddr_dl),
	    "P-B: cached entry's gateway holds a sockaddr_dl");
	/*
	 * P-C is exact: ESRCH if and only if if_get failed; otherwise a
	 * gateway of another family is EINVAL, and one of family AF_LINK
	 * goes through (0, or ENOBUFS from rt_setgate).  A verified P-C
	 * means the family check's "error = EINVAL" is reached for every
	 * such input: it is not a must_reach anchor, because the lines
	 * of that check are the ones the mutants remove (README gap).
	 */
	__CPROVER_assert((error == ESRCH) == (g_ifget_failed != 0),
	    "P-C: ESRCH exactly when if_get failed");
	if (!g_ifget_failed) {
		if (gate->sa_family != AF_LINK)
			__CPROVER_assert(error == EINVAL,
			    "P-C: gateway of another family is EINVAL");
		else
			__CPROVER_assert(error == 0 || error == ENOBUFS,
			    "P-C: AF_LINK gateway is accepted");
	}
	__CPROVER_assert(g_rtreq == (error == 0 ? 1 : 0),
	    "P-D: interface hook ran once on success only");
	__CPROVER_assert(rt->rt_refcnt.r_refs == 1,
	    "P-E: only the table's reference is left");
	__CPROVER_assert(g_ifp_refs == 0, "P-E: interface reference returned");

	/* free what the harness owns, the gateway the entry holds now too */
	harness_release(g_gate_base);
	harness_release(gobj);
	harness_release((void *)info.rti_info[RTAX_DST]);
	harness_release(rt->rt_llinfo);
	harness_release(rtm);
	harness_release(dst);
	harness_release(rt);
	harness_release(g_ifp);
	return (0);
}
