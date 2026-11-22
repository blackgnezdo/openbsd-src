/*
 * Harness: the consumers of an ARP route's gateway in sys/netinet/
 * if_ether.c, arpresolve(), arpcache() and arpinvalidate(), on a route
 * whose gateway satisfies the invariant netinet/arp_rtrequest proves.
 * if_ether.c is #included (static and global objects, arp_pool etc.).
 *
 * Assume/guarantee split.  netinet/arp_rtrequest guarantees: when
 * RTF_LLINFO is set or rt_llinfo is not NULL, the gateway is AF_LINK,
 * sa_len >= sizeof(struct sockaddr_dl) (32), sdl_alen is 0 or
 * ETHER_ADDR_LEN, and offsetof(sdl_data) (8) + sdl_nlen + ETHER_ADDR_LEN
 * <= sa_len; the gateway object is exactly ROUNDUP(sa_len) bytes
 * (rt_setgate).  This target ASSUMES it (build_gate_inv builds the
 * gateway with arithmetic, check_entry is the same predicate) and
 * GUARANTEES: no out-of-bounds access, no leak or double free, and the
 * invariant still holds after each consumer (arpcache sets sdl_alen to 6,
 * arpinvalidate to 0).
 *
 * Calls, on one route, each optional (nondet), in this order:
 *   arpresolve(ifp, rt, m, dst, desten)   reads sdl_alen bytes at LLADDR
 *                                         into the 6 byte desten; may
 *                                         queue m on la_mq, send ARP
 *                                         requests (arprequest, real body)
 *   arpcache(ifp, ea, rt)                 memcmp of sdl_alen bytes at
 *                                         LLADDR, then sdl_alen = 6 and a
 *                                         6 byte write at LLADDR; sends
 *                                         the held packets
 *   arpinvalidate(rt)                     purges la_mq, sdl_alen = 0
 * so arpresolve alone, arpcache alone, and both in this order (the
 * mbuf queued by arpresolve is sent by arpcache; arpcache first then
 * arpresolve is not a separate sequence: the invariant allows sdl_alen 6
 * at the start, which gives arpresolve the same state).
 *
 * Not covered, a separate target: the proxy paths (arpproxy,
 * in_arpinput's proxy branch, arplookup's loop).  Not called: arplookup,
 * in_arpinput, arptfree, arp_rtrequest (the producer).  rtisvalid is not
 * reached by these functions.
 *
 * The route (arithmetic only, no __CPROVER_assume):
 *  - rt_flags arbitrary | RTF_LLINFO (so also RTF_GATEWAY, RTF_REJECT,
 *    RTF_PERMANENT_ARP, RTF_LOCAL ...), rt_expire arbitrary (0 <= t < 2^40),
 *    rt_ifidx arbitrary, rt_dest and rt_ifa->ifa_addr valid sockaddr_in.
 *  - gateway: sa_len 32..255, AF_LINK, sdl_nlen 0..sa_len-14, sdl_alen 0
 *    or 6, at the END of a constant 264 byte object (264 = ROUNDUP(255)),
 *    ROUNDUP(sa_len) bytes from there, so any access past the rounded
 *    length is out of bounds under both engines.  sdl_data bytes are zero
 *    (arbitrary content only changes the memcmp result, which ea already
 *    makes arbitrary).  Values are clamped, not assumed, so the
 *    distribution is skewed towards sa_len 32 and the largest nlen; every
 *    value of the invariant is reachable.
 *  - rt_llinfo: NULL or a real llinfo_arp (CBMC_NEW, mq_init'ed hold
 *    queue, empty or with one mbuf already held), la_asked 0..255 (the kernel keeps it <= arp_maxtries; an int
 *    near INT_MAX overflows in la_asked++) and la_refreshed arbitrary, la_hold_total arbitrary (both limit paths).
 *  - rt_gwroute (used through rt_getll when RTF_GATEWAY is set): NULL or
 *    a second route "other" WITHOUT RTF_LLINFO and without llinfo, whose
 *    gateway is arbitrary (any family, sa_len 0..255, any nlen/alen, laid
 *    out like build_gate of netinet/arp_rtrequest).  The invariant says
 *    nothing about it, so arpresolve must refuse it by the RTF_LLINFO
 *    test; a gwroute WITH RTF_LLINFO is the main route over again, so
 *    it is not drawn.
 *  - ea: struct ether_arp of exactly its size, the address fields
 *    (arp_sha, arp_spa, arp_tha, arp_tpa) arbitrary, the 8 byte header
 *    zero (arpcache does not read it).  desten: 6 byte object.
 *  - m: one mbuf (CBMC_NEW), m_flags arbitrary (M_BCAST, M_MCAST and
 *    the plain path).  arpresolve returns 0: m is untouched, the harness
 *    frees it; any other value: the function consumed it (freed or
 *    queued on la_mq, which the teardown purges).
 *  - ifp: a struct arpcom (arprequest reads ac_enaddr), if_index,
 *    if_flags, if_rdomain, if_llprio arbitrary.
 *
 * Models (replace file), each also what native.sh runs:
 *  m_gethdr         one mbuf from CBMC_NEW or NULL (M_DONTWAIT may fail),
 *                   as in netinet/arp_rtrequest.
 *  m_freem          frees one unchained mbuf (asserts m_next is NULL),
 *                   returns its m_nextpkt like the kernel's; NULL
 *                   tolerated.
 *  model_if_output  (fptargets, arprequest's ifp->if_output) a driver:
 *                   frees the mbuf.
 *  getuptime        arbitrary, 0 <= t < 2^40 (see NONDET_TIME).
 *  rt_getll         the kernel's body (RTF_GATEWAY: rt_gwroute, else rt);
 *                   a model only because route.c is not in sources.
 *  if_isconnected   arbitrary result, reads nothing.
 *  if_get           NULL or the harness' ifp, if_put does nothing (the
 *                   result is only used for if_xname as an argument of
 *                   the bodiless log).
 *  if_output_mq     what net/if.c does with the held packets: mq_delist,
 *                   every packet to the driver (freed), total reduced
 *                   by their number.  The real if_output_ml reaches
 *                   ifp->if_output, i.e. ether_output and so arpresolve
 *                   again for the packets; not followed.
 *  rtm_send         asserts the whole gateway (sa_len bytes) is readable,
 *                   as rtm_msg1 copies it into the message to userland.
 * Kernel bodies kept (keep): m_align, mq_init, mq_push, mq_purge,
 * mq_delist, ml_init, ml_enqueue, ml_dequeue, ml_purge.  Bodiless
 * (nobody): kern_log_model (log is #defined to it), mtx_enter, mtx_leave (single thread), inet_ntop and
 * ether_sprintf (their results and the char buffer addr only go into
 * log's arguments, never read); also by default rw_status,
 * splassert_fail (NET_ASSERT_LOCKED_EXCLUSIVE) and __mtx_init (mq_init):
 * no out-parameters, no state the target checks.
 *
 * Mutants (suite.sh -m, VIOLATED): mutant/ without arpresolve's
 * RTF_LLINFO test (a gwroute without the flag has an arbitrary gateway;
 * memcpy from LLADDR reads past it); mutant_nola/ without arpcache's
 * la == NULL return (NULL dereference of la; not a gateway property).
 * The tests of sdl_alen and sdl_family in arpresolve and of sdl_alen > 0
 * in arpcache are redundant under the invariant (alen is 0 or 6, family
 * AF_LINK) and no mutant of them is VIOLATED.
 *
 * Reductions: the bounds above; at most one mbuf already held before
 * the calls plus the one of arpresolve (queue length <= 2 for
 * --unwind 4); ea header and sdl_data zero.
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

u_int8_t etherbroadcastaddr[ETHER_ADDR_LEN];	/* all ones in the kernel */

static struct ifnet *the_ifp;

/*
 * Times: time_t values the kernel produces are seconds since boot or
 * 0, never negative and far below 2^40 (35000 years); arpcache adds
 * arpt_keep to uptime and arpresolve subtracts from rt_expire, which
 * overflows (UBSan, native engine) for values near the limits of
 * time_t.  Masked, not assumed.
 */
#define NONDET_TIME()	(nondet_long() & 0xffffffffffL)

time_t
model_getuptime(void)
{
	return (NONDET_TIME());
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
	struct mbuf *n;

	if (m == NULL)
		return (NULL);
	__CPROVER_assert(m->m_next == NULL, "m_freem model: single mbuf");
	n = m->m_nextpkt;	/* as the kernel's: the next packet, kept */
	harness_release(m);
	return (n);
}

int
model_if_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	m_freem(m);
	return (0);
}

struct rtentry *
model_rt_getll(struct rtentry *rt)
{
	if (ISSET(rt->rt_flags, RTF_GATEWAY))
		return (rt->rt_gwroute);
	return (rt);
}

int
model_if_isconnected(const struct ifnet *ifp, unsigned int ifidx)
{
	return (nondet_bool());
}

struct ifnet *
model_if_get(unsigned int ifidx)
{
	return (nondet_bool() ? NULL : the_ifp);
}

void
model_if_put(struct ifnet *ifp)
{
}

int
model_if_output_mq(struct ifnet *ifp, struct mbuf_queue *mq,
    unsigned int *total, struct sockaddr *dst, struct rtentry *rt)
{
	struct mbuf_list ml;
	unsigned int len;

	mq_delist(mq, &ml);
	len = ml_len(&ml);
	ml_purge(&ml);		/* the driver frees what it was given */
	atomic_sub_int(total, len);
	return (0);
}

void
model_rtm_send(struct rtentry *rt, int cmd, int error, unsigned int rtableid)
{
	__CPROVER_assert(__CPROVER_r_ok(rt->rt_gateway,
	    rt->rt_gateway->sa_len), "rtm_send: gateway readable");
}

/*
 * A gateway satisfying the invariant, as rt_setgate() leaves it:
 * ROUNDUP(sa_len) bytes at the end of a GATE_OBJ byte object.
 */
static struct sockaddr *
build_gate_inv(unsigned char **objp)
{
	struct sockaddr *gate;
	struct sockaddr_dl *sdl;
	unsigned int sa_len, nlen;
	int rounded;

	sa_len = nondet_uchar();
	if (sa_len < sizeof(struct sockaddr_dl))
		sa_len = sizeof(struct sockaddr_dl);
	nlen = nondet_uchar();
	if (nlen > sa_len - (offsetof(struct sockaddr_dl, sdl_data) +
	    ETHER_ADDR_LEN))
		nlen = sa_len - (offsetof(struct sockaddr_dl, sdl_data) +
		    ETHER_ADDR_LEN);
	rounded = ROUNDUP8(sa_len);
	*objp = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(*objp + GATE_OBJ - rounded);
	sdl = satosdl(gate);
	sdl->sdl_len = sa_len;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_nlen = nlen;
	sdl->sdl_alen = nondet_bool() ? 0 : ETHER_ADDR_LEN;
	return (gate);
}

/* An arbitrary gateway, the same as build_gate of netinet/arp_rtrequest. */
static struct sockaddr *
build_gate_any(unsigned char **objp)
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

/* The invariant of netinet/arp_rtrequest (its check_entry), the assumption. */
static void
check_entry(struct rtentry *rt)
{
	struct sockaddr *gate = rt->rt_gateway;
	struct sockaddr_dl *sdl = satosdl(gate);

	if (rt->rt_llinfo == NULL && !ISSET(rt->rt_flags, RTF_LLINFO))
		return;
	__CPROVER_assert(gate->sa_family == AF_LINK,
	    "inv: RTF_LLINFO gateway is AF_LINK");
	__CPROVER_assert(gate->sa_len >= sizeof(struct sockaddr_dl),
	    "inv: RTF_LLINFO gateway holds a sockaddr_dl");
	__CPROVER_assert(sdl->sdl_alen == 0 || sdl->sdl_alen == ETHER_ADDR_LEN,
	    "inv: RTF_LLINFO sdl_alen is 0 or ETHER_ADDR_LEN");
	__CPROVER_assert(offsetof(struct sockaddr_dl, sdl_data) +
	    sdl->sdl_nlen + ETHER_ADDR_LEN <= gate->sa_len,
	    "inv: RTF_LLINFO gateway has room for LLADDR .. + 6");
}

#define FILL4(a)	((a)[0] = nondet_uchar(), (a)[1] = nondet_uchar(), \
			 (a)[2] = nondet_uchar(), (a)[3] = nondet_uchar())
#define FILL6(a)	(FILL4(a), (a)[4] = nondet_uchar(), \
			 (a)[5] = nondet_uchar())

int
main(void)
{
	struct arpcom *ac;
	struct ifnet *ifp;
	struct rtentry *rt, *other = NULL;
	struct sockaddr_in *dst, *ia;
	struct ifaddr *ifa;
	struct llinfo_arp *la = NULL;
	struct ether_arp *ea;
	struct mbuf *m;
	u_char *desten;
	unsigned char *obj, *oobj = NULL;
	int err;

	ac = CBMC_NEW(struct arpcom);
	ifp = &ac->ac_if;
	the_ifp = ifp;
	ifp->if_output = model_if_output;
	ifp->if_index = nondet_uint();
	ifp->if_flags = nondet_uint();
	ifp->if_rdomain = nondet_uint();
	ifp->if_llprio = nondet_uchar();

	dst = CBMC_NEW(struct sockaddr_in);
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;
	dst->sin_addr.s_addr = nondet_uint();
	ia = CBMC_NEW(struct sockaddr_in);
	ia->sin_len = sizeof(*ia);
	ia->sin_family = AF_INET;
	ia->sin_addr.s_addr = nondet_uint();
	ifa = CBMC_NEW(struct ifaddr);
	ifa->ifa_addr = sintosa(ia);
	ifa->ifa_ifp = ifp;

	rt = CBMC_NEW(struct rtentry);
	rt->rt_flags = nondet_uint() | RTF_LLINFO;
	rt->rt_expire = NONDET_TIME();
	rt->rt_ifidx = nondet_uint();
	rt->rt_dest = sintosa(dst);
	rt->rt_ifa = ifa;
	rt->rt_gateway = build_gate_inv(&obj);
	if (nondet_bool()) {
		la = CBMC_NEW(struct llinfo_arp);
		la->la_rt = rt;
		mq_init(&la->la_mq, LA_HOLD_QUEUE, IPL_SOFTNET);
		la->la_asked = nondet_uchar();	/* real: 0..arp_maxtries; no int overflow */
		la->la_refreshed = NONDET_TIME();
		if (nondet_bool())
			mq_push(&la->la_mq, CBMC_NEW(struct mbuf));
		rt->rt_llinfo = (caddr_t)la;
	}
	la_hold_total = nondet_uint();
	if (ISSET(rt->rt_flags, RTF_GATEWAY) && nondet_bool()) {
		other = CBMC_NEW(struct rtentry);
		other->rt_flags = nondet_uint() &
		    ~(RTF_LLINFO | RTF_GATEWAY);
		other->rt_expire = NONDET_TIME();
		other->rt_ifidx = nondet_uint();
		other->rt_dest = sintosa(dst);
		other->rt_ifa = ifa;
		other->rt_gateway = build_gate_any(&oobj);
		rt->rt_gwroute = other;
	}

	ea = CBMC_NEW(struct ether_arp);
	FILL6(ea->arp_sha);
	FILL4(ea->arp_spa);
	FILL6(ea->arp_tha);
	FILL4(ea->arp_tpa);
	desten = CBMC_NEW_ARRAY(u_char, ETHER_ADDR_LEN);

	check_entry(rt);

	if (nondet_bool()) {
		m = CBMC_NEW(struct mbuf);
		m->m_flags = nondet_uint();
		m->m_data = m->m_pktdat;
		err = arpresolve(ifp, rt, m, sintosa(dst), desten);
		if (err == 0)
			m_freem(m);	/* not taken over */
		check_entry(rt);
	}
	if (nondet_bool()) {
		arpcache(ifp, ea, rt);
		check_entry(rt);
	}
	if (nondet_bool()) {
		arpinvalidate(rt);
		check_entry(rt);
	}

	/* teardown: what is still held, then what the harness made */
	if (la != NULL) {
		mq_purge(&la->la_mq);
		harness_release(la);
	}
	if (other != NULL) {
		harness_release(other);
		harness_release(oobj);
	}
	harness_release(rt);
	harness_release(obj);
	harness_release(ea);
	harness_release(desten);
	harness_release(ifa);
	harness_release(ia);
	harness_release(dst);
	harness_release(ac);
	return (0);
}
