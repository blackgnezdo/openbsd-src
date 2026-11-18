/*
 * Harness: arp_rtrequest() of sys/netinet/if_ether.c, with arprequest()
 * which it calls, on an arbitrary gateway sockaddr and arbitrary
 * rt_flags, for req RTM_ADD or RTM_RESOLVE, then the teardown
 * arp_rtrequest(ifp, RTM_DELETE, rt).  if_ether.c is #included so
 * that its static and global objects (arp_pool, arp_list, arp_mtx)
 * match.
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
 *  - rt is fresh: rt_llinfo NULL, rt_flags arbitrary (all 32 bits),
 *    rt_dest a valid sockaddr_in (rt_key), rt_gateway as above.
 *  - req is RTM_ADD or RTM_RESOLVE (the callers rtrequest1 and
 *    rtable_match use these two for a new route).
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
 *  - The hold queue la_mq stays empty (nothing here enqueues), so
 *    mq_purge in the teardown frees nothing.
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
 * postcondition: if the gateway was accepted (rt_llinfo != NULL) it is
 * AF_LINK and LLADDR(gate) .. + sdl_alen lies inside the sa_len bytes
 * that rt_setgate copied.
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

int
main(void)
{
	struct ifnet *ifp;
	struct rtentry *rt;
	struct sockaddr_in *dst;
	struct sockaddr *gate;
	unsigned char *obj;
	unsigned int sa_len;
	int req, rounded;

	arpinit();

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_output = model_if_output;
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_uint();
	ifp->if_rdomain = nondet_uint();
	ifp->if_llprio = nondet_uchar();

	/* the gateway: ROUNDUP(sa_len) bytes at the end of a 264 byte object */
	sa_len = nondet_uchar();
	rounded = ROUNDUP8(sa_len);
	obj = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(obj + GATE_OBJ - rounded);
	gate->sa_len = sa_len;
	if (sa_len >= 2)
		gate->sa_family = nondet_bool() ? AF_LINK : nondet_uchar();
	if (sa_len >= 6)
		satosdl(gate)->sdl_nlen = nondet_uchar();
	if (sa_len >= 7)
		satosdl(gate)->sdl_alen = nondet_uchar();

	dst = CBMC_NEW(struct sockaddr_in);
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;

	rt = CBMC_NEW(struct rtentry);
	rt->rt_flags = nondet_uint();
	rt->rt_dest = sintosa(dst);
	rt->rt_gateway = gate;
	rt->rt_llinfo = NULL;

	req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
	arp_rtrequest(ifp, req, rt);

	if (rt->rt_llinfo != NULL) {
		struct sockaddr_dl *sdl = satosdl(gate);

		__CPROVER_assert(gate->sa_family == AF_LINK,
		    "post: accepted gateway is AF_LINK");
		__CPROVER_assert(gate->sa_len >= sizeof(struct sockaddr_dl),
		    "post: accepted gateway holds a sockaddr_dl");
		__CPROVER_assert(offsetof(struct sockaddr_dl, sdl_data) +
		    sdl->sdl_nlen + sdl->sdl_alen <= gate->sa_len,
		    "post: LLADDR .. + sdl_alen lies inside sa_len");
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
