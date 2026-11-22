/*
 * Harness: the proxy ARP lookups of sys/netinet/if_ether.c, arpproxy()
 * and arplookup(..., SIN_PROXY, ...) as in_arpinput() uses it, on a
 * route table of NROUTES routes under one key (a multipath chain).
 *
 * Route table model.  Each route is built as netinet/arp_rtrequest
 * builds one (arbitrary rt_flags, an arbitrary gateway laid out as
 * rt_setgate leaves it) and then put through the real arp_rtrequest()
 * (RTM_ADD, or RTM_RESOLVE without the flags rtrequest clears for a
 * clone), so every route is in a state the kernel can produce.  The
 * routes are chained through rt_next, as rtable keeps a multipath
 * chain.  rtalloc returns the head of the chain with a reference, or
 * NULL; rtable_iterate is the kernel's body (next on the chain with a
 * reference, then rtfree of the current one); rtref and rtfree count
 * references; rtisvalid is the kernel's body.  if_get returns the one
 * interface or NULL.  NROUTES is 2: the smallest table in which the
 * proxy loop runs (a first route without RTF_ANNOUNCE, a second with
 * it).
 *
 * Properties: no out-of-bounds access (arpproxy's memcmp at LLADDR of
 * the proxy route's gateway; in_arpinput's proxy branch passes
 * LLADDR of the route arplookup returns to arpreply, which copies
 * ETHER_ADDR_LEN bytes: the harness does that copy), no leak, and
 * every reference taken is dropped (r_refs back to 1 on each route).
 *
 * ifp->if_sadl is a link address as if_alloc_sadl builds it for an
 * Ethernet interface: 32 bytes, sdl_nlen 0..18, sdl_alen 6.
 *
 * Mutants: mutant/ is the current source with the RTF_LLINFO and
 * AF_LINK tests of arplookup's proxy loop removed (the loop before
 * 12a68fffb).
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

#define NROUTES	2

static struct ifnet *the_ifp;

struct rtentry *table[NROUTES];

struct rtentry *
model_rtalloc(const struct sockaddr *dst, int flags, unsigned int rtableid)
{
	if (nondet_bool())
		return (NULL);
	table[0]->rt_refcnt.r_refs++;
	return (table[0]);
}

void
model_rtref(struct rtentry *rt)
{
	rt->rt_refcnt.r_refs++;
}

void
model_rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt->rt_refcnt.r_refs > 1, "rtfree: a reference held");
	rt->rt_refcnt.r_refs--;
}

struct rtentry *
model_rtable_iterate(struct rtentry *rt0)
{
	struct rtentry *rt;

	rt = rt0->rt_next;
	if (rt != NULL)
		rtref(rt);
	rtfree(rt0);
	return (rt);
}

int
model_rtisvalid(struct rtentry *rt)
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

struct ifnet *
model_if_get(unsigned int index)
{
	return (nondet_bool() ? the_ifp : NULL);
}

void
model_if_put(struct ifnet *ifp)
{
}

int
main(void)
{
	struct ifnet *ifp;
	struct sockaddr_in *dst;
	struct sockaddr_dl *ifsdl;
	unsigned char *obj[NROUTES];
	struct in_addr in;
	struct rtentry *rt;
	unsigned int nlen;
	unsigned char eaddr[ETHER_ADDR_LEN];
	int i, req;

	arpinit();

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_output = model_if_output;
	ifp->if_type = nondet_uchar();
	ifp->if_index = nondet_uint();
	ifp->if_rdomain = nondet_uint();
	ifp->if_llprio = nondet_uchar();
	ifsdl = CBMC_NEW(struct sockaddr_dl);
	ifsdl->sdl_len = sizeof(*ifsdl);
	ifsdl->sdl_family = AF_LINK;
	nlen = nondet_uchar();
	if (nlen > sizeof(*ifsdl) - 8 - ETHER_ADDR_LEN)
		nlen = sizeof(*ifsdl) - 8 - ETHER_ADDR_LEN;
	ifsdl->sdl_nlen = nlen;
	ifsdl->sdl_alen = ETHER_ADDR_LEN;
	ifp->if_sadl = ifsdl;
	the_ifp = ifp;

	dst = CBMC_NEW(struct sockaddr_in);
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;

	for (i = 0; i < NROUTES; i++) {
		rt = CBMC_NEW(struct rtentry);
		rt->rt_refcnt.r_refs = 1;
		rt->rt_flags = nondet_uint();
		rt->rt_ifidx = nondet_uint();
		rt->rt_dest = sintosa(dst);
		rt->rt_gateway = build_gate(&obj[i]);
		req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
		if (req == RTM_RESOLVE)
			rt->rt_flags &= ~(RTF_CLONING|RTF_CONNECTED|RTF_STATIC);
		arp_rtrequest(ifp, req, rt);
		table[i] = rt;
	}
	for (i = 0; i + 1 < NROUTES; i++)
		table[i]->rt_next = table[i + 1];

	in.s_addr = nondet_uint();
	(void)arpproxy(in, 0);

	/* in_arpinput, proxy branch: arpreply copies ETHER_ADDR_LEN bytes */
	rt = arplookup(&in, 0, SIN_PROXY, 0);
	if (rt != NULL) {
		memcpy(eaddr, LLADDR(satosdl(rt->rt_gateway)), ETHER_ADDR_LEN);
		rtfree(rt);
	}

	for (i = 0; i < NROUTES; i++) {
		__CPROVER_assert(table[i]->rt_refcnt.r_refs == 1,
		    "every reference taken is dropped");
		arp_rtrequest(ifp, RTM_DELETE, table[i]);
		harness_release(obj[i]);
		harness_release(table[i]);
	}
	harness_release(dst);
	harness_release(ifsdl);
	harness_release(ifp);
	return (0);
}
