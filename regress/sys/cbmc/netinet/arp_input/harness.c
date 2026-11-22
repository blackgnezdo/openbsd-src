/*
 * Harness: the receive path of an ARP packet from the link,
 * arpinput() -> arppullup(), then arpintr() -> in_arpinput() of
 * sys/netinet/if_ether.c, on an untrusted packet.
 *
 * What the callers guarantee.  ether_input() hands arpinput() the frame
 * without its Ethernet header: an mbuf chain with M_PKTHDR on the first
 * mbuf and m_pkthdr.len the sum of the m_len, of any length, an empty
 * first mbuf included (a runt frame reaches arpinput).  arpinput() runs
 * arppullup(): the first mbuf is pulled up to the 8 byte header, the
 * header is checked (ar_hrd Ethernet, ar_pro IP, ar_hln 6, ar_pln 4),
 * then the first mbuf is pulled up to 8 + 2 * (6 + 4) = 28 bytes, a
 * struct ether_arp.  Anything shorter, or with another header, is freed.
 * arpinput() puts the packet on arpinq (niq_enqueue, which frees it
 * when the queue is full); arpintr() takes it off again, looks the
 * interface up by m_pkthdr.ph_ifidx (the packet is freed if it is gone)
 * and calls in_arpinput(), which reads a whole struct ether_arp at
 * mtod(m) and consumes the packet (arpreply sends it back, else m_freem).
 *
 * The packet.  The mbuf contract models (common/mbufcontract.h), not
 * the real mbuf code (mbufkit): nothing below arppullup depends on the
 * mbuf library, m_pullup is the one function the length guarantee comes
 * from, and the real m_pullup costs 111 s and 426,000 variables alone
 * (README, "Writing a packet parser target").  The models are the
 * assume side of that split; net/mbuf_pullup proves the real m_pullup.
 * MC_MAXLEN 46: any length 0..46 in one or two mbufs (the first of an
 * arbitrary length, zero included), arbitrary content.  46 is an ARP
 * packet padded to the 60 byte Ethernet minimum (28 + 18 bytes of
 * padding); packets above 46 bytes are not covered.  The data of each
 * mbuf ends where its object ends, so a read past m_len (the mutant:
 * arppullup without its pullup to 28 bytes) is out of bounds.
 * m_pkthdr.ph_ifidx and ph_rtableid are arbitrary.
 *
 * Route table.  As in netinet/arp_proxy: two routes under one key
 * chained through rt_next, each with arbitrary rt_flags and an
 * arbitrary gateway sockaddr (sa_len 0..63, any family, any sdl_nlen
 * and sdl_alen, exactly ROUNDUP(sa_len) bytes at the end of a 64 byte
 * object, as rt_setgate leaves it) and put through the real
 * arp_rtrequest (RTM_ADD, or RTM_RESOLVE without the flags rtrequest
 * clears for a clone), so every route is in a state the kernel can
 * produce.  Each route that got an llinfo may hold one packet on la_mq
 * (la_hold_total counts them).  rtalloc returns, per call, NULL, the
 * head of the chain, its second route, or a CLONE: with RT_RESOLVE and
 * a head with RTF_CLONING (once per run; rt_clone succeeded), a new
 * route built as rtrequest(RTM_RESOLVE) builds it: the parent's flags
 * with RTF_HOST|RTF_CLONED, without RTF_CLONING|RTF_CONNECTED|
 * RTF_STATIC, RTF_UP arbitrary (link down), and a blank AF_LINK sdl as
 * gateway (sa_dl of rtrequest: 32 bytes, nlen 0, alen 0), put through
 * the real arp_rtrequest(RTM_RESOLVE).  A head with RTF_CLONING that
 * rt_clone failed on is the same as returning the head.  Once the clone
 * exists later lookups may return it too.  Every route has the table's
 * reference (r_refs 1); rtalloc, rtref and rtable_iterate add one,
 * rtfree drops one and asserts that one is held.  rtisvalid is the
 * kernel's body (a route with RTF_GATEWAY is valid with an up
 * rt_gwroute, which may be arbitrary).  Properties asserted at the end:
 * every reference taken is dropped, and the invariant of
 * netinet/arp_rtrequest (check_entry, as in netinet/arp_consumers)
 * holds on every route, the clone included.
 *
 * Real code: arpinput, arppullup, arpintr, in_arpinput, arplookup
 * (create and proxy, with its loop), arpcache, arpreply, arprequest and
 * arp_rtrequest (all of if_ether.c is included).  ifp->if_output is a
 * driver model that frees the mbuf (fptargets, arprequest and
 * arpreply).  ifp->if_sadl is a link address as if_alloc_sadl builds it
 * for an Ethernet interface: exactly 32 bytes, sdl_nlen 0..18, sdl_alen
 * 6.
 *
 * Models (all named as the kernel's, replacing what is in files this
 * target does not compile; natively it is the same code):
 *  niq_enqueue    either the packet is freed (queue full, as mq_enqueue)
 *                 or it is the one packet of arpinq.ni_q.  Returns what
 *                 mq_enqueue returns.
 *  mq_init, mq_delist, mq_purge, ml_dequeue, ml_purge   the kernel's
 *                 statements without the mutex (single thread).
 *  m_resethdr     the kernel's body without m_tag_delete_chain: no
 *                 packet carries tags (ph_tags empty is asserted).
 *  m_gethdr, m_align   arprequest's mbuf: M_PKTHDR, a MHLEN byte data
 *                 area (kept in m_ext.ext_buf like mc_seg's, so that
 *                 m_free releases it) or NULL (M_DONTWAIT fails);
 *                 m_align puts the data at the START of the area (the
 *                 kernel puts it at the end) and asserts what the
 *                 kernel KASSERTs.
 *  pool_get, pool_put   (replace file: model_pool_get, model_pool_put) arp_pool only (natively the common pool stub with pr_size set in main): a typed llinfo_arp (CBMC_NEW) or
 *                 NULL (PR_NOWAIT), not the untyped common model (the
 *                 field accesses through rt_llinfo would be byte loops).
 *  refcnt_init, refcnt_rele   single threaded.
 *  rtalloc, rtref, rtfree, rtisvalid, rtable_iterate   above.
 *  if_get, if_put   NULL or the interface; nothing.
 *  if_isconnected   arbitrary result, reads nothing.
 *  if_output_mq     what net/if.c does with the held packets: delist,
 *                 the driver frees them, la_hold_total reduced.
 *  rtm_send         asserts the whole gateway (sa_len bytes) is readable,
 *                 as rtm_msg1 copies it into the message to userland.
 *  getuptime        arbitrary, 0 <= t < 2^40 (native UBSan: arpcache
 *                 adds arpt_keep to it).
 *  m_pullup, m_pulldown, m_copydata, m_adj, m_free, m_freem, m_getptr:
 *                 mbufcontract.h.
 * Bodiless (a call returns an arbitrary value, no effect): kern_log_model
 * (log is #defined to it), mtx_enter, mtx_leave, inet_ntop, ether_sprintf
 * (their results only go into log's arguments), rtable_l2 (the rdomain
 * only goes to the route table model and ph_rtableid), rw_status and
 * splassert_fail (NET_ASSERT_LOCKED).  arpinit is not called, so
 * timeout_set_flags and timeout_add_sec are not reached.
 *
 * The packet content is arbitrary.  For the fuzzer only, by nondet
 * choices (the arbitrary content stays covered by the other branch of
 * each): the header fields of a valid ARP request or reply, an ARP
 * route's flags, gateway and interface index, as nd6_proxy does.
 *
 * Properties: no out-of-bounds access (the header reads, the 28 byte
 * struct ether_arp at mtod, the 6 byte reads at LLADDR of the gateway of
 * an ARP route and of if_sadl, the in place reply), no leak or double
 * free (--memory-leak-check; arpinq is empty at the end), every
 * reference taken is dropped, the gateway invariant on every route.
 *
 * Not covered: packets above 46 bytes, gateways above 63 bytes (sa_len 64..255), RARP (revarpinput), arpresolve
 * (netinet/arp_consumers), arptimer, more than one clone or two routes
 * under a key, packets that carry mbuf tags, the real mbuf library
 * (net/mbuf_pullup), carp (NCARP 0), a held packet that the real
 * driver would send through ether_output.
 *
 * Mutants (suite.sh -m, VIOLATED): mutant/ is if_ether.c without
 * arppullup's pullup to the 28 bytes of struct ether_arp, mutant_hdr/
 * without the pullup to the 8 byte header.
 */
#define MC_MAXLEN	46
#define MC_COPY_LOOP
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include "mbufcontract.h"

#define log	kern_log_model
#include "if_ether.c"

#define GATE_MAX	63	/* sa_len 0..63; the kernel's 255 is not covered */
#define GATE_OBJ	64	/* ROUNDUP(GATE_MAX) */
#define ROUNDUP8(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)
#define NROUTES		2

/* a time_t as the kernel produces them: below 2^40 */
#define NONDET_TIME()	(nondet_long() & 0xffffffffffL)

u_int8_t etherbroadcastaddr[ETHER_ADDR_LEN];	/* all ones in the kernel */

static struct ifnet *the_ifp;
static struct sockaddr_in *the_key;
static struct rtentry *table[NROUTES];
static struct rtentry *gwroute[NROUTES];
static struct rtentry *clone;
static struct sockaddr_dl *clone_gate;

/*
 * For the fuzzer: the usual choice in 3 of 4 inputs (a nondet choice for
 * CBMC, which explores both).
 */
static int
usual(void)
{
	return ((nondet_uchar() & 3) != 0);
}

/* ---- queues, mbufs ---- */

int
niq_enqueue(struct niqueue *niq, struct mbuf *m)
{
	__CPROVER_assert(niq == &arpinq && niq->ni_q.mq_list.ml_len == 0 &&
	    m->m_nextpkt == NULL, "niq_enqueue model: one packet, empty queue");
	if (nondet_bool()) {
		niq->ni_q.mq_drops++;
		m_freem(m);
		return (1);
	}
	niq->ni_q.mq_list.ml_head = m;
	niq->ni_q.mq_list.ml_tail = m;
	niq->ni_q.mq_list.ml_len = 1;
	return (0);
}

void
mq_init(struct mbuf_queue *mq, u_int maxlen, int ipl)
{
	mq->mq_list.ml_head = NULL;
	mq->mq_list.ml_tail = NULL;
	mq->mq_list.ml_len = 0;
	mq->mq_maxlen = maxlen;
	mq->mq_drops = 0;
}

void
mq_delist(struct mbuf_queue *mq, struct mbuf_list *ml)
{
	*ml = mq->mq_list;
	mq->mq_list.ml_head = NULL;
	mq->mq_list.ml_tail = NULL;
	mq->mq_list.ml_len = 0;
}

struct mbuf *
ml_dequeue(struct mbuf_list *ml)
{
	struct mbuf *m;

	m = ml->ml_head;
	if (m != NULL) {
		ml->ml_head = m->m_nextpkt;
		if (ml->ml_head == NULL)
			ml->ml_tail = NULL;
		m->m_nextpkt = NULL;
		ml->ml_len--;
	}
	return (m);
}

unsigned int
ml_purge(struct mbuf_list *ml)
{
	struct mbuf *m;
	unsigned int len;

	len = ml->ml_len;
	while ((m = ml_dequeue(ml)) != NULL)
		m_freem(m);
	return (len);
}

unsigned int
mq_purge(struct mbuf_queue *mq)
{
	struct mbuf_list ml;

	mq_delist(mq, &ml);
	return (ml_purge(&ml));
}

void
m_resethdr(struct mbuf *m)
{
	int len = m->m_pkthdr.len;
	u_int8_t loopcnt = m->m_pkthdr.ph_loopcnt;

	__CPROVER_assert(m->m_flags & M_PKTHDR, "m_resethdr: KASSERT M_PKTHDR");
	__CPROVER_assert(SLIST_EMPTY(&m->m_pkthdr.ph_tags),
	    "m_resethdr model: no mbuf tags");
	m->m_flags &= (M_EXT|M_PKTHDR|M_EOR|M_EXTWR|M_ZEROIZE);
	memset(&m->m_pkthdr, 0, sizeof(m->m_pkthdr));
	m->m_pkthdr.pf.prio = IFQ_DEFPRIO;
	m->m_pkthdr.len = len;
	m->m_pkthdr.ph_loopcnt = loopcnt;
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
	MC_BUF(m) = (caddr_t)CBMC_NEW_ARRAY(u_char, MHLEN);
	m->m_data = MC_BUF(m);
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

void *
model_pool_get(struct pool *pp, int flags)
{
	__CPROVER_assert(pp == &arp_pool, "model_pool_get: arp_pool only");
	if ((flags & PR_NOWAIT) && nondet_bool())
		return (NULL);
	return (CBMC_NEW(struct llinfo_arp));
}

void
model_pool_put(struct pool *pp, void *v)
{
	__CPROVER_assert(pp == &arp_pool, "model_pool_put: arp_pool only");
	mc_release(v);
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

time_t
getuptime(void)
{
	return (NONDET_TIME());
}

/* ---- interface, link layer ---- */

int
model_if_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	/* a driver: it frees what it is given */
	m_freem(m);
	return (0);
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

int
if_isconnected(const struct ifnet *ifp, unsigned int ifidx)
{
	return (nondet_bool());
}

int
if_output_mq(struct ifnet *ifp, struct mbuf_queue *mq, unsigned int *total,
    struct sockaddr *dst, struct rtentry *rt)
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
rtm_send(struct rtentry *rt, int cmd, int error, unsigned int rtableid)
{
	__CPROVER_assert(__CPROVER_r_ok(rt->rt_gateway,
	    rt->rt_gateway->sa_len), "rtm_send: gateway readable");
}

/* ---- the route table ---- */

/*
 * A gateway as rt_setgate() leaves it: ROUNDUP(sa_len) bytes at the end
 * of a GATE_OBJ byte object (*objp, freed by the caller).  For the
 * fuzzer, the usual ARP gateway in 3 of 4 inputs: 32 bytes, AF_LINK,
 * nlen 0, alen 0 or 6.
 */
static struct sockaddr *
build_gate(unsigned char **objp)
{
	struct sockaddr *gate;
	unsigned int sa_len;
	int rounded;

	sa_len = nondet_uchar() & GATE_MAX;
	if (usual())
		sa_len = sizeof(struct sockaddr_dl);
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
	if (sa_len >= 7 && usual()) {
		gate->sa_family = AF_LINK;
		satosdl(gate)->sdl_nlen = 0;
		satosdl(gate)->sdl_alen = nondet_bool() ? 0 : ETHER_ADDR_LEN;
	}
	return (gate);
}

/*
 * The clone rtrequest(RTM_RESOLVE) makes (see the header), through the
 * real arp_rtrequest.
 */
static struct rtentry *
make_clone(void)
{
	struct rtentry *rt;

	rt = CBMC_NEW(struct rtentry);
	rt->rt_refcnt.r_refs = 1;		/* the table's */
	rt->rt_flags = (nondet_uint() | RTF_HOST | RTF_CLONED | RTF_UP) &
	    ~(RTF_CLONING | RTF_CONNECTED | RTF_STATIC);
	if (nondet_bool())
		rt->rt_flags &= ~RTF_UP;	/* link down */
	rt->rt_ifidx = nondet_uint();
	if (usual())
		rt->rt_ifidx = the_ifp->if_index;
	rt->rt_dest = sintosa(the_key);
	clone_gate = CBMC_NEW(struct sockaddr_dl);
	clone_gate->sdl_len = sizeof(*clone_gate);
	clone_gate->sdl_family = AF_LINK;
	rt->rt_gateway = sdltosa(clone_gate);
	arp_rtrequest(the_ifp, RTM_RESOLVE, rt);
	if (rt->rt_llinfo != NULL)
		((struct llinfo_arp *)rt->rt_llinfo)->la_asked = nondet_uchar();
	return (rt);
}

struct rtentry *
rtalloc(const struct sockaddr *dst, int flags, unsigned int rtableid)
{
	struct rtentry *rt;
	int sel;

	__CPROVER_assert(dst->sa_family == AF_INET &&
	    dst->sa_len >= sizeof(struct sockaddr_in) &&
	    __CPROVER_r_ok(dst, dst->sa_len), "rtalloc: key");
	sel = nondet_uchar() & 3;
	if (sel == 0)
		return (NULL);
	if (sel == 3) {
		if (clone == NULL) {
			if (!ISSET(flags, RT_RESOLVE) ||
			    !ISSET(table[0]->rt_flags, RTF_CLONING))
				return (NULL);
			clone = make_clone();
		}
		rt = clone;
	} else
		rt = table[sel - 1];
	rt->rt_refcnt.r_refs++;
	return (rt);
}

void
rtref(struct rtentry *rt)
{
	rt->rt_refcnt.r_refs++;
}

void
rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt->rt_refcnt.r_refs > 1, "rtfree: a reference held");
	rt->rt_refcnt.r_refs--;
}

struct rtentry *
rtable_iterate(struct rtentry *rt0)
{
	struct rtentry *rt;

	rt = rt0->rt_next;
	if (rt != NULL)
		rtref(rt);
	rtfree(rt0);
	return (rt);
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

/* The invariant of netinet/arp_rtrequest (its check_entry). */
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

/* ---- the packet ---- */

/* the address of packet byte off (0 <= off < the packet's length) */
static unsigned char *
pktp(struct mbuf *m, int off)
{
	if (off < m->m_len)
		return (mtod(m, unsigned char *) + off);
	return (mtod(m->m_next, unsigned char *) + (off - m->m_len));
}

int
main(void)
{
	struct ifnet *ifp;
	struct sockaddr_dl *ifsdl;
	unsigned char *obj[NROUTES];
	struct rtentry *rt;
	struct llinfo_arp *la;
	struct mbuf *m;
	unsigned int nlen;
	int i, req, total, held = 0;

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
	arp_pool.pr_size = sizeof(struct llinfo_arp);	/* arpinit() is not called; native pool_get */

	the_key = CBMC_NEW(struct sockaddr_in);
	the_key->sin_len = sizeof(*the_key);
	the_key->sin_family = AF_INET;

	for (i = 0; i < NROUTES; i++) {
		rt = CBMC_NEW(struct rtentry);
		rt->rt_refcnt.r_refs = 1;
		rt->rt_flags = nondet_uint();
		if (usual())
			rt->rt_flags = RTF_UP | RTF_HOST | RTF_LLINFO |
			    (nondet_uint() & (RTF_ANNOUNCE | RTF_LOCAL |
			    RTF_PERMANENT_ARP | RTF_CLONING));
		rt->rt_ifidx = nondet_uint();
		if (usual())
			rt->rt_ifidx = ifp->if_index;
		rt->rt_expire = NONDET_TIME();
		rt->rt_dest = sintosa(the_key);
		rt->rt_gateway = build_gate(&obj[i]);
		req = nondet_bool() ? RTM_ADD : RTM_RESOLVE;
		if (req == RTM_RESOLVE)
			rt->rt_flags &= ~(RTF_CLONING|RTF_CONNECTED|RTF_STATIC);
		if (ISSET(rt->rt_flags, RTF_GATEWAY) && nondet_bool()) {
			gwroute[i] = CBMC_NEW(struct rtentry);
			gwroute[i]->rt_flags = nondet_uint();
			rt->rt_gwroute = gwroute[i];
		}
		arp_rtrequest(ifp, req, rt);
		table[i] = rt;
		la = (struct llinfo_arp *)rt->rt_llinfo;
		if (la != NULL) {
			la->la_asked = nondet_uchar();
			la->la_refreshed = NONDET_TIME();
			if (nondet_bool()) {
				struct mbuf *h = mc_seg(0);

				la->la_mq.mq_list.ml_head = h;
				la->la_mq.mq_list.ml_tail = h;
				la->la_mq.mq_list.ml_len = 1;
				held++;
			}
		}
	}
	table[0]->rt_next = table[1];
	la_hold_total = held;

	/* the packet: any length, one or two mbufs, arbitrary content */
	total = mc_upto(MC_MAXLEN);
	m = mc_build(total);
	m->m_pkthdr.ph_ifidx = nondet_ushort();
	m->m_pkthdr.ph_rtableid = nondet_uint();
	/*
	 * For the fuzzer: the header of an ARP request or reply (hrd 1,
	 * pro 0x0800, hln 6, pln 4, op 1 or 2) in 3 of 4 inputs.
	 */
	if (total >= sizeof(struct ether_arp) && usual()) {
		*pktp(m, 0) = 0;
		*pktp(m, 1) = ARPHRD_ETHER;
		*pktp(m, 2) = ETHERTYPE_IP >> 8;
		*pktp(m, 3) = ETHERTYPE_IP & 0xff;
		*pktp(m, 4) = ETHER_ADDR_LEN;
		*pktp(m, 5) = sizeof(struct in_addr);
		*pktp(m, 6) = 0;
		*pktp(m, 7) = nondet_bool() ? ARPOP_REQUEST : ARPOP_REPLY;
	}

	arpinput(ifp, m, NULL);
	arpintr();

	__CPROVER_assert(arpinq.ni_q.mq_list.ml_len == 0 &&
	    arpinq.ni_q.mq_list.ml_head == NULL, "arpinq is empty again");
	for (i = 0; i < NROUTES; i++) {
		__CPROVER_assert(table[i]->rt_refcnt.r_refs == 1,
		    "every reference taken is dropped");
		check_entry(table[i]);
	}
	if (clone != NULL) {
		__CPROVER_assert(clone->rt_refcnt.r_refs == 1,
		    "every reference taken is dropped (clone)");
		check_entry(clone);
	}

	/* teardown by the kernel's own code, then what the harness made */
	for (i = 0; i < NROUTES; i++) {
		arp_rtrequest(ifp, RTM_DELETE, table[i]);
		mc_release(obj[i]);
		mc_release(table[i]);
		if (gwroute[i] != NULL)
			mc_release(gwroute[i]);
	}
	if (clone != NULL) {
		arp_rtrequest(ifp, RTM_DELETE, clone);
		mc_release(clone_gate);
		mc_release(clone);
	}
	mc_release(the_key);
	mc_release(ifsdl);
	mc_release(ifp);
	return (0);
}
