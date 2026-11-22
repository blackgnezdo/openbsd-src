/*
 * Harness: icmp6_redirect_input() of sys/netinet6/icmp6.c on an ICMPv6
 * Redirect (RFC 4861, 8.3).
 *
 * Why: the function takes the destination, the target and the options
 * out of the packet, decides by a route lookup whether the sender is the
 * current router for the destination, parses the options with
 * nd6_options(), accepts a target link-layer address option only if its
 * length is that of if_addrlen (icmp6.c:1285, the same test as
 * nd6_ns_input and nd6_rtr_cache) and hands the address to
 * nd6_cache_lladdr(), which compares and stores if_addrlen bytes from it
 * (netinet6/nd6_consumers).  Without the length test a short option
 * would be over-read by those bcmp/bcopy.  rtredirect() then gets three
 * sockaddr_in6 built on the stack.
 *
 * The packet.  The mbuf contract models (common/mbufcontract.h): an IPv6
 * header (40 bytes), a Redirect (struct nd_redirect, 40 bytes: ICMPv6
 * header, target, destination, arbitrary content) and 0..16 option bytes
 * (arbitrary: none, one or two 8 byte options, or fragments nd6_options
 * refuses), 80..96 bytes in one or two mbufs, the first holding at least
 * the IPv6 header, the split arbitrary.  off is 40 (no extension header).
 * The content is arbitrary, except ip6_plen, which is set to total - 40:
 * the function takes icmp6len from ip6_plen, not from m_pkthdr.len, and
 * ip6_input() (ip6_input.c:702-715) drops a packet shorter than
 * 40 + plen and trims a longer one, so plen == m_pkthdr.len - 40
 * whenever plen != 0 and no jumbo payload option is present (jumbograms,
 * plen 0, need more than 65535 bytes and are not covered, see below).
 * icmp6_input() (icmp6.c:696) drops a Redirect with icmp6len below
 * sizeof(struct nd_redirect) before the call, so total >= 80.  The
 * hop limit, the source address, the destination and the target are
 * arbitrary bytes of the packet: the hop limit test, the link-local and
 * multicast tests, the on-link / router decision run as the kernel's.
 * m_pkthdr.ph_ifidx is arbitrary, ph_rtableid arbitrary.
 *
 * Interface: one ifnet, if_addrlen 0..255 (arbitrary: the lladdr length
 * test meets every value; the option area allows lladdrlen 8 or 16, so
 * if_addrlen up to 14 can pass), arbitrary if_index and if_xflags (so
 * IFXF_AUTOCONF6 is set or not), ip6_forwarding arbitrary (a router
 * ignores redirects), ip6_maxdynroutes arbitrary, icmp6_redirtimeout
 * arbitrary 0..2^30.
 *
 * Routes.  Two routes, both rtentry objects of the harness with
 * r_refs 1 (the table's), never freed by the model:
 *   table0   the route to the destination: rtalloc (model) returns NULL
 *            or table0 with a reference, after asserting the key is a
 *            sockaddr_in6.  rt_gateway is NULL or a sockaddr of
 *            ROUNDUP(sa_len) bytes at the END of a 264 byte object
 *            (an over-read is out of bounds), sa_len 0..255, any family
 *            (AF_INET6 or arbitrary), arbitrary address bytes.  The
 *            only constraint is the one the kernel enforces: an AF_INET6
 *            gateway has sa_len >= sizeof(struct sockaddr_in6) (userland
 *            routes: rtm_xaddrs, rtsock.c:1555-1558; kernel callers
 *            build a sockaddr_in6).  icmp6_redirect_input tests the
 *            family and then reads sin6_addr (16 bytes at offset 8)
 *            without a length test.
 *   newrt0   the route rtredirect (model) may return in *rtp with a
 *            reference; rt_timer_add (model) asserts a reference is held.
 *   rtfree   (model) NULL ok; asserts a reference is held, drops it.
 *   Both routes' r_refs are asserted back to 1 afterwards.  rtisvalid is
 *   not called by this function (only by rtredirect, a model here).
 *
 * Models below icmp6_redirect_input (every one stated):
 *   nd6_cache_lladdr  NOT the real body: a model that asserts what it is
 *            passed: ifp is the interface, from readable (16 bytes),
 *            when lladdr != NULL: lladdrlen == (if_addrlen + 9) & ~7
 *            (what its callers check), lladdr readable for lladdrlen - 2
 *            bytes (the option holds them) and for if_addrlen bytes (what
 *            the real body's bcmp and bcopy read); when lladdr == NULL
 *            lladdrlen is 0.  Natively it also reads those bytes.  The
 *            real body on a route that satisfies the nd6 invariant is
 *            netinet6/nd6_consumers, which has the same caller guarantee
 *            for its lladdr argument; this target proves that guarantee
 *            for icmp6_redirect_input.
 *   rtredirect  asserts dst, gateway, src are readable for their sa_len,
 *            AF_INET6 with sa_len == sizeof(struct sockaddr_in6); sets
 *            *rtp to NULL or newrt0 with a reference.  The real body
 *            (route table, rtrequest) is not affordable and is another
 *            target's.
 *   rt_timer_queue_count  arbitrary.   rt_timer_add  asserts newrt0 with a
 *            reference.   pfctlinput  asserts its sockaddr readable.
 *   if_get, if_put  if_get returns NULL (interface detached) or the
 *            interface with a count; if_put ignores NULL, otherwise
 *            asserts the count and drops it; the count is 0 at the end.
 *   m_pulldown, m_freem, m_free: mbufcontract.h.  counters_inc: nobody
 *            (statistics).
 * Kept bodies: icmp6_redirect_input, nd6_options (nd6.c), ip6_exthdr_get
 * and the other header inlines.  NOT read by the function: the Redirected
 * Header option (ND_OPT_REDIRECTED_HEADER): struct nd_opts of this tree
 * holds only the source and target link-layer address options, so there is
 * nothing to model.
 *
 * mutant_prefix/ is the source before the if_get() NULL path went to
 * freeit: it returned without m_freem(m), a leak (VIOLATED).
 *
 * Properties: no out-of-bounds access, no leak or double free
 * (--memory-leak-check), every route and interface reference taken is
 * dropped, the model contracts above.
 *
 * Bounds: packet 80..96 bytes, options 0..16 bytes (nd6_options: --unwind 4
 * covers its loop, the unwinding assertion proves it: every option is at
 * least 8 bytes), if_addrlen 0..255.  Not covered: extension headers
 * (off > 40: ip6_plen then exceeds the data and ip6_exthdr_get fails),
 * jumbograms (ip6_plen 0 leaves icmp6len 0 and nd_rd is read beyond the
 * length asked of ip6_exthdr_get; needs a packet of 65536+ bytes), the
 * real rtredirect, the real nd6_cache_lladdr, packets above 96 bytes.
 *
 * Mutant: mutant/icmp6.c has the lladdr length test (icmp6.c:1285) removed.
 */
#define MC_MAXLEN	96
#define MC_COPY_LOOP
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/protosw.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include "mbufcontract.h"

/* icmp6.c is included (its other functions are not called): it names these */
u_char ip6_protox[IPPROTO_MAX];
const struct protosw inet6sw[1];
#include "icmp6.c"
#include "nd6.c"

#define GATE_OBJ	264	/* ROUNDUP(255) */
#define ROUNDUP8(a)	((a) > 0 ? (1 + (((a) - 1) | 7)) : 8)

int ip6_forwarding;
int ip6_maxdynroutes;
extern int icmp6_redirtimeout;

static struct ifnet *the_ifp;
static int g_ifrefs;
static struct rtentry *table0;		/* the route to the destination */
static struct rtentry *newrt0;		/* the route rtredirect returns */

/* ---- models below icmp6_redirect_input ---- */

static volatile unsigned char sink;

void
model_nd6_cache_lladdr(struct ifnet *ifp, const struct in6_addr *from,
    char *lladdr, int lladdrlen, int type, int code, int i_am_router)
{
	__CPROVER_assert(ifp == the_ifp, "nd6_cache_lladdr model: interface");
	__CPROVER_assert(__CPROVER_r_ok(from, sizeof(*from)),
	    "nd6_cache_lladdr model: from readable");
	if (lladdr == NULL) {
		__CPROVER_assert(lladdrlen == 0,
		    "nd6_cache_lladdr model: no lladdr, no length");
		return;
	}
	__CPROVER_assert(lladdrlen == ((ifp->if_addrlen + 2 + 7) & ~7),
	    "nd6_cache_lladdr model: lladdrlen consistent with if_addrlen");
	__CPROVER_assert(lladdrlen >= 2 &&
	    __CPROVER_r_ok(lladdr, lladdrlen - 2),
	    "nd6_cache_lladdr model: lladdr readable for lladdrlen - 2");
	__CPROVER_assert(ifp->if_addrlen == 0 ||
	    __CPROVER_r_ok(lladdr, ifp->if_addrlen),
	    "nd6_cache_lladdr model: lladdr readable for if_addrlen");
#ifdef NATIVE_SHIM_H
	{
		int i;

		for (i = 0; i < ifp->if_addrlen; i++)
			sink = lladdr[i];
	}
#endif
}

void
rtredirect(struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *src, struct rtentry **rtp, unsigned int rdomain)
{
	struct sockaddr *sa[3];
	int i;

	sa[0] = dst;
	sa[1] = gateway;
	sa[2] = src;
	for (i = 0; i < 3; i++) {
		__CPROVER_assert(__CPROVER_r_ok(sa[i], sizeof(struct sockaddr)),
		    "rtredirect model: sockaddr header readable");
		__CPROVER_assert(sa[i]->sa_family == AF_INET6 &&
		    sa[i]->sa_len == sizeof(struct sockaddr_in6),
		    "rtredirect model: sockaddr_in6");
		__CPROVER_assert(__CPROVER_r_ok(sa[i], sa[i]->sa_len),
		    "rtredirect model: sockaddr readable for sa_len");
	}
	__CPROVER_assert(rtp != NULL, "rtredirect model: rtp");
	*rtp = NULL;
	if (nondet_bool()) {
		newrt0->rt_refcnt.r_refs++;
		*rtp = newrt0;
	}
}

unsigned long
rt_timer_queue_count(struct rttimer_queue *rtq)
{
	unsigned long n = nondet_ulong();

#ifdef NATIVE_SHIM_H
	/* the fuzzer: a small count in 3 of 4 inputs, else arbitrary */
	if ((nondet_uchar() & 3) != 0)
		n &= 0xff;
#endif
	return (n);
}

int
rt_timer_add(struct rtentry *rt, struct rttimer_queue *queue, u_int rtableid)
{
	__CPROVER_assert(rt == newrt0 && rt->rt_refcnt.r_refs > 1,
	    "rt_timer_add model: the route, with a reference");
	return (nondet_bool() ? 0 : ENOBUFS);
}

void
pfctlinput(int cmd, struct sockaddr *sa)
{
	__CPROVER_assert(__CPROVER_r_ok(sa, sizeof(struct sockaddr)) &&
	    sa->sa_len == sizeof(struct sockaddr_in6) &&
	    __CPROVER_r_ok(sa, sa->sa_len), "pfctlinput model: sockaddr");
}

struct ifnet *
if_get(unsigned int index)
{
	if (nondet_bool())
		return (NULL);	/* the interface was detached */
	g_ifrefs++;
	return (the_ifp);
}

void
if_put(struct ifnet *ifp)
{
	if (ifp == NULL)
		return;
	__CPROVER_assert(ifp == the_ifp && g_ifrefs > 0,
	    "if_put model: a reference is held");
	g_ifrefs--;
}

struct rtentry *
rtalloc(const struct sockaddr *dst, int flags, unsigned int rtableid)
{
	__CPROVER_assert(dst->sa_family == AF_INET6 &&
	    dst->sa_len == sizeof(struct sockaddr_in6), "rtalloc: key");
	if (nondet_bool())
		return (NULL);
	table0->rt_refcnt.r_refs++;
	return (table0);
}

void
rtfree(struct rtentry *rt)
{
	if (rt == NULL)
		return;
	__CPROVER_assert(rt == table0 || rt == newrt0,
	    "rtfree: one of the routes");
	__CPROVER_assert(rt->rt_refcnt.r_refs > 1, "rtfree: a reference held");
	rt->rt_refcnt.r_refs--;
}

/* ---- the route, the interface, the packet ---- */

/*
 * A gateway as rt_setgate() leaves it: ROUNDUP(sa_len) bytes at the end of
 * a GATE_OBJ byte object (*objp, freed by the caller).  src is the
 * packet's source address, for the fuzzer.
 */
static struct sockaddr *
build_gate(unsigned char **objp, const struct in6_addr *src)
{
	struct sockaddr *gate;
	unsigned int sa_len;
	int rounded;

	sa_len = nondet_uchar();
	if (nondet_bool() && sa_len < sizeof(struct sockaddr_in6))
		sa_len = sizeof(struct sockaddr_in6);	/* rtm_xaddrs */
	rounded = ROUNDUP8(sa_len);
	*objp = CBMC_NEW_ARRAY(unsigned char, GATE_OBJ);
	gate = (struct sockaddr *)(*objp + GATE_OBJ - rounded);
	gate->sa_len = sa_len;
	if (sa_len >= sizeof(struct sockaddr_in6) && nondet_bool())
		gate->sa_family = AF_INET6;
	else {
		gate->sa_family = nondet_uchar();
		/* an AF_INET6 gateway is at least a sockaddr_in6 */
		if (gate->sa_family == AF_INET6 &&
		    sa_len < sizeof(struct sockaddr_in6))
			gate->sa_family = AF_INET;
	}
	if (gate->sa_family == AF_INET6) {
		struct sockaddr_in6 *g6 = satosin6(gate);

		g6->sin6_addr.s6_addr32[0] = nondet_uint();
		g6->sin6_addr.s6_addr32[1] = nondet_uint();
		g6->sin6_addr.s6_addr32[2] = nondet_uint();
		g6->sin6_addr.s6_addr32[3] = nondet_uint();
		if ((nondet_uchar() & 3) != 0)
			g6->sin6_addr = *src;
	}
	return (gate);
}

/*
 * The packet: total bytes (>= 80) in one or two mbufs, the first holding
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

/* for the fuzzer: the usual choice in 3 of 4 inputs, both for CBMC */
static int
usual(void)
{
	return ((nondet_uchar() & 3) != 0);
}

#ifdef NATIVE_SHIM_H
/* byte off of the packet (the harness knows the two mbufs) */
static unsigned char *
packet_byte(struct mbuf *m, int off)
{
	if (off < m->m_len)
		return ((unsigned char *)m->m_data + off);
	return ((unsigned char *)m->m_next->m_data + (off - m->m_len));
}

static void
set_byte(struct mbuf *m, int off, unsigned char v)
{
	*packet_byte(m, off) = v;
}

static unsigned char
get_byte(struct mbuf *m, int off)
{
	return (*packet_byte(m, off));
}
#endif

int
main(void)
{
	struct ifnet *ifp;
	struct ip6_hdr *ip6;
	unsigned char *obj;
	struct mbuf *m;
	int total;

	ip6_forwarding = nondet_int();
	ip6_maxdynroutes = nondet_int();
	icmp6_redirtimeout = nondet_int() & 0x3fffffff;
	if (usual())
		ip6_forwarding = 0;

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_addrlen = nondet_uchar();
	ifp->if_index = nondet_ushort();
	ifp->if_xflags = nondet_int();
	if (usual())
		ifp->if_xflags |= IFXF_AUTOCONF6;
	the_ifp = ifp;

	table0 = CBMC_NEW(struct rtentry);
	table0->rt_refcnt.r_refs = 1;		/* the table's */
	newrt0 = CBMC_NEW(struct rtentry);
	newrt0->rt_refcnt.r_refs = 1;

	/* the packet: IPv6 header, Redirect, 0..16 option bytes */
	total = sizeof(struct ip6_hdr) + sizeof(struct nd_redirect) +
	    mc_upto(16);
	m = build_packet(total);
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_plen = htons(total - sizeof(struct ip6_hdr));
	/*
	 * Arbitrary content; two fields are, in 3 of 4 cases (a nondet
	 * choice, so the arbitrary content stays covered), set to what the
	 * accepting path needs: hop limit 255 and a link-local source.
	 */
	if (usual())
		ip6->ip6_hlim = 255;
	if (usual()) {
		ip6->ip6_src.s6_addr[0] = 0xfe;
		ip6->ip6_src.s6_addr[1] = 0x80;
	}

#ifdef NATIVE_SHIM_H
	/*
	 * The fuzzer needs the accepting path within seconds: in 3 of 4
	 * inputs the target is link-local (router case) and the destination
	 * is not multicast, in 1 of 2 of those the target equals the
	 * destination (on-link case); CBMC finds these by itself.
	 */
	if (usual()) {
		set_byte(m, 40 + 8, 0xfe);
		set_byte(m, 40 + 8 + 1, 0x80);
		if (nondet_bool()) {
			int i;

			for (i = 0; i < 16; i++)
				set_byte(m, 40 + 24 + i,
				    get_byte(m, 40 + 8 + i));
		}
	}
	/* a target link-layer address option, length 1 or 2, an Ethernet ifp */
	if (total >= 88 && usual()) {
		set_byte(m, 80, ND_OPT_TARGET_LINKADDR);
		set_byte(m, 81, nondet_bool() ? 1 : 2);
	}
	if (usual())
		ifp->if_addrlen = 6;
#endif
	table0->rt_gateway = nondet_bool() ? build_gate(&obj, &ip6->ip6_src) :
	    NULL;
	if (table0->rt_gateway == NULL)
		obj = NULL;

	icmp6_redirect_input(m, sizeof(struct ip6_hdr));

	__CPROVER_assert(table0->rt_refcnt.r_refs == 1,
	    "every reference taken is dropped (destination route)");
	__CPROVER_assert(newrt0->rt_refcnt.r_refs == 1,
	    "every reference taken is dropped (redirect route)");
	__CPROVER_assert(g_ifrefs == 0,
	    "every interface reference taken is dropped");

	mc_release(table0);
	mc_release(newrt0);
	if (obj != NULL)
		mc_release(obj);
	mc_release(ifp);
	return (0);
}
