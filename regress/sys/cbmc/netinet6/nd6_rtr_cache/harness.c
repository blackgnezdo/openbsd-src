/*
 * Harness: nd6_rtr_cache() of sys/netinet6/nd6_rtr.c on a Router
 * Solicitation or Router Advertisement (RFC 4861, 6.1, 6.2): the kernel
 * only caches the sender's link-layer address (OpenBSD leaves the rest
 * to slaacd).
 *
 * Why: the function takes the source link-layer address option out of
 * the packet and hands it to nd6_cache_lladdr() if the option length is
 * that of if_addrlen (nd6_rtr.c:124, the same test as nd6_ns_input and
 * icmp6_redirect_input; netinet6/nd6_consumers assumes it).  Without the
 * test a short option would be over-read by the bcmp/bcopy of
 * nd6_cache_lladdr.
 *
 * The caller (icmp6_input, icmp6.c:642-659) guarantees: the hop limit is
 * not checked there, the ICMPv6 code is 0, icmp6len = m_pkthdr.len - off
 * (icmp6.c:393) is at least sizeof(struct nd_router_solicit) (8) for an
 * RS and sizeof(struct nd_router_advert) (16) for an RA (icmp6.c:646-650),
 * the checksum is good, the type is ND_ROUTER_SOLICIT or ND_ROUTER_ADVERT
 * (the KASSERT).  It passes a copy made by m_copym(), which this function
 * frees on every path ("m stays"), or, when m_copym fails, m itself, which
 * this function frees (icmp6.c:653-657: m = NULL, goto freeit).  So the
 * function owns its mbuf chain: every path frees it, and ip6_exthdr_get
 * frees it when it fails.  A copy has the same data in some chain of
 * mbufs: one or two mbufs, the first holding at least the IPv6 header, the
 * split arbitrary, covers the shapes of the harness's packets.
 *
 * The packet.  The mbuf contract models (common/mbufcontract.h): an IPv6
 * header (40 bytes), an RS (8 bytes) or an RA (16 bytes) with 0..16 option
 * bytes of arbitrary content (none, one or two 8 byte options, fragments
 * nd6_options refuses): 48..64 bytes (RS) or 56..72 (RA), in one or two
 * mbufs, the first holding at least the IPv6 header, the split arbitrary.
 * off is 40 (no extension header) and icmp6len = total - 40.  The content
 * is arbitrary, except ip6_plen, which is set to total - 40 as ip6_input()
 * leaves it (ip6_input.c:702-715); this function does not read it.  The
 * hop limit, the source address and everything after the header are
 * arbitrary bytes of the packet: the hop limit test, the unspecified and
 * link-local tests run as the kernel's.  m_pkthdr.ph_ifidx arbitrary.
 * icmp6_type is ND_ROUTER_SOLICIT or ND_ROUTER_ADVERT (nondet); the type
 * byte inside the packet is not read by this function.
 *
 * Interface: one ifnet, if_addrlen 0..255 (arbitrary: the length test
 * meets every value; the option area allows lladdrlen 8 or 16, so if_addrlen
 * up to 14 can pass), ip6_forwarding arbitrary (i_am_router).
 *
 * Models below nd6_rtr_cache (every one stated):
 *   nd6_cache_lladdr  NOT the real body: a model that asserts what it is
 *            passed, as in netinet6/icmp6_redirect: ifp is the interface,
 *            from readable (16 bytes), the type is the one passed in, code
 *            0, i_am_router is ip6_forwarding != 0; when lladdr != NULL:
 *            lladdrlen == (if_addrlen + 9) & ~7 (what its callers check),
 *            lladdr readable for lladdrlen - 2 bytes (the option holds
 *            them) and for if_addrlen bytes (what the real body's bcmp and
 *            bcopy read); when lladdr == NULL lladdrlen is 0.  Natively it
 *            also reads those bytes.  The real body on a route that
 *            satisfies the nd6 invariant is netinet6/nd6_consumers.
 *   if_get, if_put  if_get returns NULL (interface detached) or the
 *            interface with a count; if_put ignores NULL, otherwise asserts
 *            the count and drops it; the count is 0 at the end.
 *   m_pulldown, m_freem, m_free: mbufcontract.h.  counters_inc: nobody
 *            (statistics).
 * Kept bodies: nd6_rtr_cache, nd6_options (nd6.c), ip6_exthdr_get.
 *
 * Properties: no out-of-bounds access, no leak or double free
 * (--memory-leak-check; the harness never touches the chain after the
 * call), interface references balanced, the nd6_cache_lladdr contract.
 *
 * Bounds: packet 48..72 bytes, options 0..16 bytes (nd6_options: --unwind 4
 * covers its loop, the unwinding assertion proves it: every option is at
 * least 8 bytes), if_addrlen 0..255.  Not covered: extension headers
 * (off > 40), packets above 72 bytes, the real nd6_cache_lladdr, the
 * "too many options" exit of nd6_options (needs 88 option bytes; see
 * netinet6/nd6_options).
 *
 * Mutants: mutant/nd6_rtr.c has the lladdr length test (nd6_rtr.c:124-126)
 * removed; mutant_off1/nd6_rtr.c rounds one byte short (if_addrlen + 2 + 6)
 * so an if_addrlen of 7 passes with a 6 byte address.
 */
#define MC_MAXLEN	72
#define MC_COPY_LOOP
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/queue.h>
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

#include "nd6_rtr.c"
#include "nd6.c"

int ip6_forwarding;

static struct ifnet *the_ifp;
static int g_ifrefs;
static int g_type;

/* ---- models below nd6_rtr_cache ---- */

static volatile unsigned char sink;

void
model_nd6_cache_lladdr(struct ifnet *ifp, const struct in6_addr *from,
    char *lladdr, int lladdrlen, int type, int code, int i_am_router)
{
	__CPROVER_assert(ifp == the_ifp, "nd6_cache_lladdr model: interface");
	__CPROVER_assert(__CPROVER_r_ok(from, sizeof(*from)),
	    "nd6_cache_lladdr model: from readable");
	__CPROVER_assert(type == g_type && code == 0,
	    "nd6_cache_lladdr model: type and code");
	__CPROVER_assert(i_am_router == (ip6_forwarding != 0),
	    "nd6_cache_lladdr model: i_am_router");
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

/* ---- the packet ---- */

/*
 * The packet: total bytes in one or two mbufs, the first holding the IPv6
 * header at least, arbitrary content (mc_seg).
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
#endif

int
main(void)
{
	struct ifnet *ifp;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int total, hdrlen, icmp6_type;

	ip6_forwarding = nondet_int();

	ifp = CBMC_NEW(struct ifnet);
	ifp->if_addrlen = nondet_uchar();
	the_ifp = ifp;

	/* an RS or an RA, 0..16 option bytes */
	if (nondet_bool()) {
		icmp6_type = ND_ROUTER_SOLICIT;
		hdrlen = sizeof(struct nd_router_solicit);
	} else {
		icmp6_type = ND_ROUTER_ADVERT;
		hdrlen = sizeof(struct nd_router_advert);
	}
	g_type = icmp6_type;
	total = sizeof(struct ip6_hdr) + hdrlen + mc_upto(16);
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
	/* a source link-layer address option, length 1 or 2, an Ethernet ifp */
	if (total >= 40 + hdrlen + 8 && usual()) {
		set_byte(m, 40 + hdrlen, ND_OPT_SOURCE_LINKADDR);
		set_byte(m, 40 + hdrlen + 1, nondet_bool() ? 1 : 2);
	}
	if (usual())
		ifp->if_addrlen = 6;
#endif

	/* the function owns m: it frees it on every path */
	nd6_rtr_cache(m, sizeof(struct ip6_hdr), total - sizeof(struct ip6_hdr),
	    icmp6_type);

	__CPROVER_assert(g_ifrefs == 0,
	    "every interface reference taken is dropped");

	mc_release(ifp);
	return (0);
}
