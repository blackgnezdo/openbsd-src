/*
 * Harness: ip_dooptions() of sys/netinet/ip_input.c on an arbitrary IP
 * header of 6..15 words (ip_hl) with arbitrary option bytes, on the
 * contract models of the mbuf library (common/mbufcontract.h).
 *
 * Caller contract (ip_input.c: m_pullup(m, hlen) when hlen > m->m_len,
 * and "hlen > sizeof (struct ip) && ip_dooptions(...)"): the hlen header
 * bytes are contiguous at mtod(m).  The harness does the same.  The
 * packet is exactly hlen bytes long and the first mbuf's data area is
 * exactly m_len bytes, so a read or write past the header is out of
 * bounds.
 *
 * Properties: no out-of-bounds access; the option walk ends (unwinding
 * assertions; 41 iterations cover 40 one-byte options); if the function
 * returns 0 the chain is still well formed and is freed here (leak
 * check); if it returns 1 icmp_error or ip_forward consumed the mbuf.
 *
 * Callees: rtalloc, rtisvalid, ifa_ifwithaddr, ifaof_ifpforaddr give
 * any answer over static objects; icmp_error and ip_forward free the
 * mbuf.  save_rte and counters_inc have no body (nobody).
 */
#define MC_MAXLEN	60
#include "mbufcontract.h"

/* ghost state for the loop invariant (target file "loops") */
u_char *g_end;		/* one past the last header byte */

#include "ip_input.c"

/* routing and interface objects of the models: static, never freed */
static struct rtentry model_rt;
static struct in_ifaddr model_ia;
static struct ifnet model_ifp;

struct rtentry *
model_rtalloc(const struct sockaddr *dst, int flags, unsigned int tableid)
{
	if (mc_upto(1) == 0)
		return (NULL);
	model_rt.rt_flags = mc_upto(RTF_UP | RTF_GATEWAY);
	model_rt.rt_ifa = (struct ifaddr *)&model_ia;
	return (&model_rt);
}

int
model_rtisvalid(struct rtentry *rt)
{
	return (rt != NULL && (rt->rt_flags & RTF_UP) != 0);
}

struct ifaddr *
model_ifa_ifwithaddr(const struct sockaddr *sa, u_int tableid)
{
	return (mc_upto(1) ? (struct ifaddr *)&model_ia : NULL);
}

struct ifaddr *
model_ifaof_ifpforaddr(const struct sockaddr *sa, struct ifnet *ifp)
{
	return (mc_upto(1) ? (struct ifaddr *)&model_ia : NULL);
}

void
model_icmp_error(struct mbuf *m, int type, int code, u_int32_t dest, int mtu)
{
	m_freem(m);
}

void
model_ip_forward(struct mbuf *m, struct ifnet *ifp, struct route *ro,
    int flags)
{
	m_freem(m);
}

int
main(void)
{
	struct mbuf *m;
	struct ip *ip;
	int ihl, hlen, flags, ret;

	ip_dosourceroute = mc_upto(1);		/* SSRR/LSRR refused or not */
	ihl = 6 + mc_upto(9);			/* ip_hl 6..15 */
	hlen = ihl << 2;
#ifdef VIA_PULLUP
	m = mc_build(hlen);
	m = m_pullup(m, hlen);			/* as ip_input does */
	if (m == NULL)
		return (0);
#else
	/* the state after ip_input's m_pullup(m, hlen) */
	m = mc_seg(hlen);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = hlen;
#endif
	ip = mtod(m, struct ip *);
	g_end = mtod(m, u_char *) + hlen;
	ip->ip_v = IPVERSION;
	ip->ip_hl = ihl;
	/* IP_FORWARDING, IP_REDIRECT, IP_ALLOWBROADCAST, any combination */
	flags = mc_upto(7);
	ret = ip_dooptions(m, &model_ifp, flags);
	if (ret == 0) {
		mc_check(m);
		mc_free(m);
	}
	return (0);
}
