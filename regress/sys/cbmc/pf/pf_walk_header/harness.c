/*
 * Harness: pf_walk_header() of sys/net/pf.c, with pf_walk_option() and
 * pf_pull_hdr() below it, on an arbitrary IPv4 packet of 0..68 bytes.
 *
 * Caller: pf_test() (sys/net/pf.c, the IPv4 case of pf_test) checks
 * m_pkthdr.len >= sizeof(struct ip) and m_pkthdr.len >= ntohs(ip_len),
 * takes h = mtod(pd->m, struct ip *) (the first 20 bytes of the packet,
 * in the first mbuf) and calls pf_walk_header(pd, h, reason) with
 * pd->off = 0.  The harness does the same: the two checks are replayed
 * and drop as pf_test does; h is a local copy of the packet's first 20
 * bytes (m_copydata), and pf_pull_hdr reads the packet itself through
 * mtod, so both name the same header.
 *
 * NOT COVERED: the other caller of pf_walk_header, the ICMP-embedded
 * packet in pf_test (sys/net/pf.c, 6480-6500), where the header is not
 * at the start of the packet and pd->off is not 0.
 *
 * Packet: n = 0..68 bytes (60 bytes of header at most plus 8 bytes of
 * payload); ip_hl = nondet & 15, so 0..15 words (ip_hl < 5 is dropped by
 * pf_walk_header itself, not by pf_test); ip_len 20..68, and the packet
 * may be shorter than ip_len, which pf_test drops.  The option and
 * payload bytes are arbitrary (the mbuf's contents are not initialised).
 *
 * Callees: m_copydata, m_freem are the contract models of
 * common/mbufcontract.h.  KASSERT in pf_walk_option is __assert under
 * DIAGNOSTIC; __assert has no body in the kernel's libkern model, so
 * replace maps it to model_assert, which is a panic (a reached panic is a
 * failed property).  pf_hdr_limit is set to 2 (the kernel's default is
 * 20): the AH loop runs at most two times, so --unwind 3 covers it.
 * Nothing else is replaced; REASON_SET, DPFPRINTF and the counters are
 * the kernel's.
 *
 * Properties: no out-of-bounds access in the option copy and the option
 * walk; KASSERT(end - off <= sizeof(opts)) holds; the option walk ends
 * (loop contract, decreases clause); no leak (the packet and pd are
 * freed here).
 */
#define MC_MAXLEN	68	/* 60 bytes of header and 8 of payload */
#include "mbufcontract.h"

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/percpu.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>

#include <net/pfvar.h>
#include <net/pfvar_priv.h>

/* pf.c declares neither of these in a header */
extern int pf_hdr_limit;
int pf_walk_header(struct pf_pdesc *, struct ip *, u_short *);

/* KASSERT's __assert: a failed assertion is a panic of the kernel */
void
model_assert(const char *t, const char *f, int l, const char *e)
{
	panic("kernel assertion");
}

int
main(void)
{
	struct pf_pdesc *pd;
	struct mbuf *m;
	struct ip *pkt, h;
	u_short reason = 0;
	int n, ipl, ret;

	pf_hdr_limit = 2;

	/* packet length, 0..MC_MAXLEN bytes, in one mbuf */
	n = mc_upto(MC_MAXLEN);
	m = mc_seg(n);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = n;
	m->m_pkthdr.ph_ifidx = 0;

	/* pf_test: a packet shorter than a header is dropped */
	if (m->m_pkthdr.len < (int)sizeof(struct ip)) {
		mc_free(m);
		return (0);
	}

	/* the header fields of the packet: ip_hl 0..15, ip_len 20..68 */
	pkt = mtod(m, struct ip *);
	pkt->ip_hl = nondet_uchar() & 15;
	ipl = 20 + mc_upto(MC_MAXLEN - 20);
	pkt->ip_len = htons(ipl);

	/* pf_test: a packet shorter than ip_len is dropped */
	if (m->m_pkthdr.len < ntohs(pkt->ip_len)) {
		mc_free(m);
		return (0);
	}

	/* h: the packet's first 20 bytes, as pf_test's h (mtod) names them */
	m_copydata(m, 0, sizeof(h), &h);

	pd = CBMC_NEW(struct pf_pdesc);
	pd->m = m;
	pd->af = AF_INET;
	pd->off = 0;
	pd->badopts = 0;
	pd->fragoff = 0;
	pd->extoff = 0;
	pd->jumbolen = 0;

	ret = pf_walk_header(pd, &h, &reason);
	(void)ret;

	free(pd, M_TEMP, sizeof(*pd));
	mc_free(m);
	return (0);
}
