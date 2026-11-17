/*
 * Harness: pppoe_dispatch_disc_pkt() of sys/net/if_pppoe.c (static, so
 * the file is #included) on a PPPoE discovery packet of 0..MC_MAXLEN
 * bytes in one or two mbufs, with arbitrary bytes everywhere: Ethernet
 * header, PPPoE header, tags.
 *
 * MC_MAXLEN 26 = 14 Ethernet + 6 PPPoE header + 6 bytes of tags.  The
 * contract models of the mbuf library (common/mbufcontract.h) stand in
 * for the mbuf code: m_pullup, m_pulldown, m_adj, m_copydata and m_freem
 * promise what the kernel's do, and a read or write past m_len of an
 * mbuf is out of bounds.
 *
 * Softc lookup: pppoe_find_softc_by_hunique() is replaced by a model that
 * returns NULL (file "replace").  The function then ends after the tag
 * loop: every branch that needs a softc goes to done.  Code after the
 * lookup for a non-NULL softc is out of scope.
 *
 * Properties: no out-of-bounds access in the parser; the tag loop ends
 * (unwinding assertions); no mbuf is leaked or
 * freed twice (--memory-leak-check).  The function frees its packet on
 * every path (done: m_freem(m)), so the harness does not free it.
 */
/*
 * syslog's log() is a variadic kernel function; CBMC's builtin library
 * has log(double) under the same name, and the two conflict at typecheck
 * ("conflicting function declarations 'log'").  The kernel's log() is
 * renamed here before any header declares it; its body is removed
 * (file "nobody"), so the renamed name is the no-body function.
 */
#define log	kern_log_model

/*
 * 32 = 14 Ethernet + 6 PPPoE + 12 bytes of tags.  48 (28 bytes of tags)
 * gave 7.2M SAT variables and ran out of memory at the 6000 MB limit
 * (NOTES, runs 6-10); 32 is the largest size that stays within it.  The
 * MAX_PAYLOAD tag (6 bytes), the anchors and the length checks all fit.
 */
#define MC_MAXLEN	26
#include "mbufcontract.h"

/*
 * Ghost state for the loop invariant (file "loops"): the packet's first
 * mbuf, its data object and its length.  The tag loop may replace the
 * second mbuf (m_pulldown) and writes the head's fields; the invariant
 * restates what the code after the loop relies on (m_freem of the chain).
 */
struct mbuf	*g_m;
u_char		*g_buf;
int		 g_pktlen;

#include "if_pppoe.c"

/*
 * Model of the softc lookup: no softc is found.  Calls in
 * pppoe_dispatch_disc_pkt() are redirected here by "replace".
 */
struct pppoe_softc *
model_find_softc_by_hunique(u_int8_t *token, size_t len, u_int ifidx)
{
	return (NULL);
}

int
main(void)
{
	struct mbuf *m;

	m = mc_build(mc_upto(MC_MAXLEN));
	g_m = m;
	g_buf = (u_char *)MC_BUF(m);
	g_pktlen = m->m_pkthdr.len;
	pppoe_dispatch_disc_pkt(m);
	return (0);
}
