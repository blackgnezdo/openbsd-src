/*
 * Harness: sppp_lcp_RCR() of sys/net/if_spppsubr.c, the analysis of an
 * LCP Configure-Request, on an arbitrary LCP packet of 4..MAXLEN bytes
 * (header, then options) and a struct sppp with arbitrary fields.
 *
 * Caller contract, read from the source:
 *   sppp_input() makes the packet contiguous: "if (m->m_len <
 *   m->m_pkthdr.len) m = m_pullup(m, m->m_pkthdr.len)".  So len bytes are
 *   readable at h, len = m_pkthdr.len.
 *   sppp_cp_input() sets len = min(m_pkthdr.len, ntohs(h->len)), and calls
 *   RCR for CONF_REQ only after "if (len < 4) break".  So 4 <= len <=
 *   readable bytes.  The harness sets h->len to len (the consistent case).
 *   RCR is not called in the STATE_CLOSING/STOPPING/CLOSED cases.
 *
 * Sizes: MAXLEN 24 is the packet bound of this proof (4 header bytes and 20 option
 * bytes, at most 10 options; the real limit is a 16-bit length: a 48-byte or
 * longer packet is not covered (a 48-byte model did not finish the
 * solver in 1500 s).  The packet is a
 * constant-size object with its data at the END (h = obj + MAXLEN - len),
 * so any read or write past the packet's last byte is out of bounds.
 * Every byte is arbitrary.  The option loops are unwound (opts), no loop
 * contracts ("loops" is empty): see opts.
 *
 * Environment models: sppp_cp_send is replaced by model_sppp_cp_send,
 * which asserts that the reply is readable for len bytes (inside the
 * object it names: the reject/nak list lives in the buffer RCR allocated
 * with malloc(origlen), and the ack sends the request options).  The
 * allocation may fail (M_NOWAIT, common malloc model).  log, addlog,
 * snprintf and the debug helpers have no body ("nobody").
 *
 * Properties: no out-of-bounds read of the request or write of the
 * reply buffer for arbitrary option bytes; every loop terminates (the
 * decreases clauses in "loops"); the reply lies inside the buffer
 * (readable for len bytes); no leak and no double free (--memory-leak-check).
 */
#define MAXLEN	24
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/timeout.h>
#include <crypto/md5.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <sys/stdarg.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet6/in6_ifattach.h>
#include <net/if_sppp.h>
#include "cbmc_harness.h"

/*
 * struct lcp_header and CONF_REQ are defined in sys/net/if_spppsubr.c,
 * not in a header; copied here unchanged (sources, not included: the
 * included file would keep the bodies of all its functions).
 */
struct lcp_header {
	u_char type;
	u_char ident;
	u_short len;
};
#define CONF_REQ	1

int sppp_lcp_RCR(struct sppp *sp, struct lcp_header *h, int len);

/*
 * bcopy(9) as a range check.  The byte loop of common/stubs_alloc.c
 * cannot run inside the contracted option loops of RCR (goto-instrument
 * refuses, or crashes on, a loop of a callee there; README "Writing a
 * loop contract", "loop-free model").  Nothing RCR does reads the copied
 * bytes: the reply buffer goes to sppp_cp_send, and the reply content is
 * not inspected.  So the model asserts what the copy needs, n bytes
 * readable at src and n bytes writable at dst, and copies nothing.
 */
void
model_bcopy(const void *src, void *dst, size_t n)
{
	__CPROVER_assert(n == 0 || (__CPROVER_r_ok(src, n) &&
	    __CPROVER_w_ok(dst, n)), "bcopy: source or destination range");
#ifdef NATIVE_SHIM_H
	/* native build: copy for real, so that ASan checks the ranges */
	if (n)
		__builtin_memmove(dst, src, n);
#endif
}

/*
 * The reply to sppp_cp_send: data must be readable for len bytes.  For
 * CONF_REJ and CONF_NAK that is the buffer malloc'ed with origlen bytes,
 * so a rejected or nak'ed list longer than the buffer is reported here.
 * For CONF_ACK it is the request's options.
 */
void
model_sppp_cp_send(struct sppp *sp, u_short proto, u_char type,
    u_char ident, u_short len, void *data)
{
	__CPROVER_assert(len == 0 || __CPROVER_r_ok(data, len),
	    "sppp_cp_send: reply is not readable for len bytes");
}

int
main(void)
{
	struct sppp *sp;
	struct lcp_header *h;
	u_char *obj;
	int len, i, rv;

	obj = CBMC_NEW_ARRAY(u_char, MAXLEN);
	for (i = 0; i < MAXLEN; i++)
		obj[i] = nondet_uchar();
	len = 4 + nondet_uint() % (MAXLEN - 4 + 1);	/* 4..MAXLEN */
	h = (struct lcp_header *)(obj + MAXLEN - len);
	h->type = CONF_REQ;
	h->len = htons(len);

	sp = CBMC_NEW(struct sppp);
	sp->pp_if.if_flags = nondet_bool() ? IFF_DEBUG : 0;
	sp->myauth.proto = nondet_ushort();
	sp->hisauth.proto = nondet_ushort();
	sp->lcp.magic = nondet_ulong();
	sp->lcp.max_failure = nondet_uint() % 4;
	sp->fail_counter[IDX_LCP] = nondet_uint() % 4;
	sp->pp_flags = nondet_uint();
	sp->pp_loopcnt = nondet_ushort();

	rv = sppp_lcp_RCR(sp, h, len);
	__CPROVER_assert(rv == -1 || rv == 0 || rv == 1,
	    "sppp_lcp_RCR returns -1, 0 or 1");

	free(sp, M_TEMP, sizeof(struct sppp));
	free(obj, M_TEMP, MAXLEN);
	return (0);
}
