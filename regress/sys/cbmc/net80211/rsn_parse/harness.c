/*
 * Harness: the RSN and WPA information element parsers of
 * sys/net80211/ieee80211_input.c, ieee80211_parse_rsn() and
 * ieee80211_parse_wpa(), both on the body parser
 * ieee80211_parse_rsn_body() with its cipher and AKM selector helpers.
 *
 * The harness calls one entry point, chosen by a nondet bool, on one
 * information element frm.  The element is 2 + L bytes: frm[0] the
 * element id (not read by the parsers), frm[1] = L the length, and L
 * bytes of body.  The element is the last 2 + L bytes of a single object
 * of constant size 2 + MAXLEN bytes with arbitrary content, so it ends
 * where the object ends (g_end) and any read past the element is out of
 * bounds.  L is 0..MAXLEN (upto() clamps a nondet value); MAXLEN is 64
 * here, the real limit is 255 (frm[1] is one byte).  The bound is a
 * proof bound: elements longer than MAXLEN are not covered.  Measured on
 * the fixed copy (see the result below): check phase 74 s at 64, 172 s at
 * 80 (unwinding 20), and a timeout at 300 s at 96 (unwinding 24); 255 is
 * far beyond that.  72 was not tried.
 *
 * Caller guarantee, read from the tree (the element loops of the callers
 * stop before an element that does not fit): ieee80211_recv_probe_resp()
 * and ieee80211_recv_assoc_req() loop "while (frm + 2 <= efrm)" and skip
 * an element with "frm + 2 + frm[1] > efrm", and set rsnie and wpaie
 * from frm with that bound (ieee80211_input.c around lines 1705-1706,
 * 1748-1792, 2347-2348, 2381); ieee80211_pae_input.c takes rsnie2 in its
 * element loop (lines 432-442, same bound, "break") and calls the parser
 * at line 511.  So the 2 + frm[1] bytes of
 * the element are inside the received frame: the harness gives exactly
 * that.  The WPA element was further matched by the callers: frm[1] >= 4,
 * the Microsoft OUI and the type byte 1 at frm[5].  The harness does not
 * assume them: the OUI and type bytes stay arbitrary, a superset of what
 * the callers pass (ieee80211_parse_wpa itself checks frm[1] >= 6 only).
 *
 * ic: a zeroed struct ieee80211com; only ic_stats is touched.  rsn: a
 * local, uninitialised struct; the body sets every member the caller
 * reads on a 0 return before any 0 return.
 *
 * Properties: no out-of-bounds access (dereference or pointer
 * arithmetic) for arbitrary element bytes; the loops terminate
 * (unwinding assertions, opts); postcondition, asserted below: if the
 * call returned 0 and rsn.rsn_npmkids != 0, then rsn.rsn_pmkids points
 * inside the element, and rsn_pmkids + rsn_npmkids * IEEE80211_PMKID_LEN
 * does not pass the end of the element.
 *
 * Environment: none modelled; the statistics counter is a plain field of
 * ic.  libkern memcmp (used by the selector helpers) is the byte-loop
 * model of common/stubs_libkern.c, bounded in opts (3 bytes compared).
 * The body loops over the pairwise cipher and AKM lists are bounded in
 * opts at 16 iterations: the list length is checked against the element
 * first, and after the 8 bytes of version, group cipher and count the
 * pairwise list has at most (L - 8) / 4 <= 14 entries for L <= 64.
 *
 * Result (expect): VERIFIED.  mutant_prefix/ is the source before the
 * length tests were written as "efrm - frm" comparisons: "frm + k >
 * efrm" formed a pointer past the element (with a pairwise count of
 * 0xffff, frm + 262140) before comparing; VIOLATED on pointer
 * arithmetic only, nothing was dereferenced out of bounds.  mutant/
 * (the pairwise list length check removed) is VIOLATED with
 * out-of-bounds reads of the cipher selectors.  Native (expect.native):
 * CLEAN.
 */
#define MAXLEN	64

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/task.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_llc.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_priv.h>
#include "cbmc_harness.h"

int ieee80211_parse_rsn(struct ieee80211com *, const u_int8_t *,
    struct ieee80211_rsnparams *);
int ieee80211_parse_wpa(struct ieee80211com *, const u_int8_t *,
    struct ieee80211_rsnparams *);

/*
 * An object of 2 + MAXLEN bytes with arbitrary content (as nd6_options'
 * option_buffer in netinet6/nd6_options/harness.c).
 */
static u_int8_t *
element_buffer(void)
{
	u_int8_t *buf = (u_int8_t *)__CPROVER_allocate(2 + MAXLEN, 0);
#ifdef NATIVE_SHIM_H
	int i;

	for (i = 0; i < 2 + MAXLEN; i++)
		buf[i] = nondet_uchar();
#endif
	return (buf);
}

/* an arbitrary int in [0, n]; a clamp, cheaper than a modulo */
static unsigned int
upto(unsigned int n)
{
	unsigned int v = nondet_uint() & 0xffff;

	return (v > n ? n : v);
}

int
main(void)
{
	struct ieee80211com *ic;
	struct ieee80211_rsnparams rsn;
	u_int8_t *buf, *frm, *efrm;
	unsigned int len;
	int rc;

	buf = element_buffer();
	len = upto(MAXLEN);			/* L: 0..MAXLEN body bytes */
	frm = buf + (MAXLEN - len);		/* element = last 2 + L bytes */
	frm[1] = len;				/* the element length */
	efrm = frm + 2 + len;			/* == buf + 2 + MAXLEN == end */

	ic = CBMC_NEW(struct ieee80211com);
	if (nondet_bool())
		rc = ieee80211_parse_rsn(ic, frm, &rsn);
	else
		rc = ieee80211_parse_wpa(ic, frm, &rsn);

	if (rc == 0 && rsn.rsn_npmkids != 0) {
		__CPROVER_assert(rsn.rsn_pmkids >= frm &&
		    rsn.rsn_pmkids + rsn.rsn_npmkids * IEEE80211_PMKID_LEN <=
		    efrm, "PMKID list inside the element");
	}
	return (0);
}
