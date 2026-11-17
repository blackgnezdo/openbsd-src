/*
 * Harness: nd6_options() of sys/netinet6/nd6.c, the neighbour discovery
 * option parser, on an arbitrary option area of 0..MAXOPT bytes in a flat
 * buffer (no mbufs).
 *
 * The buffer is one object of constant size, MAXOPT bytes of arbitrary
 * content.  The option area is its last icmp6len bytes, so it ends where
 * the object ends (g_end): a read of any option byte past it is out of
 * bounds.  icmp6len is 0..MAXOPT, the length the caller passes.
 *
 * Properties: no out-of-bounds access for arbitrary option bytes; the
 * option walk ends (decreases clause in "loops"); on return -1 every
 * member of *ndopts is NULL; on return 0 every non-NULL member points to
 * an option header inside the option area and the option it points to
 * (nd_opt_len * 8 bytes) lies inside the area.  The struct nd_opts of
 * this tree has two members (nd6.h): the source and the target link-layer
 * address option.
 *
 * Environment: the statistics (icmp6stat_inc, counters_inc) have no body
 * (nobody); they have no effect on the path.  nd6_maxndopt keeps its
 * default of 10, so the "too many options" exit needs 88 or more option
 * bytes and is not covered at MAXOPT 64.
 */
#define MAXOPT		64

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include "cbmc_harness.h"

/* ghost state for the loop invariant (target file "loops") */
u_char *g_end;		/* one past the last byte of the buffer */

int nd6_options(void *, int, struct nd_opts *);

/* an object of MAXOPT bytes with arbitrary content (see mbufcontract.h) */
static u_char *
option_buffer(void)
{
	u_char *buf = (u_char *)__CPROVER_allocate(MAXOPT, 0);
#ifdef NATIVE_SHIM_H
	int i;

	for (i = 0; i < MAXOPT; i++)
		buf[i] = nondet_uchar();
#endif
	return (buf);
}

/* an arbitrary int in [0, n]; a clamp, cheaper than a modulo */
static int
upto(int n)
{
	int v = (int)(nondet_uint() & 0xffff);

	return (v > n ? n : v);
}

/*
 * A member of *ndopts after a successful parse: NULL, or an option header
 * inside the option area whose whole option (nd_opt_len * 8 bytes) is
 * inside it too.
 */
static void
check_option(struct nd_opt_hdr *p, u_char *opt)
{
	if (p == NULL)
		return;
	__CPROVER_assert((u_char *)p >= opt && (u_char *)p + 2 <= g_end,
	    "option header inside the option area");
	__CPROVER_assert(p->nd_opt_len != 0, "option length is not zero");
	__CPROVER_assert((u_char *)p + (p->nd_opt_len << 3) <= g_end,
	    "option inside the option area");
}

int
main(void)
{
	struct nd_opts ndopts;
	u_char *buf, *opt;
	int icmp6len, rc;

	buf = option_buffer();
	icmp6len = upto(MAXOPT);		/* 0..MAXOPT option bytes */
	opt = buf + (MAXOPT - icmp6len);	/* the area ends at the end */
	g_end = buf + MAXOPT;

	rc = nd6_options(opt, icmp6len, &ndopts);
	if (rc != 0) {
		__CPROVER_assert(ndopts.nd_opts_src_lladdr == NULL &&
		    ndopts.nd_opts_tgt_lladdr == NULL,
		    "failed parse leaves no option pointers");
		return (0);
	}
	check_option(ndopts.nd_opts_src_lladdr, opt);
	check_option(ndopts.nd_opts_tgt_lladdr, opt);
	return (0);
}
