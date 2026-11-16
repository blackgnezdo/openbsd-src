/*
 * Harness: tcp_dooptions() on an arbitrary TCP options area of 0..MAXOPT
 * bytes and an arbitrary connection state.  This is the walk half of an
 * assume/guarantee split: tcp_sack_option() is replaced by a model that
 * asserts what tcp_dooptions() promises its callee (the SACK option lies
 * inside the options area); the SACK processing itself is the target
 * netinet/tcp_sack_option.  The whole of tcp_input.c in one target did not
 * finish: every iteration of the walk (up to 40 with one-byte NOPs) is a
 * copy of tcp_sack_option() with its loops (cover run: timeout after
 * 150 s, symbolic execution not finished).
 *
 * Bound: MAXOPT = 28 option bytes (the real maximum is 40): one SACK
 * option with two blocks (18) plus a timestamp option (10).  With 40 and
 * an options object of symbolic size the check run timed out (2 million
 * SAT variables); with 28 and the constant-size object below it takes
 * about 130 s of the 150 s limit, so 40 was not tried again.  Walks that
 * need more than 28 bytes (up to 40 iterations) are not covered.
 *
 * Properties: every read stays inside [cp, cp + cnt) (the options are a
 * heap object of exactly that size behind the header, so a read of one
 * byte too many is a bad dereference), the walk terminates (unwinding
 * assertions; zero and short optlen must not loop or run off the end),
 * tcp_sack_option() is called with an option inside the area, and
 * requested_s_scale is clamped.  TCP_SIGNATURE and INET6 are defined, as
 * in GENERIC; tcp_signature(), gettdbbysrcdst() and tdb_unref() have no
 * body (they are not in sources, so every function without a body here has
 * none).
 *
 * What the callers guarantee (tcp_input.c).  There are two call sites:
 *
 *   A  tcp_input_solocked(), "Process options"
 *	th = ip6_exthdr_get(mp, iphlen, off) with off = th_off * 4, 20 < off
 *	<= 60, pulled up into the first mbuf; optp = (u_int8_t *)(th + 1),
 *	optlen = off - sizeof(struct tcphdr).  So the options directly
 *	follow the header in memory (the harness allocates header and
 *	options as one object, cp behind the header) and cnt is a multiple
 *	of 4 in 4..40.  The harness lets cnt be any value in 0..MAXOPT: a
 *	superset.  cnt == 0 stands for optp == NULL (the timestamp shortcut
 *	sets optp to NULL and leaves optlen; tcp_dooptions is then only
 *	called for TF_SIGNATURE, and the loop tests "cp &&").  tp is never
 *	NULL: it comes from intotcpcb(inp) after "if (tp == NULL) goto
 *	dropwithreset_ratelim"; the state is not CLOSED (dropped) and not
 *	LISTEN (panic "tcp_input: TCPS_LISTEN").
 *
 *   B  syn_cache_add(): tp is &tb, a bzero'd stack tcpcb with pf,
 *	sack_enable, t_flags and t_state = TCPS_LISTEN set; the segment is a
 *	pure SYN (tcp_input gets there for
 *	(th_flags & (TH_RST|TH_SYN|TH_ACK)) == TH_SYN only).
 *
 *   tp is not NULL at either site.  oi points to a struct tcp_opt_info
 *   with ts_present = 0, maxseg = 0.  m is the mbuf of the packet; only
 *   the TCP_SIGNATURE code looks at it (mtod for the addresses), the
 *   harness gives it an IP header buffer of the size of an IPv6 header.
 *
 * tp: t_state, t_flags, sack_enable and the header flags are arbitrary
 * (within the ranges above); everything else is zero, the option handlers
 * only write the rest.
 *
 * Out of the model, no body: tcpstat_inc (per-CPU counters, listed in
 * nobody), tcp_signature (reads the packet), gettdbbysrcdst (returns an
 * arbitrary pointer that tcp_dooptions never dereferences), tdb_unref,
 * rtable_l2, timingsafe_bcmp (so its two 16-byte reads, sigp and cp + 2,
 * are not checked; both lie inside the option because optlen is
 * TCPOLEN_SIGNATURE).
 */
#define TCP_SIGNATURE 1
#define INET6 1
#include "tcp_input.c"
#include "cbmc_harness.h"

#define MAXOPT	28

/*
 * Guarantee of tcp_dooptions() to tcp_sack_option(): the option header
 * and its optlen bytes are readable, optlen >= 2 and the option is a SACK
 * option with that length.  The model reads the last byte so that a
 * violation is a bad dereference as well.
 */
void
model_tcp_sack_option(struct tcpcb *tp, struct tcphdr *th, u_char *cp,
    int optlen)
{
	volatile u_char sink;

	__CPROVER_assert(tp != NULL && th != NULL, "tcp_sack_option: tp or th");
	__CPROVER_assert(optlen >= 2 && optlen <= MAXOPT,
	    "tcp_sack_option: optlen out of range");
	__CPROVER_assert(cp[0] == TCPOPT_SACK, "tcp_sack_option: not a SACK option");
	__CPROVER_assert(cp[1] == optlen, "tcp_sack_option: optlen != cp[1]");
	sink = cp[optlen - 1];	/* the last byte; the area is contiguous */
}

int
main(void)
{
	struct tcpcb *tp;
	struct tcphdr *th;
	u_char *block, *cp;
	struct tcp_opt_info opti;
	static struct mbuf mb;
	static char iphdr[sizeof(struct ip6_hdr)];
	u_int flags0;
	int cnt, rc;

	mb.m_data = iphdr;

	/*
	 * Header and options as one object of constant size, the options
	 * ending exactly at the end of the object: cnt bytes behind the
	 * header, a read of one byte past them is outside the object.  (An
	 * object of symbolic size, malloc(sizeof(*th) + cnt), made the
	 * solver time out.)  The bytes in front of the header stay unused.
	 */
	cnt = nondet_uint() % (MAXOPT + 1);
	block = malloc(sizeof(struct tcphdr) + MAXOPT, M_DEVBUF, M_WAITOK);
	th = (struct tcphdr *)(block + (MAXOPT - cnt));
	cp = cnt > 0 ? block + sizeof(struct tcphdr) + (MAXOPT - cnt) : NULL;

	opti.ts_present = 0;
	opti.maxseg = 0;
	opti.ts_val = 0;
	opti.ts_ecr = 0;

	tp = CBMC_NEW(struct tcpcb);
	tp->sack_enable = nondet_bool() ? 1 : 0;
	if (nondet_bool()) {
		/* A: tcp_input_solocked() */
		tp->t_state = TCPS_SYN_SENT +
		    nondet_uint() % (TCPS_TIME_WAIT - TCPS_SYN_SENT + 1);
		tp->t_flags = nondet_uint();
	} else {
		/* B: syn_cache_add(), struct tcpcb tb, bzero'd */
		tp->pf = nondet_uchar();
		tp->t_flags = nondet_bool() ? (TF_REQ_SCALE | TF_REQ_TSTMP) : 0;
		if (nondet_bool())
			tp->t_flags |= TF_SIGNATURE;
		tp->t_state = TCPS_LISTEN;
		/* a pure SYN */
		th->th_flags = (th->th_flags | TH_SYN) & ~(TH_ACK | TH_RST);
	}
	flags0 = tp->t_flags;

	rc = tcp_dooptions(tp, cp, cnt, th, &mb, nondet_int(), &opti,
	    nondet_uint(), nondet_u64());

	__CPROVER_assert(rc == 0 || rc == -1, "tcp_dooptions result");
	if (!(flags0 & TF_RCVD_SCALE) && (tp->t_flags & TF_RCVD_SCALE))
		__CPROVER_assert(tp->requested_s_scale <= TCP_MAX_WINSHIFT,
		    "window scale not clamped");
	return (0);
}
