/*
 * Harness: session demultiplexing of sys/net/if_pppoe.c
 * (static, so the file is #included): pppoe_data_input() and
 * pppoe_vinput() on one frame of 0..MC_MAXLEN bytes in one or two mbufs,
 * arbitrary bytes (Ethernet header, PPPoE header, payload).
 *
 * Softcs: two, each on pppoe_softc_list, each on pppoe_sessions when its
 * state is PPPOE_STATE_SESSION (pppoe_dispatch_disc_pkt PADS inserts it
 * there as it enters that state).  Arbitrary sc_state, sc_session,
 * sc_eth_ifidx and sc_dest: two concentrators that picked the same
 * session ID on the same Ethernet interface are among the cases.
 *
 * Property (RFC 2516: a session is the session ID with both Ethernet
 * endpoints): a frame reaches a session's interface (sppp_input from
 * pppoe_data_input, if_vinput from pppoe_vinput) only when its Ethernet
 * source is that session's concentrator, sc_dest, and its session ID and
 * receiving interface are the session's.
 * Completeness: a well-formed frame (one mbuf, version/type 0x11, code
 * 0, plen inside the frame, a protocol that is up) whose session ID,
 * receiving interface and source are a session's is delivered; the
 * tuple names at most one session and session ID 0 is never one.
 *
 * Models: the mbuf contract models (common/mbufcontract.h);
 * sppp_input, if_vinput: the property, then free the packet;
 * sppp_proto_up: arbitrary af; pppoe_send_padt: nothing; getuptime:
 * arbitrary; refcnt_take, if_put: nothing (the reference is not the
 * subject).  No body: smr_read_enter/leave, counters_inc, printf, log.
 */
#define log	kern_log_model
#define MC_MAXLEN	26
#include "mbufcontract.h"
#include "if_pppoe.c"

/* kernel free(9) is kfree here; CBMC's free for the softcs made below */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

static struct pppoe_softc	*g_sc[2];
static u_int8_t			 g_shost[ETHER_ADDR_LEN];
static u_int16_t		 g_session;
static u_int			 g_ifidx;
static int			 g_delivered;
static int			 g_live;	/* well-formed frame mode */

static void
delivered(struct ifnet *ifp)
{
	struct pppoe_softc *sc = (struct pppoe_softc *)ifp;
	int i;

	__CPROVER_assert(ifp == &g_sc[0]->sc_sppp.pp_if ||
	    ifp == &g_sc[1]->sc_sppp.pp_if, "delivery: to a pppoe softc");
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		__CPROVER_assert(sc->sc_dest.ether_addr_octet[i] ==
		    g_shost[i], "delivery: source is the session's "
		    "concentrator");
	__CPROVER_assert(sc->sc_session == g_session,
	    "delivery: session ID is the session's");
	__CPROVER_assert(sc->sc_eth_ifidx == g_ifidx,
	    "delivery: received on the session's interface");
	g_delivered++;
}

void
sppp_input(struct ifnet *ifp, struct mbuf *m)
{
	delivered(ifp);
	m_freem(m);
}

void
if_vinput(struct ifnet *ifp, struct mbuf *m, struct netstack *ns)
{
	delivered(ifp);
	m_freem(m);
}

int
sppp_proto_up(struct ifnet *ifp, uint16_t proto)
{
	int af = g_live ? AF_INET : nondet_int();

	__CPROVER_assume(af == AF_UNSPEC || af == AF_INET || af == AF_INET6);
	return (af);
}

int
model_send_padt(unsigned int ifidx, u_int session, const u_int8_t *dest,
    u_int8_t code)
{
	return (0);
}

time_t
getuptime(void)
{
	return ((time_t)(nondet_u64() & 0xffffffffffULL));
}

void
refcnt_take(struct refcnt *r)
{
}

void
if_put(struct ifnet *ifp)
{
}

/* the frame's (session, interface, source) is this session's tuple */
static int
match(struct pppoe_softc *sc)
{
	int i;

	if (sc->sc_state != PPPOE_STATE_SESSION ||
	    sc->sc_session != g_session || sc->sc_eth_ifidx != g_ifidx)
		return (0);
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		if (sc->sc_dest.ether_addr_octet[i] != g_shost[i])
			return (0);
	return (1);
}

int
main(void)
{
	struct ifnet ifp0;
	struct mbuf *m, *r;
	int i, j, len;

	for (i = 0; i < 2; i++) {
		struct pppoe_softc *sc = CBMC_NEW(struct pppoe_softc);

		sc->sc_state = nondet_int();
		sc->sc_session = nondet_u16();
		sc->sc_eth_ifidx = nondet_uint() & 3;
		for (j = 0; j < ETHER_ADDR_LEN; j++)	/* CBMC_NEW zeroes */
			sc->sc_dest.ether_addr_octet[j] = nondet_u8();
		sc->sc_bpf = NULL;
		sc->sc_sppp.pp_if.if_flags = nondet_bool() ? IFF_LINK2 : 0;
		LIST_INSERT_HEAD(&pppoe_softc_list, sc, sc_list);
		if (sc->sc_state == PPPOE_STATE_SESSION)
			SMR_LIST_INSERT_HEAD_LOCKED(&pppoe_sessions, sc,
			    sc_session_entry);
		g_sc[i] = sc;
	}

	len = mc_upto(MC_MAXLEN);
	/* ether_input hands over at least the Ethernet header, contiguous */
	__CPROVER_assume(len >= (int)sizeof(struct ether_header));
	m = mc_build(len);
	__CPROVER_assume(m->m_len >= (int)sizeof(struct ether_header));
	memcpy(g_shost, mtod(m, struct ether_header *)->ether_shost,
	    ETHER_ADDR_LEN);
	if (len >= (int)(sizeof(struct ether_header) + PPPOE_HEADERLEN)) {
		u_int8_t s[2];

		m_copydata(m, sizeof(struct ether_header) + 2, 2, s);
		g_session = (s[0] << 8) | s[1];
	}

	/*
	 * Completeness: a well-formed frame (one mbuf, version/type 0x11,
	 * code 0, plen inside the frame, a protocol that is up) whose
	 * (session, receiving interface, source) is the tuple of a session
	 * is delivered.  The tuple identifies at most one session (RFC
	 * 2516), and session ID 0 is never a session's.
	 */
	g_live = nondet_bool();
	g_ifidx = nondet_uint() & 3;
	if (g_live) {
		struct pppoehdr *ph;

		__CPROVER_assume(m->m_len == len && len >= (int)
		    (sizeof(struct ether_header) + PPPOE_HEADERLEN + 2));
		ph = (struct pppoehdr *)(mtod(m, caddr_t) +
		    sizeof(struct ether_header));
		__CPROVER_assume(ph->vertype == PPPOE_VERTYPE &&
		    ph->code == 0);
		__CPROVER_assume(ntohs(ph->plen) >= 2 &&
		    ntohs(ph->plen) <= len - (int)
		    (sizeof(struct ether_header) + PPPOE_HEADERLEN));
	}
	for (i = 0; i < 2; i++)
		__CPROVER_assume(g_sc[i]->sc_state != PPPOE_STATE_SESSION ||
		    g_sc[i]->sc_session != 0);
	__CPROVER_assume(!(match(g_sc[0]) && match(g_sc[1])));

	if (nondet_bool()) {
		m->m_pkthdr.ph_ifidx = g_ifidx;
		pppoe_data_input(m);
	} else {
		ifp0.if_index = g_ifidx;
		r = pppoe_vinput(&ifp0, m, NULL);
		if (r != NULL)
			m_freem(r);
	}
	if (g_live && (match(g_sc[0]) || match(g_sc[1])))
		__CPROVER_assert(g_delivered == 1,
		    "completeness: a frame of a session is delivered");
	harness_release(g_sc[0]);
	harness_release(g_sc[1]);
	return (0);
}
