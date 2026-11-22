/*
 * Harness: pfsync_input() of sys/net/if_pfsync.c (static, so the file is
 * #included) -- the framing of a pfsync packet: the pfsync header
 * (version, length against the packet) and the walk over the subheaders
 * (action, length in dwords, count), each checked against
 * pfsync_acts[action].len and the remaining length and handed to
 * pfsync_acts[action].in with a pointer and a count.
 *
 * Packet: 0..44 bytes of pfsync packet of arbitrary content (the IP
 * header already stripped: hlen 0, see main), in one or two mbufs, the
 * first of arbitrary length (common/mbufcontract.h: every mbuf's data ends where
 * its object ends, so a read past m_len is out of bounds).  ttl and the
 * receiving interface index are arbitrary.
 *
 * Caller (pfsync_input4, if_pfsync.c, via ip_deliver): ip = mtod(m)
 * is read at once, so the IP header is contiguous in the first mbuf
 * (ip_input.c ipv4_check: m_pullup to hlen); ip_len equals the chain
 * length (ipv4_check trims the chain to ip_len); hlen = ip_hl << 2, here
 * 20; ttl = ip_ttl.  pfsync_input4 frees the returned chain (m_freem(m),
 * NULL allowed): the harness does the same.
 *
 * State: pf_status.running = 1; one softc, pfsyncif = sc (it is only set
 * when the interface is up), sc_sync_ifidx = 1 (the packet's ph_ifidx is
 * arbitrary: a packet from another interface is dropped), sc_refs 1.
 * The reference taken for the walk is counted (model_refcnt_*) and
 * asserted balanced.
 *
 * Models:
 *   pfsync_in_clr, _iack, _upd_c, _ureq, _del, _del_c, _bus, _tdb, _ins,
 *   _upd	each asserts the contract the framing owes the handler:
 *		mlen >= the size of the handler's message (what
 *		pfsync_acts[action].len holds), and the buffer is readable
 *		for mlen * count bytes (one contiguous region inside the
 *		chain).  The real handlers are later targets.
 *   pfsync_in_skip	the handler for an unknown action, a short
 *		message size or an empty table slot: asserts the buffer is
 *		readable for mlen * count bytes.
 *   refcnt_take, refcnt_rele_wake	count the references on sc_refs.
 *   m_pullup, m_adj, m_freem	contract models (mbufcontract.h).
 * Not modelled, no body (NOBODY line): counters_inc, counters_pkt
 * (statistics), smr_read_enter, smr_read_leave.
 *
 * When the first mbuf holds both headers, the harness may write the pfsync
 * header with a version that passes and a length 0..63 (g_decl); the
 * handlers then also assert that what they are given, with its
 * subheaders, lies within that declared length (a length below the
 * header's own size admits nothing).
 *
 * Properties: no out-of-bounds access, no leak or double free, every
 * handler gets mlen * count readable bytes and mlen >= its message size,
 * the reference on the softc is balanced, the walk ends.
 */
#define MC_MAXLEN	44	/* pfsync header and 24 bytes of subheaders */
#define m_pullup	mc_m_pullup
#include "mbufcontract.h"
#undef m_pullup
/* sys/mbuf.h was read under the rename: declare the real name again */
struct mbuf *m_pullup(struct mbuf *, int);

#include "if_pfsync.c"

/*
 * m_pullup: what mc_m_pullup promises (NULL and the chain freed if short
 * or on failure, m if it holds len bytes, else a new chain whose first
 * mbuf holds at least len), without its byte copies: the new bytes are
 * arbitrary.  The framing only bounds-checks what it reads after a
 * pullup, and the declared length is checked only when the header needs
 * none (netinet/icmp_input does the same).
 */
struct mbuf *
m_pullup(struct mbuf *m, int len)
{
	struct mbuf *n;
	int total, first;

	__CPROVER_assert(m != NULL && len >= 0, "m_pullup: arguments");
	total = mc_total(m);
	if (len > total || mc_fails()) {
		m_freem(m);
		return (NULL);
	}
	if (m->m_len >= len)
		return (m);
	first = len + mc_upto(total - len);
	n = mc_seg(first);
	n->m_flags = m->m_flags;
	n->m_pkthdr = m->m_pkthdr;
	if (first < total)
		n->m_next = mc_seg(total - first);
	m_freem(m);
	return (n);
}

static unsigned int model_refs;
static int g_decl;		/* ph->len as the harness wrote it, or -1 */
static unsigned int g_used;	/* subheader and message bytes handed out */

void
model_refcnt_take(struct refcnt *r)
{
	model_refs++;
}

void
model_refcnt_rele_wake(struct refcnt *r)
{
	__CPROVER_assert(model_refs > 0, "refcnt_rele: reference held");
	model_refs--;
}

/* what the framing owes every handler */
static void
check_buf(const caddr_t buf, unsigned int mlen, unsigned int count)
{
	__CPROVER_assert(mlen <= 1020 && count <= 65535, "handler: arguments");
	g_used += sizeof(struct pfsync_subheader) + mlen * count;
	if (g_decl >= 0)
		__CPROVER_assert(g_decl >= (int)sizeof(struct pfsync_header) &&
		    g_used <= g_decl - sizeof(struct pfsync_header),
		    "handler: within the length the pfsync header declares");
	if (mlen * count > 0)
		__CPROVER_assert(__CPROVER_r_ok(buf, mlen * count),
		    "handler: mlen * count bytes readable");
}

#define MODEL_IN(name, type)						\
void									\
model_in_##name(struct pfsync_softc *sc, const caddr_t buf,		\
    unsigned int mlen, unsigned int count)				\
{									\
	__CPROVER_assert(sc == pfsyncif, "handler: softc");		\
	__CPROVER_assert(mlen >= sizeof(struct type),			\
	    "handler: mlen below the message size");			\
	check_buf(buf, mlen, count);					\
}

MODEL_IN(clr, pfsync_clr)
MODEL_IN(iack, pfsync_ins_ack)
MODEL_IN(upd_c, pfsync_upd_c)
MODEL_IN(ureq, pfsync_upd_req)
MODEL_IN(del, pfsync_state)
MODEL_IN(del_c, pfsync_del_c)
MODEL_IN(bus, pfsync_bus)
MODEL_IN(tdb, pfsync_tdb)
MODEL_IN(ins, pfsync_state)
MODEL_IN(upd, pfsync_state)

void
model_in_skip(struct pfsync_softc *sc, const caddr_t buf, unsigned int mlen,
    unsigned int count)
{
	__CPROVER_assert(sc == pfsyncif, "handler: softc");
	check_buf(buf, mlen, count);
}

int
main(void)
{
	static struct pfsync_softc softc;
	struct pfsync_softc *sc = &softc;
	struct mbuf *m;
	int len;

	pf_status.running = 1;
	sc->sc_sync_ifidx = 1;
	pfsyncif = sc;
	model_refs = 0;
	g_used = 0;
	g_decl = -1;

	/*
	 * The pfsync bytes alone: pfsync_input strips the IP header with
	 * m_adj(m, hlen) and reads nothing of it, so the harness passes the
	 * packet with the header already gone and hlen 0.
	 */
	len = mc_upto(MC_MAXLEN);
	m = mc_build(len);
	if (m->m_len >= (int)sizeof(struct pfsync_header) && nondet_bool()) {
		struct pfsync_header *ph = mtod(m, struct pfsync_header *);

		ph->version = PFSYNC_VERSION;
		g_decl = nondet_ushort() & 63;
		ph->len = htons(g_decl);
	}
	m->m_pkthdr.ph_ifidx = nondet_uchar() & 3;

	m = pfsync_input(m, nondet_uchar(), 0);
	__CPROVER_assert(model_refs == 0, "softc references balanced");
	m_freem(m);
	return (0);
}
