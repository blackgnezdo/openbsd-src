/*
 * Harness: pfsync_in_upd() and pfsync_in_upd_c() of sys/net/if_pfsync.c
 * (static, so the file is #included), the handlers for a peer's state
 * update, with pfsync_in_updates() and pfsync_upd_tcp() real, and
 * pf_state_peer_ntoh() of pf.c real.
 *
 * Call, as pfsync_input() makes it (net/pfsync_input proves the framing):
 * in(sc, buf, mlen, count), buf readable for mlen * count bytes, mlen at
 * least the size of the message (struct pfsync_state, 264 bytes, or
 * struct pfsync_upd_c, 84), count from the peer.  Here: buf is an object
 * of exactly mlen * count bytes of arbitrary content, the data ending
 * where the object ends (a read past the last message is out of bounds);
 * count 1 or 2; mlen the message size or that plus 4 (a peer may send
 * larger messages); the handler is pfsync_in_upd or pfsync_in_upd_c.
 *
 * State table: one state, g_st, which pf_find_state_byid() returns or
 * not, per message.  Its timeout is valid (below PFTM_MAX, or
 * PFTM_UNLINKED), its peer states are at most PF_TCPS_PROXY_DST, the
 * sequence numbers arbitrary, each scrub pointer NULL or an object, its
 * wire key's protocol arbitrary (TCP or not), sync_defer NULL or set.
 * The table holds one reference.
 *
 * Models (each replaces the kernel function of the same name, see
 * "replace"; natively the model runs too):
 *   pf_find_state_byid	NULL or &g_st (the key is read for its size).
 *   pf_state_ref, _unref	count the references on g_st: the table's one
 *			is never dropped.
 *   pf_state_scrub_get, _put	NULL or a typed object; counted, the put
 *			frees.
 *   pf_state_import	what the handler promises it and what it does for
 *			it: the whole pfsync_state readable, flags
 *			PFSYNC_SI_PFSYNC, timeout below PFTM_MAX and the
 *			peer states at most PF_TCPS_PROXY_DST (it indexes
 *			r->timeout[sp->timeout]); returns 0, EINVAL, ENOMEM
 *			or EEXIST, and keeps nothing; the import
 *			itself is not part of this target.
 *   pfsync_update_state	asserts st->mtx is not held (the real one does),
 *			and that the update left the state valid.
 *   pfsync_deferred	clears st->sync_defer; the mutex is not held.
 *   pfsync_upd_req_init, m_prepend, pfsync_encap, pfsync_sendout
 *			the UPD_REQ packet pfsync_in_upd_c builds for
 *			states it does not have.  upd_req_init returns
 *			NULL or an empty mbuf with the leading space its
 *			size computation promises (room for count requests
 *			and a subheader: the leading space of an mbuf or
 *			cluster is all of its buffer), m_prepend asserts
 *			that the space is there (it never fails then),
 *			encap fails or marks the chain encapsulated,
 *			sendout consumes it and asserts the subheader and
 *			that its count is the number of requests in it.
 *   mtx_enter, mtx_leave	track the owner (st->mtx: the real code
 *			asserts it unlocked); entering st->mtx is the point
 *			where another CPU may have attached scrub memory
 *			to g_st (the handler allocated without the mutex).
 *   rw_*, rw_status, splassert_fail
 *			PF_LOCK, PF_UNLOCK, PF_ASSERT_LOCKED over pf_lock;
 *			PF_STATE_ENTER_READ/EXIT_READ balanced.
 *   getuptime		an arbitrary time below 2^40.
 * Not modelled, no body (NOBODY line): counters_inc, counters_pkt
 * (statistics).
 *
 * Properties: no out-of-bounds access (the buffer, the state, the
 * requests), no leak or double free, g_st's references as before, the
 * scrub objects taken are attached to g_st or freed, g_st's timeout and
 * peer states valid after the update, st->mtx not held, the locks
 * balanced, a UPD_REQ sent has the declared number of requests.
 */
#define MC_MAXLEN	40	/* 2 requests (12 bytes each) and a subheader */
#include "mbufcontract.h"

#include "if_pfsync.c"
#include "pf.c"

/* the state table */
static struct pf_state g_st;
static struct pf_state_key g_key;
static struct pfsync_deferral g_defer;
static unsigned int g_refs;	/* references on g_st; the table holds 1 */
static int g_scrubs;		/* scrub objects handed out less returned */
static unsigned int g_base_scrubs;	/* scrub objects g_st had of its own */
static int g_pf_locked;		/* pf_lock held */
static int g_state_readers;	/* pf_state_lock held for reading */
static int g_encap;		/* the request packet was encapsulated */
static unsigned int g_recs;	/* requests in the request packet */
static unsigned int g_lead;	/* leading space of the request packet */

static int
valid_timeout(unsigned int t)
{
	return (t < PFTM_MAX || t == PFTM_UNLINKED);
}

static void
check_state(void)
{
	__CPROVER_assert(valid_timeout(g_st.timeout),
	    "state: timeout valid");
	__CPROVER_assert(g_st.src.state <= PF_TCPS_PROXY_DST &&
	    g_st.dst.state <= PF_TCPS_PROXY_DST, "state: peer states valid");
}

struct pf_state *
model_pf_find_state_byid(struct pf_state_cmp *key)
{
	__CPROVER_assert(__CPROVER_r_ok(key, sizeof(*key)),
	    "pf_find_state_byid: key readable");
	return (nondet_bool() ? &g_st : NULL);
}

struct pf_state *
model_pf_state_ref(struct pf_state *st)
{
	if (st != NULL) {
		__CPROVER_assert(st == &g_st && g_refs > 0,
		    "pf_state_ref: live state");
		g_refs++;
	}
	return (st);
}

void
model_pf_state_unref(struct pf_state *st)
{
	if (st != NULL) {
		__CPROVER_assert(st == &g_st && g_refs > 1,
		    "pf_state_unref: reference held beyond the table's");
		g_refs--;
	}
}

struct pf_state_scrub *
model_pf_state_scrub_get(void)
{
	struct pf_state_scrub *s;

	if (nondet_bool())
		return (NULL);
	s = CBMC_NEW(struct pf_state_scrub);
	g_scrubs++;
	return (s);
}

void
model_pf_state_scrub_put(struct pf_state_scrub *s)
{
	__CPROVER_assert(s != NULL && g_scrubs > 0, "scrub_put: object held");
	g_scrubs--;
	mc_release(s);
}

int
model_pf_state_import(const struct pfsync_state *sp, int flags)
{
	__CPROVER_assert(flags == PFSYNC_SI_PFSYNC, "pf_state_import: flags");
	__CPROVER_assert(__CPROVER_r_ok(sp, sizeof(*sp)),
	    "pf_state_import: state readable");
	__CPROVER_assert(g_pf_locked, "pf_state_import: pf_lock held");
	__CPROVER_assert(sp->timeout < PFTM_MAX,
	    "pf_state_import: timeout indexes r->timeout");
	__CPROVER_assert(sp->src.state <= PF_TCPS_PROXY_DST &&
	    sp->dst.state <= PF_TCPS_PROXY_DST,
	    "pf_state_import: peer states in range");
	switch (nondet_uchar() & 3) {
	case 0:
		return (0);
	case 1:
		return (EINVAL);
	case 2:
		return (ENOMEM);
	}
	return (EEXIST);
}

void
model_pfsync_update_state(struct pf_state *st)
{
	__CPROVER_assert(st == &g_st, "pfsync_update_state: state");
	__CPROVER_assert(mtx_owner(&st->mtx) != mtx_curcpu(),
	    "pfsync_update_state: st->mtx not held");
	check_state();
}

void
model_pfsync_deferred(struct pfsync_softc *sc, struct pf_state *st)
{
	__CPROVER_assert(st == &g_st, "pfsync_deferred: state");
	__CPROVER_assert(mtx_owner(&st->mtx) != mtx_curcpu(),
	    "pfsync_deferred: st->mtx not held");
	st->sync_defer = NULL;
}

/* the packet of requests: one mbuf, the leading space of g_lead bytes */
struct mbuf *
model_pfsync_upd_req_init(struct pfsync_softc *sc, unsigned int count)
{
	struct mbuf *m;

	if (nondet_bool())
		return (NULL);
	m = mc_seg(0);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = 0;
	g_recs = 0;
	g_encap = 0;
	/* mlen = max_linkhdr + template + header + subheader + count
	 * requests, all of it in front of the (empty) data */
	g_lead = sizeof(struct pfsync_subheader) +
	    sizeof(struct pfsync_upd_req) * count;
	return (m);
}

struct mbuf *
model_m_prepend(struct mbuf *m, int len, int how)
{
	struct mbuf *n;

	__CPROVER_assert(m != NULL, "m_prepend: chain");
	__CPROVER_assert(len == sizeof(struct pfsync_upd_req) ||
	    len == sizeof(struct pfsync_subheader), "m_prepend: length");
	__CPROVER_assert(len <= g_lead, "m_prepend: leading space");
	g_lead -= len;
	n = mc_seg(m->m_len + len);
	n->m_flags = m->m_flags;
	n->m_pkthdr.len = m->m_pkthdr.len + len;
	m_freem(m);
	if (len == sizeof(struct pfsync_upd_req))
		g_recs++;
	return (n);
}

struct mbuf *
model_pfsync_encap(struct pfsync_softc *sc, struct mbuf *m)
{
	__CPROVER_assert(m != NULL && (m->m_flags & M_PKTHDR),
	    "pfsync_encap: chain");
	if (nondet_bool()) {
		m_freem(m);
		return (NULL);
	}
	g_encap = 1;
	return (m);
}

void
model_pfsync_sendout(struct pfsync_softc *sc, struct mbuf *m)
{
	struct pfsync_subheader *subh;

	__CPROVER_assert(m != NULL && g_encap, "pfsync_sendout: packet");
	__CPROVER_assert(m->m_len >= (int)sizeof(*subh) &&
	    __CPROVER_r_ok(mtod(m, caddr_t), m->m_len),
	    "pfsync_sendout: subheader readable");
	subh = mtod(m, struct pfsync_subheader *);
	__CPROVER_assert(subh->action == PFSYNC_ACT_UPD_REQ &&
	    subh->len == sizeof(struct pfsync_upd_req) >> 2,
	    "pfsync_sendout: subheader");
	__CPROVER_assert(m->m_len == sizeof(*subh) +
	    sizeof(struct pfsync_upd_req) * g_recs &&
	    m->m_pkthdr.len == m->m_len,
	    "pfsync_sendout: length is the requests");
	__CPROVER_assert(ntohs(subh->count) == g_recs,
	    "pfsync_sendout: subheader counts the requests");
	m_freem(m);
	g_encap = 0;
}

void
model_mtx_enter(struct mutex *mtx)
{
	__CPROVER_assert(mtx->mtx_owner == 0, "mtx_enter: not held");
	mtx->mtx_owner = mtx_curcpu();
	/*
	 * The handler decided to allocate scrub memory without the mutex;
	 * before it gets st->mtx another CPU may attach its own.
	 */
	if (mtx == &g_st.mtx) {
		if (g_st.src.scrub == NULL && nondet_bool()) {
			g_st.src.scrub = CBMC_NEW(struct pf_state_scrub);
			g_base_scrubs++;
		}
		if (g_st.dst.scrub == NULL && nondet_bool()) {
			g_st.dst.scrub = CBMC_NEW(struct pf_state_scrub);
			g_base_scrubs++;
		}
	}
}

void
model_mtx_leave(struct mutex *mtx)
{
	__CPROVER_assert(mtx_owner(mtx) == mtx_curcpu(), "mtx_leave: held");
	mtx->mtx_owner = 0;
}

void
model_rw_enter_write(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_lock && !g_pf_locked, "rw_enter_write");
	g_pf_locked = 1;
}

void
model_rw_exit_write(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_lock && g_pf_locked, "rw_exit_write");
	g_pf_locked = 0;
}

void
model_rw_enter_read(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_state_lock, "rw_enter_read: lock");
	g_state_readers++;
}

void
model_rw_exit_read(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_state_lock && g_state_readers > 0,
	    "rw_exit_read: held");
	g_state_readers--;
}

int
model_rw_status(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_lock, "rw_status: lock");
	return (g_pf_locked ? RW_WRITE : 0);
}

void
model_splassert_fail(int wantipl, int haveipl, const char *func)
{
	__CPROVER_assert(0, "splassert_fail: lock assertion");
}

time_t
model_getuptime(void)
{
	return ((time_t)(nondet_ulong() & ((1UL << 40) - 1)));
}

/*
 * One object of the largest size (two messages of struct pfsync_state
 * plus 4 bytes each), of arbitrary content; the messages are placed at
 * its end, so a read past the last one is out of bounds.  A single
 * object keeps the field accesses cheap (an allocation per case made
 * the first runs 9 million variables).
 */
#define BUF_MAX		(2 * (sizeof(struct pfsync_state) + 4))
static caddr_t
buf_make(unsigned int total, caddr_t *base)
{
	u_char *p = (u_char *)MC_ALLOC(BUF_MAX);
	/* natively the runtime fills a harness allocation from the input */
	*base = (caddr_t)p;
	return ((caddr_t)p + (BUF_MAX - total));
}

#ifdef NATIVE_SHIM_H
/*
 * Natively only: the message bytes come from the end of the fuzzer's
 * input, which has to be 500 bytes long to fill them, and random bytes
 * rarely pass the handlers' range checks (timeout below 21, both peer
 * states at most 10).  Set the fields the handlers look at from the
 * front of the input, a few bytes, as a seed would; the rest of every
 * message stays the fuzzer's bytes.
 */
static void
bias_peer(struct pfsync_state_peer *p)
{
	p->state = nondet_uchar() % (PF_TCPS_PROXY_DST + 1);
	p->seqlo = nondet_uchar() & 1 ? nondet_uint() : 0;
	p->scrub.scrub_flag = nondet_bool() ? PFSYNC_SCRUB_FLAG_VALID :
	    nondet_uchar();
}

static void
bias_messages(caddr_t buf, int upd_c, unsigned int mlen, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (nondet_bool())
			continue;
		if (upd_c) {
			struct pfsync_upd_c *up =
			    (struct pfsync_upd_c *)(buf + mlen * i);

			up->timeout = nondet_uchar() % PFTM_MAX;
			bias_peer(&up->src);
			bias_peer(&up->dst);
		} else {
			struct pfsync_state *sp =
			    (struct pfsync_state *)(buf + mlen * i);

			sp->timeout = nondet_uchar() % PFTM_MAX;
			bias_peer(&sp->src);
			bias_peer(&sp->dst);
		}
	}
}
#endif

int
main(void)
{
	static struct pfsync_softc softc;
	struct pfsync_softc *sc = &softc;
	struct pf_state *st = &g_st;
	unsigned int mlen, count, nscrub = 0, t;
	int upd_c, big;
	caddr_t buf, base;

	g_base_scrubs = 0;

	/* g_st: a valid state the table holds one reference on */
	g_key.proto = nondet_bool() ? IPPROTO_TCP : nondet_uchar();
	g_key.af = AF_INET;
	st->key[PF_SK_WIRE] = &g_key;
	st->key[PF_SK_STACK] = &g_key;
	t = nondet_uchar() % (PFTM_MAX + 1);
	st->timeout = t == PFTM_MAX ? PFTM_UNLINKED : t;
	st->src.state = nondet_uchar() % (PF_TCPS_PROXY_DST + 1);
	st->dst.state = nondet_uchar() % (PF_TCPS_PROXY_DST + 1);
	st->src.seqlo = nondet_uint();
	st->dst.seqlo = nondet_uint();
	st->src.wscale = nondet_uchar();
	st->dst.wscale = nondet_uchar();
	if (nondet_bool()) {
		st->src.scrub = CBMC_NEW(struct pf_state_scrub);
		g_base_scrubs++;
	}
	if (nondet_bool()) {
		st->dst.scrub = CBMC_NEW(struct pf_state_scrub);
		g_base_scrubs++;
	}
	st->sync_defer = nondet_bool() ? &g_defer : NULL;
	st->sync_state = PFSYNC_S_NONE;
	st->pfsync_time = nondet_ulong() & ((1UL << 40) - 1);
	st->expire = nondet_ulong() & ((1UL << 40) - 1);
	g_refs = 1;
	g_scrubs = 0;
	g_pf_locked = 0;
	g_state_readers = 0;
	g_encap = 0;
	g_recs = 0;
	g_lead = 0;

	upd_c = nondet_bool();
	big = nondet_bool();
	count = nondet_bool() ? 1 : 2;
	mlen = (upd_c ? sizeof(struct pfsync_upd_c) :
	    sizeof(struct pfsync_state)) + (big ? 4 : 0);
	buf = buf_make(mlen * count, &base);
#ifdef NATIVE_SHIM_H
	bias_messages(buf, upd_c, mlen, count);
#endif

	if (upd_c)
		pfsync_in_upd_c(sc, buf, mlen, count);
	else
		pfsync_in_upd(sc, buf, mlen, count);

	check_state();
	__CPROVER_assert(g_refs == 1, "state references balanced");
	__CPROVER_assert(!g_pf_locked && g_state_readers == 0,
	    "locks balanced");
	__CPROVER_assert(mtx_owner(&st->mtx) == 0, "st->mtx released");
	if (st->src.scrub != NULL)
		nscrub++;
	if (st->dst.scrub != NULL)
		nscrub++;
	__CPROVER_assert(nscrub >= g_base_scrubs &&
	    g_scrubs == (int)(nscrub - g_base_scrubs),
	    "scrub objects attached or freed");

	/* tear down: what the state keeps, and the message buffer */
	if (st->src.scrub != NULL)
		mc_release(st->src.scrub);
	if (st->dst.scrub != NULL)
		mc_release(st->dst.scrub);
	mc_release(base);
	return (0);
}
