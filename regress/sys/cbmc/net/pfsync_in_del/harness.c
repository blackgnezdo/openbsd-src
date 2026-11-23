/*
 * Harness: the lookup-and-act handlers of sys/net/if_pfsync.c, called
 * through the pfsync_acts table as pfsync_input does: pfsync_in_iack
 * (INS_ACK), pfsync_in_ureq (UPD_REQ), pfsync_in_del (DEL),
 * pfsync_in_del_c (DEL_C) and pfsync_in_bus (BUS).  The action is
 * nondet among those five; the other table entries are replaced by
 * models that must not be reached.
 *
 * Framing (proven by net/pfsync_input): the handler gets buf readable
 * for mlen * count bytes, mlen a multiple of 4 and at least the size of
 * its message, count from the peer.  Here mlen is the message size or
 * the message size + 4 (a peer may send larger messages), count is 1 or
 * 2, and the buffer is one object of MAXBUF bytes, arbitrary content
 * (malloc-like, not zeroed), with the messages at its END: a read past
 * the last message is out of bounds of the object.
 *
 * State table: NSTATES = 2 states, each a zeroed object of its real
 * type with arbitrary id, creatorid (ids distinct), state_flags and
 * timeout, and, for each, an arbitrary deferral attached or not.
 * pf_find_state_byid returns the listed state whose key matches, or
 * NULL: the RBT_FIND result.  Ghost fields, per state k:
 *	listed[k]	the state is in the tree (the tree's reference)
 *	cnt[k]		references held: the tree (while listed), the
 *			handler (pf_state_ref), a deferral (sync_defer)
 * pf_state_ref asserts the state is live (cnt > 0), pf_state_unref
 * asserts a reference is held, pf_remove_state asserts PF_LOCK is held
 * and the state is listed, drops the tree's reference and unlists it,
 * pfsync_update_state_req asserts the state is listed (no use after
 * pf_remove_state), pfsync_deferred asserts a deferral is attached and
 * drops its reference (pfsync_defer_output does that in the kernel).
 * Locks are tracked: PF_LOCK (write) and pf_state_lock (read or write),
 * so PF_ASSERT_LOCKED and PF_STATE_ASSERT_LOCKED are checked by
 * model_rw_status; find asserts that the state lock is held.
 *
 * Models (replace file):
 *   pf_find_state_byid, pf_remove_state, pf_state_ref, pf_state_unref,
 *   pfsync_update_state_req, pfsync_deferred, pfsync_bulk_snd_start,
 *   pfsync_bulk_req_evt, rw_enter_*, rw_exit_*, rw_status, mtx_enter,
 *   mtx_leave.  The five table entries not chosen are replaced by
 *   models that assert they are never called.
 * Not modelled, no body (NOBODY line): counters_inc, counters_pkt
 * (statistics only).
 *
 * Properties: no out-of-bounds access in the message buffer, no use of a
 * state after its last reference is dropped or after pf_remove_state, no
 * double unref, the locks each step needs are held, and at the end every
 * reference taken is dropped or held by the tree or an attached
 * deferral (cnt[k] == listed[k] + attached[k]).
 */
#include "cbmc_harness.h"

#include "if_pfsync.c"

#define NSTATES		2
#define MAXMSG		(sizeof(struct pfsync_state) + 4)
#define MAXBUF		(2 * MAXMSG)

static struct pf_state		*tab[NSTATES];
static struct pfsync_deferral	*defer[NSTATES];
static unsigned int		 listed[NSTATES];
static unsigned int		 cnt[NSTATES];
static int			 g_pf_lock;	/* PF_LOCK, write */
static int			 g_state_lock;	/* 1 read, 2 write */

static unsigned int
state_index(const struct pf_state *st)
{
	unsigned int k;

	for (k = 0; k < NSTATES; k++) {
		if (tab[k] == st)
			return (k);
	}
	__CPROVER_assert(0, "state: a state of the table");
	return (0);
}

/* pf_find_state_byid: RBT_FIND on the key; takes no reference */
struct pf_state *
model_find_state_byid(struct pf_state_cmp *key)
{
	unsigned int k;

	__CPROVER_assert(g_state_lock != 0, "find: PF_STATE lock held");
	for (k = 0; k < NSTATES; k++) {
		if (listed[k] && tab[k]->id == key->id &&
		    tab[k]->creatorid == key->creatorid)
			return (tab[k]);
	}
	return (NULL);
}

/* pf_remove_state: unlink, drop the tree's reference */
void
model_remove_state(struct pf_state *st)
{
	unsigned int k = state_index(st);

	__CPROVER_assert(g_pf_lock, "remove: PF_LOCK held");
	__CPROVER_assert(listed[k], "remove: state listed");
	__CPROVER_assert(cnt[k] > 0, "remove: state live");
	listed[k] = 0;
	cnt[k]--;
}

struct pf_state *
model_state_ref(struct pf_state *st)
{
	unsigned int k;

	if (st != NULL) {
		k = state_index(st);
		__CPROVER_assert(cnt[k] > 0, "ref: state live");
		cnt[k]++;
	}
	return (st);
}

void
model_state_unref(struct pf_state *st)
{
	unsigned int k;

	if (st != NULL) {
		k = state_index(st);
		__CPROVER_assert(cnt[k] > 0, "unref: reference held");
		cnt[k]--;
	}
}

void
model_update_state_req(struct pfsync_softc *sc, struct pf_state *st)
{
	__CPROVER_assert(sc == pfsyncif, "update_state_req: softc");
	__CPROVER_assert(st != NULL, "update_state_req: a state");
	__CPROVER_assert(listed[state_index(st)],
	    "update_state_req: state not removed");
}

void
model_deferred(struct pfsync_softc *sc, struct pf_state *st)
{
	unsigned int k;

	__CPROVER_assert(sc == pfsyncif, "deferred: softc");
	__CPROVER_assert(st != NULL, "deferred: a state");
	k = state_index(st);
	__CPROVER_assert(st->sync_defer != NULL, "deferred: deferral attached");
	/* the deferral's reference, released by pfsync_defer_output */
	st->sync_defer = NULL;
	cnt[k]--;
}

void
model_bulk_snd_start(struct pfsync_softc *sc)
{
	__CPROVER_assert(sc == pfsyncif, "bulk_snd_start: softc");
}

void
model_bulk_req_evt(struct pfsync_softc *sc, enum pfsync_bulk_req_event evt)
{
	__CPROVER_assert(sc == pfsyncif, "bulk_req_evt: softc");
	__CPROVER_assert(evt == PFSYNC_BREQ_EVT_BUS_START ||
	    evt == PFSYNC_BREQ_EVT_BUS_END, "bulk_req_evt: bus event");
}

/* locks: single thread; PF_LOCK and pf_state_lock are tracked */
void
model_rw_enter_write(struct rwlock *rwl)
{
	if (rwl == &pf_lock) {
		__CPROVER_assert(!g_pf_lock, "PF_LOCK: not held");
		g_pf_lock = 1;
	} else {
		__CPROVER_assert(g_state_lock == 0, "pf_state_lock: not held");
		g_state_lock = 2;
	}
}

void
model_rw_exit_write(struct rwlock *rwl)
{
	if (rwl == &pf_lock) {
		__CPROVER_assert(g_pf_lock, "PF_LOCK: held");
		g_pf_lock = 0;
	} else {
		__CPROVER_assert(g_state_lock == 2, "pf_state_lock: write held");
		g_state_lock = 0;
	}
}

void
model_rw_enter_read(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_state_lock, "rw_enter_read: pf_state_lock");
	__CPROVER_assert(g_state_lock == 0, "pf_state_lock: not held");
	g_state_lock = 1;
}

void
model_rw_exit_read(struct rwlock *rwl)
{
	__CPROVER_assert(rwl == &pf_state_lock, "rw_exit_read: pf_state_lock");
	__CPROVER_assert(g_state_lock == 1, "pf_state_lock: read held");
	g_state_lock = 0;
}

int
model_rw_status(struct rwlock *rwl)
{
	if (rwl == &pf_lock)
		return (g_pf_lock ? RW_WRITE : 0);
	if (g_state_lock == 2)
		return (RW_WRITE);
	if (g_state_lock == 1)
		return (RW_READ);
	return (0);
}

void
model_mtx_enter(struct mutex *mtx)
{
}

void
model_mtx_leave(struct mutex *mtx)
{
}

/* CBMC's free for the objects made here (kernel free(9) is kfree here) */
#undef free
void free(void *);

/* table entries this harness never selects */
#define MODEL_UNUSED(name)						\
void									\
model_unused_##name(struct pfsync_softc *sc, const caddr_t buf,		\
    unsigned int mlen, unsigned int count)				\
{									\
	__CPROVER_assert(0, "action: not one of the five handlers");	\
}

MODEL_UNUSED(clr)
MODEL_UNUSED(upd_c)
MODEL_UNUSED(ins)
MODEL_UNUSED(upd)
MODEL_UNUSED(tdb)

int
main(void)
{
	static struct pfsync_softc softc;
	struct pfsync_softc *sc = &softc;
	unsigned char *obj;
	caddr_t buf;
	unsigned int a, action, mlen, count, k;

	pfsyncif = sc;
	g_pf_lock = 0;
	g_state_lock = 0;

	/* the state table, as the tree holds it: each state listed */
	for (k = 0; k < NSTATES; k++) {
		tab[k] = CBMC_NEW(struct pf_state);
		defer[k] = CBMC_NEW(struct pfsync_deferral);
		listed[k] = 1;
		cnt[k] = 1;
		tab[k]->state_flags = nondet_uint();
		tab[k]->timeout = nondet_uint();
		tab[k]->creatorid = nondet_uint();
		if (nondet_bool()) {
			tab[k]->sync_defer = defer[k];
			cnt[k]++;
		}
	}
	tab[0]->id = nondet_u64();
	tab[1]->id = tab[0]->id ^ 1;	/* distinct keys */

	/* the handler, chosen as the table index is in pfsync_input */
	a = nondet_uint() % 5;
	switch (a) {
	case 0:
		action = PFSYNC_ACT_INS_ACK;
		break;
	case 1:
		action = PFSYNC_ACT_UPD_REQ;
		break;
	case 2:
		action = PFSYNC_ACT_DEL;
		break;
	case 3:
		action = PFSYNC_ACT_DEL_C;
		break;
	default:
		action = PFSYNC_ACT_BUS;
		break;
	}

	/* mlen: the message size or 4 more; count 1 or 2 */
	mlen = pfsync_acts[action].len + (nondet_bool() ? 4 : 0);
	count = 1 + nondet_bool();
	__CPROVER_assert(mlen * count <= MAXBUF, "harness: message fits");

	/* one object of MAXBUF bytes, arbitrary content; messages at its end */
	obj = __CPROVER_allocate(MAXBUF, 0);
	CBMC_LEAK_RECORD_(obj);
	buf = (caddr_t)(obj + MAXBUF - mlen * count);

	pfsync_acts[action].in(sc, buf, mlen, count);

	__CPROVER_assert(g_pf_lock == 0 && g_state_lock == 0,
	    "locks released");
	for (k = 0; k < NSTATES; k++) {
		__CPROVER_assert(cnt[k] == listed[k] +
		    (tab[k]->sync_defer != NULL),
		    "references balanced");
	}

	free(obj);
	for (k = 0; k < NSTATES; k++) {
		free(tab[k]);
		free(defer[k]);
	}
	return (0);
}
