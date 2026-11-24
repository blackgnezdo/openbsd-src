/*
 * Harness: pfsync_in_ins() of sys/net/if_pfsync.c (static, so the file is
 * #included) and pf_state_import() of sys/net/pf.c below it, for
 * PFSYNC_SI_PFSYNC: the validation of one or two peer messages and the
 * import of each into a pf_state with its state keys.
 *
 * Caller guarantees (net/pfsync_input, pfsync_input() if_pfsync.c
 * 2687-2740): in(sc, buf, mlen, count) with buf readable for mlen * count
 * contiguous bytes, mlen a multiple of 4 and at least
 * sizeof(struct pfsync_state), count from the peer.  Messages are at
 * buf + i * mlen; every byte is the peer's.
 *
 * Sizes, from a compile of the headers (struct pfsync_state 264 bytes:
 * ifname at 8 (16 bytes), key[2] at 24 (40 bytes each), src at 104, dst
 * at 136, rule at 184, creatorid at 236, af at 250, direction at 252,
 * timeout at 255; PFTM_MAX 20; PF_TCPS_PROXY_DST 12; PFSYNC_SI_PFSYNC 8):
 * the buffer is an object of mlen * count bytes with arbitrary content,
 * mlen 264 (count 1 or 2) or 268 (count 2: a peer may send larger
 * messages; the four bytes are never read), and the unterminated case
 * below (264, 1).  The data ends where the object
 * ends, so a read past the last message is out of bounds.  The object
 * is made per case, with a constant size (run_case is called at four
 * sites), so every access to the message is at a constant offset.
 *
 * Harness state, set once:
 *   pf_default_rule	arbitrary max_states, states_cur (below 2^24) and
 *			timeout[]; with flags == PFSYNC_SI_PFSYNC the rule
 *			lookup of pf_state_import is not entered
 *			(pf.c 1738: it needs PFSYNC_SI_IOCTL or
 *			PFSYNC_SI_CKSUM), r is always &pf_default_rule.
 *   kif tree		model_kif_find/insert: a list of at most 3 kifs,
 *			optionally seeded with one named "x"; find returns
 *			NULL or any listed kif, insert lists the kif.  The
 *			real pfi_kif_get, pfi_kif_find (with the real
 *			strlcpy of the peer's ifname), pfi_kif_alloc,
 *			pfi_kif_ref and pfi_kif_unref run.
 *   locks		pf_lock and pf_state_lock: rw_enter_write,
 *			rw_exit_write and rw_status track the owner, and
 *			splassert_fail is an assertion failure, so
 *			PF_ASSERT_LOCKED is checked, not ignored.
 *   refcnt_*		count r_refs; refcnt_rele returns 1 at zero.
 *
 * Models:
 *   pool_get	pf_state_pl, pf_state_key_pl and pf_state_scrub_pl give
 *		typed zeroed items (PR_ZERO is always set on this path) and
 *		may fail (PR_NOWAIT | PR_LIMITFAIL); outstanding items are
 *		counted per pool.  pool_put is CBMC's free.
 *   pf_state_insert	asserts what the handler's validation promises
 *		about the state and its keys (timeout < PFTM_MAX, peer states
 *		<= PF_TCPS_PROXY_DST, direction <= PF_OUT, both keys AF_INET
 *		or AF_INET6, key reference counts, creatorid != 0, the rule,
 *		the lock), then either fails (it releases both key
 *		references, as pf.c 1331-1347 does, and the caller frees the
 *		state) or takes the state and the keys and a kif state
 *		reference (pfi_kif_ref); the harness releases them in the
 *		teardown.
 *   pf_pkt_hash	arbitrary result (the toeplitz table is not the
 *		subject).
 *   getuptime	arbitrary below 2^40.
 *   Not modelled, no body (NOBODY line): counters_inc, counters_pkt
 *		(statistics), gettime (pfik_tzero), mtx_init_flags,
 *		log and addlog (DPFPRINTF: the arguments are not read).
 *
 * The real pf_state_import, pf_alloc_state_key,
 * pf_state_alloc_scrub_memory, pf_normalize_tcp_alloc,
 * pf_state_peer_ntoh, pf_state_key_ref/unref and pfsync_init_state run.
 *
 * Properties: no out-of-bounds access (also past the last message: a
 * read of the unterminated ifname by strlcpy is the case); pool items,
 * key references, scrub buffers, kifs and the buffer all released; the
 * rule's states_cur and states_tot grow by exactly the number of states
 * inserted; every kif state reference taken is dropped in the teardown
 * and no other kif count changed; the locks are released; every index
 * from the message (timeout, peer states, direction) is in range where
 * it is used.
 */
#include "cbmc_harness.h"
#include "if_pfsync.c"

extern struct pool		 pf_state_pl, pf_state_key_pl;
extern struct pool		 pf_state_scrub_pl;
struct rwlock			 pf_lock, pf_state_lock;
struct pf_rule			 pf_default_rule;

#define MSZ	sizeof(struct pfsync_state)

/* kernel free(9) is kfree here; CBMC's free for the objects made below */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

/* ---- locks ---- */
static int g_lock, g_slock;

void
model_rw_enter_write(struct rwlock *rwl)
{
	if (rwl == &pf_lock) {
		__CPROVER_assert(g_lock == 0, "lock: pf_lock not held");
		g_lock = 1;
	} else if (rwl == &pf_state_lock) {
		__CPROVER_assert(g_slock == 0, "lock: pf_state_lock not held");
		g_slock = 1;
	}
}

void
model_rw_exit_write(struct rwlock *rwl)
{
	if (rwl == &pf_lock) {
		__CPROVER_assert(g_lock == 1, "lock: pf_lock held");
		g_lock = 0;
	} else if (rwl == &pf_state_lock) {
		__CPROVER_assert(g_slock == 1, "lock: pf_state_lock held");
		g_slock = 0;
	}
}

int
model_rw_status(const struct rwlock *rwl)
{
	if (rwl == &pf_lock)
		return (g_lock ? RW_WRITE : 0);
	if (rwl == &pf_state_lock)
		return (g_slock ? RW_WRITE : 0);
	return (0);
}

void
model_splassert_fail(int wantipl, int curipl, const char *func)
{
	__CPROVER_assert(0, "lock: assertion failed (splassert_fail)");
}

/* ---- reference counts ---- */
void
model_refcnt_init(struct refcnt *r)
{
	r->r_refs = 1;
}

void
model_refcnt_take(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs > 0, "refcnt_take: reference held");
	r->r_refs++;
}

int
model_refcnt_rele(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs > 0, "refcnt_rele: reference held");
	r->r_refs--;
	return (r->r_refs == 0);
}

/* ---- time ---- */
time_t
model_getuptime(void)
{
	return ((time_t)(nondet_u64() & 0xffffffffffULL));	/* < 2^40 */
}

/* ---- pools ---- */
static int g_n_state, g_n_key, g_n_scrub;	/* outstanding items */

void *
model_pool_get(struct pool *pp, int flags)
{
	__CPROVER_assert(flags & PR_ZERO, "pool_get: PR_ZERO");
	if (pp == &pf_state_pl) {
		if (nondet_bool())
			return (NULL);
		g_n_state++;
		return (CBMC_NEW(struct pf_state));
	}
	if (pp == &pf_state_key_pl) {
		if (nondet_bool())
			return (NULL);
		g_n_key++;
		return (CBMC_NEW(struct pf_state_key));
	}
	if (pp == &pf_state_scrub_pl) {
		if (nondet_bool())
			return (NULL);
		g_n_scrub++;
		return (CBMC_NEW(struct pf_state_scrub));
	}
	__CPROVER_assert(0, "pool_get: unexpected pool");
	return (NULL);
}

void
model_pool_put(struct pool *pp, void *v)
{
	__CPROVER_assert(v != NULL, "pool_put: item");
	if (pp == &pf_state_pl)
		g_n_state--;
	else if (pp == &pf_state_key_pl)
		g_n_key--;
	else if (pp == &pf_state_scrub_pl)
		g_n_scrub--;
	else
		__CPROVER_assert(0, "pool_put: unexpected pool");
	harness_release(v);
}

/* pf_pkt_hash: the result is not the subject */
u_int16_t
model_pkt_hash(sa_family_t af, uint8_t proto, const struct pf_addr *src,
    const struct pf_addr *dst, uint16_t sport, uint16_t dport)
{
	return (nondet_u16());
}

/* ---- kif tree: RB_FIND / RB_INSERT of pfi_ifs ---- */
static struct pfi_kif *g_tree[3];
static int g_ntree;

struct pfi_kif *
model_kif_find(struct pfi_ifhead *head, struct pfi_kif *key)
{
	if (g_ntree == 0 || nondet_bool())
		return (NULL);
	return (g_tree[nondet_uint() % g_ntree]);
}

struct pfi_kif *
model_kif_insert(struct pfi_ifhead *head, struct pfi_kif *kif)
{
	__CPROVER_assert(kif != NULL && g_ntree < 3, "kif tree: insert");
	g_tree[g_ntree++] = kif;
	return (NULL);
}

/* pfi_kif_unref() removes the kif from the tree before it frees it (pf_if.c 273) */
struct pfi_kif *
model_kif_remove(struct pfi_ifhead *head, struct pfi_kif *kif)
{
	int i, j;

	for (i = 0; i < g_ntree; i++)
		if (g_tree[i] == kif)
			break;
	__CPROVER_assert(i < g_ntree, "kif tree: removed kif is on the tree");
	for (j = i; j + 1 < g_ntree; j++)
		g_tree[j] = g_tree[j + 1];
	g_ntree--;
	return (kif);
}

/*
 * pfi_kif_alloc (pf_if.c 92-112) with a typed object: the real one takes
 * malloc(9)'s untyped bytes, which cost a byte-wise encoding once a
 * pointer may refer to one of several kifs.  Same statements: M_NOWAIT
 * may fail, strlcpy of the name (the real one, the peer's ifname), the
 * dynaddrs list, the "any" flag.
 */
struct pfi_kif *
model_kif_alloc(const char *kif_name, int mflags)
{
	struct pfi_kif *kif;

	if ((mflags & M_NOWAIT) && nondet_bool())
		return (NULL);
	kif = CBMC_NEW(struct pfi_kif);
	strlcpy(kif->pfik_name, kif_name, sizeof(kif->pfik_name));
	TAILQ_INIT(&kif->pfik_dynaddrs);
	if (!strcmp(kif->pfik_name, "any")) {
		kif->pfik_flags |= PFI_IFLAG_ANY;
		kif->pfik_flags_new |= PFI_IFLAG_ANY;
	}
	return (kif);
}

/* ---- pf_state_insert ---- */
static struct pf_state *g_ins[2];
static int g_nins;

int
model_state_insert(struct pfi_kif *kif, struct pf_state_key **skwp,
    struct pf_state_key **sksp, struct pf_state *st)
{
	struct pf_state_key *skw = *skwp, *sks = *sksp;

	__CPROVER_assert(g_lock == 1, "pf_state_insert: pf_lock held");
	__CPROVER_assert(kif != NULL && st != NULL && skw != NULL &&
	    sks != NULL, "pf_state_insert: arguments");
	__CPROVER_assert(skw->af == AF_INET || skw->af == AF_INET6,
	    "pf_state_insert: wire key family");
	__CPROVER_assert(sks->af == AF_INET || sks->af == AF_INET6,
	    "pf_state_insert: stack key family");
	__CPROVER_assert(st->timeout < PFTM_MAX,
	    "pf_state_insert: timeout index");
	__CPROVER_assert(st->src.state <= PF_TCPS_PROXY_DST &&
	    st->dst.state <= PF_TCPS_PROXY_DST,
	    "pf_state_insert: peer state index");
	__CPROVER_assert(st->direction <= PF_OUT,
	    "pf_state_insert: direction");
	__CPROVER_assert(st->creatorid != 0, "pf_state_insert: creatorid");
	__CPROVER_assert(st->rule.ptr == &pf_default_rule,
	    "pf_state_insert: rule");
	if (skw == sks)
		__CPROVER_assert(skw->sk_refcnt.r_refs == 2,
		    "pf_state_insert: shared key has two references");
	else
		__CPROVER_assert(skw->sk_refcnt.r_refs == 1 &&
		    sks->sk_refcnt.r_refs == 1,
		    "pf_state_insert: keys have one reference each");

	if (nondet_bool()) {
		/* pf.c 1329-1350: the keys are released, the state is the
		 * caller's */
		pf_state_key_unref(skw);
		pf_state_key_unref(sks);
		return (-1);
	}
	st->kif = kif;
	st->key[PF_SK_WIRE] = skw;
	st->key[PF_SK_STACK] = sks;
	pfi_kif_ref(kif, PFI_KIF_REF_STATE);
	__CPROVER_assert(g_nins < 2, "pf_state_insert: at most two states");
	g_ins[g_nins++] = st;
	return (0);
}

/*
 * One case: a message buffer of mlen * count bytes, arbitrary content,
 * the data ending where the object ends.
 *
 * term != 0: the ifname of every message is the constant "x" (README,
 * "When a run exhausts time or memory", 4: a symbolic byte in the name
 * costs the byte-loop strlcpy a symbolic copy of ifname and, with the
 * copy loop's exits merged, an unwinding of its rest-of-src loop over
 * the whole message once per copy: 14 copies were out of memory in the
 * cover run).  The kif only holds the first 15 bytes of a name, a NUL
 * between ifname and the end of the message ends the read inside the
 * buffer, and the name decides nothing else (the kif tree is a model),
 * so one terminated name stands for them.  Everything else in the
 * message is arbitrary.
 * term == 0: the peer sends no NUL byte at all (every byte is 2, a valid
 * message: sp->af, key af, timeout, states, direction and creatorid all
 * pass the validation): strlcpy() of pfi_kif_find() reads ifname and
 * on, up to a NUL that is not there.
 */
static struct pfsync_softc g_softc;

static void
run_case(unsigned int mlen, unsigned int count, int term)
{
	char *buf = __CPROVER_allocate(mlen * count, 0);
	unsigned int i;

	CBMC_LEAK_RECORD_(buf);
#ifdef NATIVE_SHIM_H
	__CPROVER_havoc_slice(buf, mlen * count);
#endif
	if (term) {
		for (i = 0; i < count; i++) {
			char *name = buf + mlen * i +
			    offsetof(struct pfsync_state, ifname);

			memset(name, 0, IFNAMSIZ);
			name[0] = 'x';
		}
	} else {
		memset(buf, 2, mlen * count);
	}
	pfsync_in_ins(&g_softc, buf, mlen, count);
	harness_release(buf);
}

int
main(void)
{
	unsigned int sel, i;
	unsigned int cur0, tot0;
	struct pfi_kif *k;

	pf_state_pl.pr_size = sizeof(struct pf_state);
	pf_state_key_pl.pr_size = sizeof(struct pf_state_key);
	pf_state_scrub_pl.pr_size = sizeof(struct pf_state_scrub);

	/* the rule every state is imported against */
	pf_default_rule.max_states = nondet_u32();
	pf_default_rule.states_cur = nondet_u32() & 0xffffff;
	pf_default_rule.states_tot = nondet_u32() & 0xffffff;
	for (i = 0; i < PFTM_MAX; i++)
		pf_default_rule.timeout[i] = nondet_u32();
	cur0 = pf_default_rule.states_cur;
	tot0 = pf_default_rule.states_tot;

	/* a kif "x" may be on the tree already */
	if (nondet_bool()) {
		k = model_kif_alloc("x", M_WAITOK);
		g_tree[g_ntree++] = k;
	}

	sel = nondet_uint() & 3;
	if (sel == 0)
		run_case(MSZ, 1, 1);
	else if (sel == 1)
		run_case(MSZ, 2, 1);
	else if (sel == 2)
		run_case(MSZ + 4, 2, 1);
	else
		run_case(MSZ, 1, 0);

	__CPROVER_assert(g_lock == 0 && g_slock == 0, "locks released");
	__CPROVER_assert(pf_default_rule.states_cur == cur0 + g_nins &&
	    pf_default_rule.states_tot >= tot0 &&
	    pf_default_rule.states_tot - tot0 >= g_nins,
	    "rule: states_cur grew by the number of states inserted");

	/* teardown: pf_remove_state of what the model took; the last
	 * pfi_kif_unref of a kif frees it and takes it off the tree */
	PF_LOCK();
	for (i = 0; i < g_nins; i++) {
		struct pf_state *st = g_ins[i];

		pf_default_rule.states_cur--;
		pfi_kif_unref(st->kif, PFI_KIF_REF_STATE);
		pf_state_key_unref(st->key[PF_SK_WIRE]);
		pf_state_key_unref(st->key[PF_SK_STACK]);
		if (st->dst.scrub)
			pool_put(&pf_state_scrub_pl, st->dst.scrub);
		if (st->src.scrub)
			pool_put(&pf_state_scrub_pl, st->src.scrub);
		pool_put(&pf_state_pl, st);
	}
	__CPROVER_assert(pf_default_rule.states_cur == cur0,
	    "rule: states_cur restored");
	__CPROVER_assert(g_n_state == 0 && g_n_key == 0 && g_n_scrub == 0,
	    "pool items all released");

	/* kif references: what is left on the tree (a kif pfi_kif_get made
	 * and no state took, or the seeded one) holds no reference */
	while (g_ntree > 0) {
		k = g_tree[g_ntree - 1];
		__CPROVER_assert(k->pfik_states == 0 && k->pfik_rules == 0 &&
		    k->pfik_routes == 0 && k->pfik_srcnodes == 0 &&
		    k->pfik_flagrefs == 0, "kif references balanced");
		g_ntree--;
		pfi_kif_free(k);
	}
	PF_UNLOCK();
	return (0);
}
