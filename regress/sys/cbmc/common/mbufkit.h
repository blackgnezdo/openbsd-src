/*
 * mbufkit: the real mbuf library (kern/uipc_mbuf.c, kern/uipc_mbuf2.c)
 * on a typed pool(9) model, plus a packet builder, a chain checker and
 * byte probes for harnesses.  See README, "mbuf kit" and "Writing a
 * packet parser target".
 *
 *	#define MAXLEN 40		(the harness's packet bound)
 *	#define MBUFKIT_MAXLEN MAXLEN
 *	#define MBUFKIT_MEMTRACK 1	(with stubflags -DMEMCPY_TRACK)
 *	#include "mbufkit.h"
 *
 *	mbufkit_init();			first thing in main(): runs mbinit()
 *	m = mbufkit_build(mbufkit_upto(MAXLEN), MBUFKIT_ANY);
 *	mbufkit_track(&b, m);		follow one arbitrary byte
 *	... code under test ...
 *	mbufkit_check(m);		chain well formed (asserts)
 *	assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)))	byte in place
 *	mbufkit_free(m);		m_freem(), for --memory-leak-check
 *
 * Target files (copy them from net/mbuf_example_parser):
 *	sources		kern/uipc_mbuf.c, kern/uipc_mbuf2.c
 *	keep		the list there, plus the mbuf functions on the path
 *	replace		pool_get:mbufkit_pool_get
 *			pool_put:mbufkit_pool_put
 *	config		pf.h NPF 0
 *	fptargets	m_extfree.function_pointer_call.1/m_extfree_pool
 *			(add m_extfree_refs and
 *			m_extfree_refs.function_pointer_call.1/m_extfree_pool
 *			where clusters are shared: m_split, m_copym)
 *	stubflags	-DMEMCPY_TRACK
 *	opts		--unwind 5 (more than MBUFKIT_MAXCHAIN), the
 *			--unwindset lines there, --memory-leak-check
 *
 * Everything here is defined in this header, so it is part of harness.c:
 * both engines keep the bodies without keep entries.  Include it only
 * from harness.c.
 *
 * Model decisions (what is and is not real)
 *  - m_get, m_gethdr, m_clget, m_free, m_freem, m_extfree, m_extref,
 *    mbinit, ... are the kernel's.  Below them pool_get is
 *    mbufkit_pool_get (replace file): an mbuf is a typed struct mbuf, a
 *    cluster a byte array of the pool's item size, an m_ext_refs a typed
 *    mirror of uipc_mbuf.c's private struct.  Untyped mbufs make the
 *    formula explode (README, "Adding a target", step 3).  Clusters
 *    have arbitrary content; mbufs and m_ext_refs are zeroed (see
 *    mbufkit_pool_get).
 *  - PR_NOWAIT (M_DONTWAIT) allocations may fail; set
 *    mbufkit_nofail = 1 to switch that off.  The builder uses M_WAIT.
 *  - pool_init (only reached from mbinit) records the item size;
 *    refcnt_* are single-threaded models with the KASSERTs of
 *    kern_synch.c.  nmbclust is defined here as conf/param.c does.
 *  - no tags are ever attached, pf is configured out (NPF 0), no
 *    M_ZEROIZE.
 *  - pool_put is mbufkit_pool_put (replace file): CBMC's free.
 *  - native.sh: the replaces of pool_get and pool_put do not reach
 *    common/stubs_pool.c (a model module), so natively mbufs come from
 *    the common pool model (malloc of pr_size, content: ASan's fill
 *    byte).  Same semantics; natively the type does not matter.
 *  - every allocation here is visible to --memory-leak-check
 *    (MBUFKIT_ALLOC, cbmc_harness.h).
 */
#ifndef MBUFKIT_H
#define MBUFKIT_H

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/refcnt.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>		/* MCLPOOLS */

#include "cbmc_harness.h"

/*
 * Bounds.  MBUFKIT_MAXSEG: most mbufs the builder puts in a chain.
 * MBUFKIT_MAXCHAIN: longest chain the checker and the probes walk; code
 * under test may add mbufs (m_pullup, m_pulldown, m_split, m_copyback
 * add at most one or two each), a longer chain is reported.  Every loop
 * of the kit runs at most MBUFKIT_MAXCHAIN + 1 times, so --unwind
 * MBUFKIT_MAXCHAIN + 1 covers them.
 */
#ifndef MBUFKIT_MAXSEG
#define MBUFKIT_MAXSEG		2
#endif
/*
 * MBUFKIT_MAXLEN: largest len the harness passes to mbufkit_build (at
 * most MCLBYTES).  Only used to rule out, at compile time, the forced
 * cluster for a segment that does not fit its mbuf, so that a harness
 * with short packets and MBUFKIT_PLAIN has no cluster objects at all.
 */
#ifndef MBUFKIT_MAXLEN
#define MBUFKIT_MAXLEN		MCLBYTES
#endif
#ifndef MBUFKIT_MAXCHAIN
#define MBUFKIT_MAXCHAIN	(MBUFKIT_MAXSEG + 2)
#endif

/*
 * MBUFKIT_REFS: 1 if the code under test shares clusters (m_extref:
 * m_copym, m_split of a cluster).  0 (default) keeps the reference
 * counting path out of every m_free; a shared cluster is then reported.
 */
#ifndef MBUFKIT_REFS
#define MBUFKIT_REFS		0
#endif

/* mbufkit_build() flags */
#define MBUFKIT_CLUSTER	0x01	/* a segment may be a 2k cluster */
#define MBUFKIT_RDONLY	0x02	/* a cluster may be read-only (M_EXTWR clear,
				   as for a loaned or shared cluster) */
#define MBUFKIT_ANY	(MBUFKIT_CLUSTER | MBUFKIT_RDONLY)
#define MBUFKIT_PLAIN	0	/* only mbufs with internal storage (except
				   where a segment would not fit) */

extern struct pool mbpool;
extern struct pool mtagpool;
extern struct pool mclpools[MCLPOOLS];
extern u_int m_extfree_refs_fn;
extern u_int mclsizes[MCLPOOLS];
void mbinit(void);
void m_extfree_pool(caddr_t, u_int, void *);

/*
 * Engine-specific primitives.  native.sh force-includes native/shim.h,
 * which defines NATIVE_SHIM_H; CBMC has no pointer-to-object query
 * natively, plain address arithmetic serves there.
 */
#ifdef NATIVE_SHIM_H
#define MBUFKIT_SAME_OBJECT(p, q)	1
#define MBUFKIT_DIFF(p, q)	((long)((unsigned long)(p) - (unsigned long)(q)))
#else
#define MBUFKIT_SAME_OBJECT(p, q)	__CPROVER_same_object((p), (q))
#define MBUFKIT_DIFF(p, q)	\
	((long)__CPROVER_POINTER_OFFSET(p) - (long)__CPROVER_POINTER_OFFSET(q))
#endif

/* ---- models below the mbuf code ---- */

/* conf/param.c */
long nmbclust = NMBCLUSTERS;

/* uipc_mbuf.c's private struct m_ext_refs, same layout (checked in
 * pool_init against the size mbinit asks for) */
struct mbufkit_ext_refs {
	void		*arg;
	u_int		 free_fn;
	u_int		 zero;
	struct refcnt	 refs;
};

/* __CPROVER_allocate, visible to --memory-leak-check (cbmc_harness.h) */
#define MBUFKIT_ALLOC(size, zero) ({					\
	void *mbufkit_p_ = __CPROVER_allocate((size), (zero));		\
	CBMC_LEAK_RECORD_(mbufkit_p_);					\
	mbufkit_p_;							\
})

int mbufkit_nofail;		/* 1: PR_NOWAIT allocations never fail */
int mbufkit_nfail;		/* PR_NOWAIT allocations that failed */
static int mbufkit_in_mbinit;
static struct pool *mbufkit_refs_pool;	/* uipc_mbuf.c's m_ext_refs_pool */
static int mbufkit_pool_get_used;

static int
mbufkit_is_clpool(struct pool *pp)
{
	return (MBUFKIT_SAME_OBJECT(pp, mclpools) &&
	    MBUFKIT_DIFF(pp, mclpools) >= 0 &&
	    MBUFKIT_DIFF(pp, mclpools) < (long)sizeof(mclpools));
}

void
pool_init(struct pool *pp, size_t size, u_int align, int ipl, int flags,
    const char *wchan, struct pool_allocator *palloc)
{
	pp->pr_size = size;
	if (mbufkit_in_mbinit && pp != &mbpool && pp != &mtagpool &&
	    !mbufkit_is_clpool(pp)) {
		/* the only other pool mbinit creates */
		__CPROVER_assert(size == sizeof(struct mbufkit_ext_refs),
		    "mbufkit: struct m_ext_refs changed, update the mirror");
		mbufkit_refs_pool = pp;
	}
}

/* replace: pool_get:mbufkit_pool_get */
void *
mbufkit_pool_get(struct pool *pp, int flags)
{
	_Bool zero = (flags & PR_ZERO) != 0;

	mbufkit_pool_get_used = 1;
	if ((flags & PR_NOWAIT) && !mbufkit_nofail && nondet_bool()) {
		mbufkit_nfail++;
		return (NULL);
	}
	/* (__CPROVER_allocate takes a constant for zero) */
	/*
	 * mbufs and m_ext_refs are zeroed, unlike real pool items: with
	 * arbitrary content their pointer fields (m_ext.ext_arg, ...)
	 * point anywhere on paths symex cannot rule out, and every store
	 * through them touches every object (m_split ran out of memory).
	 * Reads of fields the code never set therefore see 0, not garbage;
	 * the native build (ASan fill, NATIVE_SAN=msan) covers those.
	 */
	if (pp == &mbpool)
		return (MBUFKIT_ALLOC(sizeof(struct mbuf), 1));
	if (pp == mbufkit_refs_pool && pp != NULL)
		return (MBUFKIT_ALLOC(sizeof(struct mbufkit_ext_refs), 1));
	/* clusters (byte arrays) and any other pool */
	return (zero ? MBUFKIT_ALLOC(pp->pr_size, 1) :
	    MBUFKIT_ALLOC(pp->pr_size, 0));
}

/*
 * replace: pool_put:mbufkit_pool_put.  Frees with CBMC's own free:
 * the common pool model goes through the free(9) model, whose size
 * check is pointless for pool items (pr_size is the item size by
 * construction) and costs solver time on every m_free.
 */
#undef free
void free(void *);

void
mbufkit_pool_put(struct pool *pp, void *v)
{
	__CPROVER_assert(v != NULL, "pool_put: NULL item");
	free(v);
}

#define free kfree	/* as -Dfree=kfree on the command line */

/* kern_synch.c, single-threaded */
void
refcnt_init(struct refcnt *r)
{
	r->r_traceidx = 0;
	r->r_refs = 1;
}

void
refcnt_take(struct refcnt *r)
{
	r->r_refs++;
	KASSERT(r->r_refs > 1);
}

int
refcnt_rele(struct refcnt *r)
{
	r->r_refs--;
	KASSERT(r->r_refs != ~0U);
	return (r->r_refs == 0);
}

unsigned int
refcnt_read(const struct refcnt *r)
{
	return (r->r_refs);
}


/*
 * Allocation models (replace file, alternative (b), see README "mbuf
 * kit"): m_get:mbufkit_m_get, m_gethdr:mbufkit_m_gethdr,
 * m_clget:mbufkit_m_clget, m_free:mbufkit_m_free.  They do what the
 * kernel functions do for chains without tags, pf state or M_ZEROIZE,
 * with the same pools and failure behaviour, but without the
 * counters, the tag and pf calls and the call through mextfree_fns, so
 * that each m_free on a path costs a few steps instead of a few
 * hundred.  m_freem, m_extref and everything above stay real.
 */
static int
mbufkit_fails(int how)
{
	if (how == M_DONTWAIT && !mbufkit_nofail && nondet_bool()) {
		mbufkit_nfail++;
		return (1);
	}
	return (0);
}

struct mbuf *
mbufkit_m_get(int nowait, int type)
{
	struct mbuf *m;

	KASSERT(type >= 0 && type < MT_NTYPES);
	if (mbufkit_fails(nowait))
		return (NULL);
	m = MBUFKIT_ALLOC(sizeof(struct mbuf), 1);
	m->m_type = type;
	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_dat;
	m->m_flags = 0;
	return (m);
}

struct mbuf *
mbufkit_m_gethdr(int nowait, int type)
{
	struct mbuf *m;

	KASSERT(type >= 0 && type < MT_NTYPES);
	mbufkit_pool_get_used = 1;
	if (mbufkit_fails(nowait))
		return (NULL);
	m = MBUFKIT_ALLOC(sizeof(struct mbuf), 1);
	m->m_type = type;
	/* m_inithdr() */
	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_pktdat;
	m->m_flags = M_PKTHDR;
	memset(&m->m_pkthdr, 0, sizeof(m->m_pkthdr));
	m->m_pkthdr.pf.prio = IFQ_DEFPRIO;
	return (m);
}

struct mbuf *
mbufkit_m_clget(struct mbuf *m, int how, u_int pktlen)
{
	struct mbuf *m0 = NULL;
	struct pool *pp;
	caddr_t buf;

	/* m_clpool(), unrolled: smallest pool whose items hold pktlen */
	if (pktlen <= mclsizes[0])
		pp = &mclpools[0];
	else if (pktlen <= mclsizes[1])
		pp = &mclpools[1];
	else if (pktlen <= mclsizes[2])
		pp = &mclpools[2];
	else if (pktlen <= mclsizes[3])
		pp = &mclpools[3];
	else if (pktlen <= mclsizes[4])
		pp = &mclpools[4];
	else if (pktlen <= mclsizes[5])
		pp = &mclpools[5];
	else if (pktlen <= mclsizes[6])
		pp = &mclpools[6];
	else if (pktlen <= mclsizes[7])
		pp = &mclpools[7];
	else
		panic("m_clget: request for %u byte cluster", pktlen);
	if (m == NULL) {
		m0 = mbufkit_m_gethdr(how, MT_DATA);
		if (m0 == NULL)
			return (NULL);
		m = m0;
	}
	if (mbufkit_fails(how)) {
		m_freem(m0);
		return (NULL);
	}
	buf = MBUFKIT_ALLOC(pp->pr_size, 0);
	MEXTADD(m, buf, pp->pr_size, M_EXTWR, MEXTFREE_POOL, pp);
	return (m);
}

struct mbuf *
mbufkit_m_free(struct mbuf *m)
{
	struct mbuf *n;

	if (m == NULL)
		return (NULL);
	__CPROVER_assert(!(m->m_flags & M_ZEROIZE),
	    "mbufkit: M_ZEROIZE is not modelled");
	n = m->m_next;
	if (m->m_flags & M_EXT) {
		if (m->m_ext.ext_free_fn == MEXTFREE_POOL) {
			/* m_extfree_pool() */
			free(m->m_ext.ext_buf, M_TEMP, 0);
		} else {
#if !MBUFKIT_REFS
			__CPROVER_assert(0, "mbufkit: referenced cluster, "
			    "define MBUFKIT_REFS 1");
#else
			/* m_extfree_refs(): the last reference frees */
			struct mbufkit_ext_refs *r = m->m_ext.ext_arg;

			__CPROVER_assert(m->m_ext.ext_free_fn ==
			    m_extfree_refs_fn && r->free_fn == MEXTFREE_POOL,
			    "mbufkit: ext free function");
			if (refcnt_rele(&r->refs)) {
				free(m->m_ext.ext_buf, M_TEMP, 0);
				free(r, M_TEMP, 0);
			}
#endif
		}
		m->m_flags &= ~(M_EXT|M_EXTWR);
	}
	free(m, M_TEMP, 0);
	return (n);
}

/*
 * MBUFKIT_FAILED(): an allocation has failed so far.  Natively the
 * common pool model allocates (see above) and failures are not counted,
 * so there it is always 1: postconditions of the form "NULL only if an
 * allocation failed" are checked by CBMC only.
 */
#ifdef NATIVE_SHIM_H
#define MBUFKIT_FAILED()	1
#else
#define MBUFKIT_FAILED()	(mbufkit_nfail > 0)
#endif

/*
 * An arbitrary int in [0, n] (n >= 0), every value reachable.  Cheaper
 * for the solver than nondet % (n + 1) with a variable n (a divider):
 * a clamp.  The extra weight on n does not matter to either engine.
 */
static int
mbufkit_upto(int n)
{
	int v = (int)(nondet_uint() & 0xffff);

	return (v > n ? n : v);
}

/* ---- set-up ---- */

/*
 * The kernel's mbinit(): pools get their item sizes, the ext free
 * functions are registered.  Call once, first.
 */
void
mbufkit_init(void)
{
	mbufkit_in_mbinit = 1;
	mbinit();
	mbufkit_in_mbinit = 0;
	__CPROVER_assert(mbpool.pr_size == MSIZE &&
	    mclpools[0].pr_size == MCLBYTES && mbufkit_refs_pool != NULL &&
	    m_extfree_refs_fn == 1,
	    "mbufkit: mbinit did not run (keep: mbinit m_pool_init "
	    "nmbclust_update mextfree_register)");
}

/* ---- packet builder ---- */

/*
 * A packet of len bytes (0 <= len <= MCLBYTES) of arbitrary content in a
 * chain of 1..MBUFKIT_MAXSEG mbufs with arbitrary segmentation: every
 * m_len is arbitrary (zero-length mbufs included), the lengths sum to
 * len, and each segment starts at an arbitrary offset of its storage
 * (arbitrary leading and trailing space).  The first mbuf has M_PKTHDR
 * and m_pkthdr.len == len.  With MBUFKIT_CLUSTER a segment may be a
 * MCLBYTES cluster; one that does not fit its mbuf always is.  With
 * MBUFKIT_RDONLY a cluster may be read-only (M_EXTWR clear).  All
 * allocations are the kernel's (m_gethdr, m_get, m_clget with M_WAIT).
 */
struct mbuf *
mbufkit_build(int len, int flags)
{
	struct mbuf *top = NULL, *m, **mp = &top;
	int nseg, i, l, cap, rem = len;

	__CPROVER_assert(len >= 0 && len <= MBUFKIT_MAXLEN &&
	    len <= MCLBYTES, "mbufkit_build: 0 <= len <= MBUFKIT_MAXLEN");
	nseg = 1 + mbufkit_upto(MBUFKIT_MAXSEG - 1);
	for (i = 0; i < nseg; i++) {
		if (i == 0) {
			m = m_gethdr(M_WAIT, MT_DATA);
#ifndef NATIVE_SHIM_H	/* natively the replace has no effect, see above */
			__CPROVER_assert(mbufkit_pool_get_used,
			    "mbufkit: replace file needs "
			    "pool_get:mbufkit_pool_get or the models");
#endif
			__CPROVER_assert(m->m_flags == M_PKTHDR &&
			    m->m_data == m->m_pktdat,
			    "mbufkit: m_gethdr not in keep");
			cap = MHLEN;
		} else {
			m = m_get(M_WAIT, MT_DATA);
			cap = MLEN;
		}
		l = i == nseg - 1 ? rem : mbufkit_upto(rem);
		if ((MBUFKIT_MAXLEN > MHLEN && l > cap) ||
		    ((flags & MBUFKIT_CLUSTER) && nondet_bool())) {
			MCLGET(m, M_WAIT);
			__CPROVER_assert(m->m_flags & M_EXT,
			    "mbufkit: m_clget not in keep");
			cap = MCLBYTES;
			if ((flags & MBUFKIT_RDONLY) && nondet_bool())
				m->m_flags &= ~M_EXTWR;
		}
		m->m_data += mbufkit_upto(cap - l);
		m->m_len = l;
#ifdef NATIVE_SHIM_H
		/* natively the content comes from the fuzzer's input */
		if (l > 0)
			__CPROVER_havoc_slice(mtod(m, char *), l);
#endif
		rem -= l;
		*mp = m;
		mp = &m->m_next;
	}
	top->m_pkthdr.len = len;
	return (top);
}

/* ---- checks and probes ---- */

/* number of mbufs in the chain (walks at most MBUFKIT_MAXCHAIN + 1) */
int
mbufkit_count(struct mbuf *m)
{
	int n;

	for (n = 0; m != NULL && n <= MBUFKIT_MAXCHAIN; n++)
		m = m->m_next;
	return (n);
}

/* sum of m_len over the chain, as long */
long
mbufkit_len(struct mbuf *m)
{
	long sum = 0;
	int n;

	for (n = 0; m != NULL && n <= MBUFKIT_MAXCHAIN; n++, m = m->m_next)
		sum += m->m_len;
	return (sum);
}

/* mbufkit_check_chain() flags */
#define MBUFKIT_CHK_NOHDR	0x01	/* a chain without packet header */
#define MBUFKIT_CHK_HDR2	0x02	/* tolerate M_PKTHDR on later mbufs */

/*
 * Well-formedness of a packet chain, asserted:
 *  - at most MBUFKIT_MAXCHAIN mbufs (also: no cycle within that bound)
 *  - M_PKTHDR on the first mbuf if pkthdr is set, on no other mbuf
 *  - m_data .. m_data + m_len inside the mbuf's storage (cluster,
 *    m_pktdat or m_dat, by M_EXT and M_PKTHDR)
 *  - M_EXT: buffer readable for ext_size bytes; a pool cluster's pool
 *    is a cluster pool whose item size is ext_size, a referenced one
 *    has a reference count of at least 1; M_EXTWR only with M_EXT
 *  - m_nextpkt is NULL, m_type valid
 *  - m_pkthdr.len equals the sum of m_len
 */
void
mbufkit_check_chain(struct mbuf *m0, int flags)
{
	struct mbuf *m;
	caddr_t buf;
	long size, sum = 0;
	int n;

	__CPROVER_assert(m0 != NULL, "mbufkit_check: chain is not NULL");
	__CPROVER_assert((flags & MBUFKIT_CHK_NOHDR) ||
	    (m0->m_flags & M_PKTHDR),
	    "mbufkit_check: M_PKTHDR on the first mbuf");
	for (n = 0, m = m0; m != NULL && n < MBUFKIT_MAXCHAIN;
	    n++, m = m->m_next) {
		__CPROVER_assert(m == m0 || !(m->m_flags & M_PKTHDR) ||
		    (flags & MBUFKIT_CHK_HDR2),
		    "mbufkit_check: M_PKTHDR only on the first mbuf");
		__CPROVER_assert(m->m_nextpkt == NULL,
		    "mbufkit_check: m_nextpkt is NULL");
		__CPROVER_assert(m->m_type >= 0 && m->m_type < MT_NTYPES,
		    "mbufkit_check: m_type valid");
		__CPROVER_assert((m->m_flags & M_EXT) ||
		    !(m->m_flags & M_EXTWR),
		    "mbufkit_check: M_EXTWR only with M_EXT");
		if (m->m_flags & M_EXT) {
			buf = m->m_ext.ext_buf;
			size = m->m_ext.ext_size;
			__CPROVER_assert(buf != NULL && size > 0 &&
			    __CPROVER_r_ok(buf, size),
			    "mbufkit_check: cluster readable for ext_size");
			if (m->m_ext.ext_free_fn == MEXTFREE_POOL) {
				struct pool *pp = m->m_ext.ext_arg;
				__CPROVER_assert(mbufkit_is_clpool(pp) &&
				    pp->pr_size == size,
				    "mbufkit_check: cluster from its pool");
			} else {
				struct mbufkit_ext_refs *r = m->m_ext.ext_arg;
				__CPROVER_assert(m->m_ext.ext_free_fn ==
				    m_extfree_refs_fn && r != NULL &&
				    r->refs.r_refs >= 1,
				    "mbufkit_check: referenced cluster");
			}
		} else if (m->m_flags & M_PKTHDR) {
			buf = m->m_pktdat;
			size = MHLEN;
		} else {
			buf = m->m_dat;
			size = MLEN;
		}
		__CPROVER_assert(MBUFKIT_SAME_OBJECT(m->m_data, buf) &&
		    MBUFKIT_DIFF(m->m_data, buf) >= 0 &&
		    MBUFKIT_DIFF(m->m_data, buf) + (long)m->m_len <= size,
		    "mbufkit_check: m_data, m_len inside the storage");
		sum += m->m_len;
	}
	__CPROVER_assert(m == NULL,
	    "mbufkit_check: chain ends within MBUFKIT_MAXCHAIN mbufs");
	__CPROVER_assert(!(m0->m_flags & M_PKTHDR) ||
	    m0->m_pkthdr.len == sum,
	    "mbufkit_check: m_pkthdr.len is the sum of m_len");
}

#define mbufkit_check(m)	mbufkit_check_chain((m), 0)

/*
 * Byte off of the packet, or -1 if the chain is shorter.  The probes
 * replace a flat copy of the packet: tracking one byte at an arbitrary
 * offset checks every offset under CBMC, at the cost of one walk.
 */
int
mbufkit_byte(struct mbuf *m, int off)
{
	int n;

	if (off < 0)
		return (-1);
	for (n = 0; m != NULL && n <= MBUFKIT_MAXCHAIN; n++, m = m->m_next) {
		if ((u_int)off < m->m_len)
			return (mtod(m, u_char *)[off]);
		off -= m->m_len;
	}
	return (-1);
}

/* one byte of a packet, at an arbitrary offset */
struct mbufkit_byte {
	int		 off;	/* offset in the packet, -1 if empty */
	int		 val;	/* its value then, 0..255 */
	const u_char	*loc;	/* its address then */
};

/* address of byte off of the packet, NULL if the chain is shorter */
u_char *
mbufkit_ptr(struct mbuf *m, int off)
{
	int n;

	if (off < 0)
		return (NULL);
	for (n = 0; m != NULL && n <= MBUFKIT_MAXCHAIN; n++, m = m->m_next) {
		if ((u_int)off < m->m_len)
			return (mtod(m, u_char *) + off);
		off -= m->m_len;
	}
	return (NULL);
}

/*
 * Content checks.  mbufkit_track() picks a byte at an arbitrary offset
 * of a packet; after the code under test, mbufkit_same(b, p) says
 * whether p (e.g. mbufkit_ptr(m, new offset)) holds that byte.  Under
 * CBMC this one byte stands for all of them (its offset is arbitrary).
 *
 * #define MBUFKIT_MEMTRACK 1 before the include when stubflags has
 * -DMEMCPY_TRACK (see common/stubs_alloc.c): copies then move no data,
 * the model follows the byte's locations, and mbufkit_same() compares
 * addresses.  Otherwise, and natively, it compares values.  A mismatch
 * between stubflags and MBUFKIT_MEMTRACK makes content checks fail; it
 * cannot make them pass.
 */
#if defined(MBUFKIT_MEMTRACK) && !defined(NATIVE_SHIM_H)
extern const unsigned char *__memtrack_loc[2];
#endif

static void
mbufkit_track_at(struct mbufkit_byte *b, const u_char *p)
{
	b->loc = p;
	b->val = p != NULL ? *p : -1;
#if defined(MBUFKIT_MEMTRACK) && !defined(NATIVE_SHIM_H)
	__memtrack_loc[0] = p;
	__memtrack_loc[1] = NULL;
#endif
}

int
mbufkit_same(const struct mbufkit_byte *b, const u_char *p)
{
	if (b->loc == NULL)		/* empty packet: nothing tracked */
		return (p == NULL);
	if (p == NULL)
		return (0);
#if defined(MBUFKIT_MEMTRACK) && !defined(NATIVE_SHIM_H)
	return (p == __memtrack_loc[0] || p == __memtrack_loc[1]);
#else
	return (*p == b->val);
#endif
}

/* track the byte at packet offset off (-1 or past the end: nothing) */
void
mbufkit_track_off(struct mbufkit_byte *b, struct mbuf *m, int off)
{
	b->off = off;
	mbufkit_track_at(b, mbufkit_ptr(m, off));
	if (b->loc == NULL)
		b->off = -1;
}

/* track the byte at an arbitrary offset of the packet */
void
mbufkit_track(struct mbufkit_byte *b, struct mbuf *m)
{
	long len = mbufkit_len(m);

	mbufkit_track_off(b, m, len > 0 ? mbufkit_upto(len - 1) : -1);
}

/* track byte off of a flat buffer of len bytes (len > 0) */
void
mbufkit_track_buf(struct mbufkit_byte *b, const void *buf, int len)
{
	b->off = mbufkit_upto(len - 1);
	mbufkit_track_at(b, (const u_char *)buf + b->off);
}

/* free a chain the code under test handed back (m_freem; NULL is fine) */
void
mbufkit_free(struct mbuf *m)
{
	m_freem(m);
}

#endif /* MBUFKIT_H */
