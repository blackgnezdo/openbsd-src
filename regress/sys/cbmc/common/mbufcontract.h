/*
 * Contract models of the mbuf library for proofs of packet parsers.
 *
 * mbufkit.h runs a parser on top of the real mbuf code; that is what
 * the net/mbuf_* targets need, but the allocator and the chain code
 * cost more symbolic execution than most parsers can afford on top.
 * This header is the other half of an assume/guarantee split: the
 * library functions are replaced by small models of what they promise
 * their callers, and the parser is proved against those promises.  The
 * promises themselves are the properties of the net/mbuf_* targets.
 *
 * Use: include this header instead of mbufkit.h and do NOT list
 * kern/uipc_mbuf.c or kern/uipc_mbuf2.c in sources; no replace, config
 * or fptargets entries are needed for mbufs.  The functions below carry
 * the kernel's names.
 *
 * The packet: MC_MAXSEG (2) mbufs at most.  Every mbuf's data lies at
 * the end of an object of its own (MC_MAXLEN bytes, arbitrary content;
 * a constant size, objects of symbolic size are very costly), so a read
 * or write past m_len of any mbuf is out of bounds for both engines
 * (mbufkit.h cannot see those inside a cluster).  Accesses before
 * m_data are not seen.  The mbuf
 * headers are typed objects; m_data points outside m_dat and M_EXT is
 * not set, so code that looks at m_ext, at leading/trailing space or at
 * M_READONLY is outside this model: use mbufkit.h for it.
 *
 * What the models promise, and what they do to stale pointers:
 *  m_pullup(m, len)	NULL and the chain freed if the packet is shorter
 *			than len or on an arbitrary allocation failure.
 *			m itself if it already holds len bytes.  Otherwise
 *			a NEW chain with an arbitrary first length in
 *			[len, total]; the old mbufs and data areas are
 *			freed, so any pointer kept across the call is a
 *			use after free.
 *  m_pulldown(m, off, len, &o)
 *			NULL and the chain freed on a short packet or an
 *			arbitrary failure.  The mbuf holding the range if
 *			one does.  Otherwise the first mbuf is cut at off
 *			(its data area stays where it is, as in the
 *			kernel) and a NEW second mbuf holds the rest; the
 *			old second mbuf is freed.
 *  m_copydata(m, off, len, dst)
 *			asserts that the range is inside the packet (the
 *			kernel panics) and copies.
 *  m_adj, m_freem, m_free, m_getptr: as in the kernel (m_freemp is
 *  an inline of sys/mbuf.h and calls the m_freem here).
 *
 * MC_MAXLEN (default 64) bounds the packet; define it before including.
 *
 * Under CBMC nothing in this file loops: the two mbufs are handled one
 * after the other and copies are stated with a quantifier (mc_copy).
 * goto-instrument refuses a loop contract on a loop whose callees
 * loop, so the models can be called from a loop under contract, and
 * opts needs no entry for this file.  A target without loop contracts
 * may define MC_COPY_LOOP before including: mc_copy is then a byte loop
 * (--unwindset mc_copy.0:<MC_MAXLEN+1>), which was cheaper for
 * netinet6/ip6_hopopts_input (93 s against 153 s).
 */
#ifndef MBUFCONTRACT_H
#define MBUFCONTRACT_H

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include "cbmc_harness.h"

#ifndef MC_MAXLEN
#define MC_MAXLEN	64
#endif
#define MC_MAXSEG	2

#undef free
void free(void *);
static void
mc_release(void *p)
{
	free(p);
}
#define free kfree	/* as -Dfree=kfree on the command line */

int mc_nfail;		/* allocation failures the models chose */

/* an arbitrary int in [0, n]; a clamp, cheaper than a modulo */
static int
mc_upto(int n)
{
	int v = (int)(nondet_uint() & 0xffff);

	return (v > n ? n : v);
}

/*
 * dst[0..n) = src[0..n), n <= MC_MAXLEN.  Under CBMC without a loop:
 * the destination becomes arbitrary and is then assumed equal.
 */
static void
mc_copy(u_char *dst, const u_char *src, int n)
{
#if defined(NATIVE_SHIM_H) || defined(MC_COPY_LOOP)
	int i;

	for (i = 0; i < n; i++)
		dst[i] = src[i];
#else
	__CPROVER_assert(n >= 0 && n <= MC_MAXLEN, "mc_copy: length");
	if (n <= 0)
		return;
	__CPROVER_assert(__CPROVER_r_ok(src, n), "mc_copy: source readable");
	__CPROVER_assert(__CPROVER_w_ok(dst, n), "mc_copy: destination writable");
	__CPROVER_havoc_slice(dst, n);
	__CPROVER_assume(__CPROVER_forall { int mc_i;
	    (0 <= mc_i && mc_i < MC_MAXLEN) ==>
	    (mc_i >= n || dst[mc_i] == src[mc_i]) });
#endif
}

/* an object of n bytes with arbitrary content, seen by the leak check */
#define MC_ALLOC(n) ({							\
	void *mc_p_ = __CPROVER_allocate((n), 0);			\
	CBMC_LEAK_RECORD_(mc_p_);					\
	(u_char *)mc_p_;						\
})

/* the data area of an mbuf made here: kept in m_ext.ext_buf (M_EXT is
 * not set, nothing else reads it) */
#define MC_BUF(m)	((m)->m_ext.ext_buf)

/* one mbuf whose len data bytes end where their object ends */
static struct mbuf *
mc_seg(int len)
{
	struct mbuf *m = CBMC_NEW(struct mbuf);
	u_char *buf = MC_ALLOC(MC_MAXLEN);
#ifdef NATIVE_SHIM_H
	int i;

	for (i = 0; i < MC_MAXLEN; i++)
		buf[i] = nondet_uchar();
#endif
	__CPROVER_assert(len >= 0 && len <= MC_MAXLEN, "mc_seg: length");
	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_type = MT_DATA;
	m->m_flags = 0;
	MC_BUF(m) = (caddr_t)buf;
	/* the data ends where the object ends: an overrun is out of bounds */
	m->m_data = (caddr_t)buf + (MC_MAXLEN - len);
	m->m_len = len;
	return (m);
}

/*
 * A packet of len bytes (0 <= len <= MC_MAXLEN) in one or two mbufs,
 * the first of an arbitrary length, zero included.
 */
struct mbuf *
mc_build(int len)
{
	struct mbuf *m;
	int first;

	__CPROVER_assert(len >= 0 && len <= MC_MAXLEN, "mc_build: length");
	first = nondet_bool() ? len : mc_upto(len);
	m = mc_seg(first);
	m->m_flags = M_PKTHDR;
	m->m_pkthdr.len = len;
	m->m_pkthdr.ph_ifidx = 0;
	if (first < len)
		m->m_next = mc_seg(len - first);
	return (m);
}

static int
mc_total(struct mbuf *m)
{
	return (m->m_len + (m->m_next != NULL ? m->m_next->m_len : 0));
}

/* chain invariants: for the harness, after the parser returned */
void
mc_check(struct mbuf *m)
{
	__CPROVER_assert(m != NULL, "mc_check: NULL chain");
	__CPROVER_assert(m->m_len >= 0, "mc_check: m_len < 0");
	if (m->m_next != NULL) {
		__CPROVER_assert(m->m_next->m_len >= 0, "mc_check: m_len < 0");
		__CPROVER_assert(m->m_next->m_next == NULL,
		    "mc_check: chain too long");
	}
	if (m->m_flags & M_PKTHDR)
		__CPROVER_assert(m->m_pkthdr.len == mc_total(m),
		    "mc_check: m_pkthdr.len is the sum of m_len");
}

struct mbuf *
m_free(struct mbuf *m)
{
	struct mbuf *n;

	__CPROVER_assert(m != NULL, "m_free: NULL");
	n = m->m_next;
	mc_release(MC_BUF(m));
	mc_release(m);
	return (n);
}

struct mbuf *
m_freem(struct mbuf *m)
{
	if (m != NULL)
		m = m_free(m);
	if (m != NULL)
		m = m_free(m);
	__CPROVER_assert(m == NULL, "m_freem: chain too long");
	return (NULL);
}

/* for the harness */
void
mc_free(struct mbuf *m)
{
	m_freem(m);
}

static int
mc_fails(void)
{
	if (nondet_bool()) {
		mc_nfail++;
		return (1);
	}
	return (0);
}

void
m_copydata(struct mbuf *m, int off, int len, void *vp)
{
	u_char *cp = vp;
	int n;

	__CPROVER_assert(off >= 0 && len >= 0 && m != NULL &&
	    off + len <= mc_total(m), "m_copydata: range inside the packet");
	if (off < m->m_len) {
		n = m->m_len - off;
		if (n > len)
			n = len;
		mc_copy(cp, mtod(m, u_char *) + off, n);
		cp += n;
		len -= n;
		off = 0;
	} else
		off -= m->m_len;
	if (len > 0)
		mc_copy(cp, mtod(m->m_next, u_char *) + off, len);
}

/* the packet's bytes [from, total) as a new mbuf */
static struct mbuf *
mc_tail(struct mbuf *m, int from, int total)
{
	struct mbuf *n = mc_seg(total - from);

	m_copydata(m, from, total - from, mtod(n, u_char *));
	return (n);
}

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
	/* a new chain: first bytes in a new first mbuf, the rest behind */
	first = len + mc_upto(total - len);
	n = mc_seg(first);
	m_copydata(m, 0, first, mtod(n, u_char *));
	n->m_flags = m->m_flags;
	n->m_pkthdr = m->m_pkthdr;
	if (first < total)
		n->m_next = mc_tail(m, first, total);
	m_freem(m);
	return (n);
}

struct mbuf *
m_pulldown(struct mbuf *m, int off, int len, int *offp)
{
	struct mbuf *n;
	int total;

	__CPROVER_assert(m != NULL, "m_pulldown: NULL mbuf");
	__CPROVER_assert(offp != NULL, "m_pulldown: model needs offp");
	total = mc_total(m);
	if (off < 0 || len < 0 || off + len > total || mc_fails()) {
		m_freem(m);
		return (NULL);
	}
	if (off + len <= m->m_len && (off < m->m_len || m->m_next == NULL)) {
		*offp = off;
		return (m);
	}
	if (off >= m->m_len) {
		*offp = off - m->m_len;
		return (m->m_next);
	}
	/* the range straddles: cut the first mbuf at off */
	n = mc_tail(m, off, total);
	m_freem(m->m_next);
	m->m_next = n;
	m->m_len = off;
	*offp = 0;
	return (n);
}

struct mbuf *
m_getptr(struct mbuf *m, int loc, int *off)
{
	if (m->m_len > loc) {
		*off = loc;
		return (m);
	}
	loc -= m->m_len;
	if (m->m_next == NULL) {
		if (loc == 0) {
			*off = m->m_len;
			return (m);
		}
		return (NULL);
	}
	m = m->m_next;
	if (m->m_len > loc || loc == m->m_len) {
		*off = loc;
		return (m);
	}
	return (NULL);
}

/* trim n bytes (0 <= n <= m_len) from the head of one mbuf */
#define MC_HEAD(m, n)	((m)->m_data += (n), (m)->m_len -= (n))

void
m_adj(struct mbuf *mp, int req_len)
{
	struct mbuf *m2;
	int len = req_len, total, n;

	if (mp == NULL)
		return;
	m2 = mp->m_next;
	total = mc_total(mp);
	if (len >= 0) {
		if (len > total)
			len = total;
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len -= len;
		n = len < mp->m_len ? len : mp->m_len;
		MC_HEAD(mp, n);
		len -= n;
		if (m2 != NULL)
			MC_HEAD(m2, len);
	} else {
		len = -len;
		if (len > total)
			len = total;
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len = total - len;
		len = total - len;	/* bytes to keep */
		if (mp->m_len > len)
			mp->m_len = len;
		len -= mp->m_len;
		if (m2 != NULL && m2->m_len > len)
			m2->m_len = len;
	}
}

#endif /* MBUFCONTRACT_H */
