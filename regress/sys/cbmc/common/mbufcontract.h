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
 * Loops in this file run MC_MAXLEN or MC_MAXSEG times at most; opts
 * needs --unwind above MC_MAXSEG and
 *	--unwindset mc_copy.0:<MC_MAXLEN+1>
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

static void
mc_copy(u_char *dst, const u_char *src, int n)
{
	int i;

	for (i = 0; i < n; i++)
		dst[i] = src[i];
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

/* one mbuf with a data area of exactly len bytes, arbitrary content */
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
	int n = 0, i;

	for (i = 0; i < MC_MAXSEG && m != NULL; i++, m = m->m_next)
		n += m->m_len;
	return (n);
}

/* chain invariants: for the harness, after the parser returned */
void
mc_check(struct mbuf *m0)
{
	struct mbuf *m = m0;
	int n = 0, i;

	__CPROVER_assert(m0 != NULL, "mc_check: NULL chain");
	for (i = 0; i < MC_MAXSEG && m != NULL; i++, m = m->m_next) {
		__CPROVER_assert(m->m_len >= 0, "mc_check: m_len < 0");
		n += m->m_len;
	}
	__CPROVER_assert(m == NULL, "mc_check: chain too long");
	if (m0->m_flags & M_PKTHDR)
		__CPROVER_assert(m0->m_pkthdr.len == n,
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
	int i;

	for (i = 0; i < MC_MAXSEG && m != NULL; i++)
		m = m_free(m);
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

/* the packet's bytes [from, total) as a new mbuf; needs from >= the
 * first mbuf's length or the first mbuf to hold [from, m_len) */
static struct mbuf *
mc_tail(struct mbuf *m, int from, int total)
{
	struct mbuf *n = mc_seg(total - from);
	int head = 0;

	if (from < m->m_len) {
		head = m->m_len - from;
		mc_copy(mtod(n, u_char *), mtod(m, u_char *) + from, head);
		from = 0;
	} else
		from -= m->m_len;
	if (m->m_next != NULL)
		mc_copy(mtod(n, u_char *) + head,
		    mtod(m->m_next, u_char *) + from,
		    m->m_next->m_len - from);
	return (n);
}

void	m_copydata(struct mbuf *, int, int, void *);

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

void
m_copydata(struct mbuf *m, int off, int len, void *vp)
{
	u_char *cp = vp;
	int i, n;

	__CPROVER_assert(off >= 0 && len >= 0 && m != NULL &&
	    off + len <= mc_total(m), "m_copydata: range inside the packet");
	for (i = 0; i < MC_MAXSEG && m != NULL && len > 0; i++) {
		if (off >= m->m_len) {
			off -= m->m_len;
		} else {
			n = m->m_len - off;
			if (n > len)
				n = len;
			mc_copy(cp, mtod(m, u_char *) + off, n);
			cp += n;
			len -= n;
			off = 0;
		}
		m = m->m_next;
	}
}

struct mbuf *
m_getptr(struct mbuf *m, int loc, int *off)
{
	int i;

	for (i = 0; i < MC_MAXSEG && m != NULL; i++) {
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
	}
	return (NULL);
}

void
m_adj(struct mbuf *mp, int req_len)
{
	struct mbuf *m = mp;
	int len = req_len, total, i;

	if (mp == NULL)
		return;
	total = mc_total(mp);
	if (len >= 0) {
		if (len > total)
			len = total;
		for (i = 0; i < MC_MAXSEG && m != NULL; i++) {
			if (m->m_len <= len) {
				len -= m->m_len;
				m->m_data += m->m_len;
				m->m_len = 0;
			} else {
				m->m_data += len;
				m->m_len -= len;
				len = 0;
			}
			m = m->m_next;
		}
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len -= (req_len > total ? total : req_len);
	} else {
		len = -len;
		if (len > total)
			len = total;
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len = total - len;
		len = total - len;	/* bytes to keep */
		for (i = 0; i < MC_MAXSEG && m != NULL; i++) {
			if (m->m_len > len)
				m->m_len = len;
			len -= m->m_len;
			m = m->m_next;
		}
	}
}

#endif /* MBUFCONTRACT_H */
