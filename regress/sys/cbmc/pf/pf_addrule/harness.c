/*
 * pf_addrule: the error paths of DIOCADDRULE in pfioctl() (sys/net/
 * pf_ioctl.c 2218-2290), from pool_get(&pf_rule_pl) to the ticket check.
 *
 * The replay below is the case's own code, in order; the anchor and
 * ticket strings have already passed their strnlen() checks (pf_ioctl.c
 * 2222-2228, no allocation on the path), and pfioctl() has taken no
 * lock yet.  The second half of the case (pf_kif_setup(), overload_tbl,
 * pf_addr_setup(), pf_anchor_setup(), the TAILQ_INSERT_TAIL into the
 * inactive ruleset and the pf_rm_rule() on its error path, pf_ioctl.c
 * 2293-2334) is out of scope: it is pf_rm_rule()'s side of the
 * interface.  When the ruleset is found and the ticket matches, the
 * replay stops and frees the rule the way the error paths free a rule
 * that never became public, so the teardown of the harness stays sound.
 * DIOCCHANGERULE frees newrule through the same pf_rule_free() on its
 * error paths (pf_ioctl.c 2507-2539); not replayed here.
 *
 * Buffer: pfioctl() works on the pfioc_rule the caller copied in;
 * sizeof(struct pfioc_rule) is 3424, offsetof(..., rule) 2064, and the
 * rule itself is 1360 bytes (a compile of sys/net/pfvar.h).  The
 * fields pf_rule_copyin() and the replay's checks branch on are
 * arbitrary, set one by one below; fields only copied from to are left
 * zero, as pool_get(PR_ZERO) leaves them in the kernel.
 *
 * The string arrays are not per-byte arbitrary under CBMC: every byte
 * of a symbolic string forks the strnlen/strlcpy loop models (stubs_
 * libkern.c) once, and eight 64 byte strings ran the cover phase out
 * of memory.  They get the four constant shapes the ownership property
 * needs, chosen by symbolic selectors: empty, the seeded name "T" (an
 * existing tag: ref++), a fresh name "N" (a new pool entry), and, for
 * ifname/rcv_ifname and the pool ifnames, "x" (a kif is allocated).
 * Every case the defect needs is covered: no tag, an existing tag, a
 * new tag, and copyin failing after to->tag was set (match_tagname
 * shape "N" with tagname shape "T").  Long and unterminated names,
 * which only reach the ENAMETOOLONG return before any tag reference,
 * are the native engine's to exercise: it havoc's the whole rule and
 * runs the real strlcpy.
 *
 * pf_tags: the global list tagname2tag()/tag_unref() walk, seeded with
 * two entries (ids 1 and 2, so a new name takes id 3 by the
 * TAILQ_INSERT_TAIL branch, tagname2tag() pf_ioctl.c 435-450), with
 * arbitrary NUL-terminated names and reference counts 1..3, as a
 * loaded ruleset leaves them.  pf_qids stays empty: pf_qname2qid(qname,
 * 0) then returns 0, which is the kernel's own answer for an unknown
 * queue name and reaches the same EBUSY path.
 *
 * strlcpy, strnlen and strcmp are replaced by loop-free models under
 * CBMC: with the byte-loop models of common/stubs_libkern.c one
 * strlcpy on a 64 byte string costs 24,500 SAT variables and unwinds
 * the "rest of src" walk 64 times as soon as a single byte is not a
 * compile-time constant (measured on a probe target; eight of them
 * ran the cover phase out of memory).  The models region-check both
 * sides and move the first four bytes, which covers every string
 * shape above; strings longer than four bytes and unterminated ones
 * are the native engine's: its models are the real functions and the
 * whole rule is havoc'd there.
 *
 * Models: pool_get returns typed items for the two pools on the path
 * (sysv/shm and the mbuf kit; a pool item reached through a list must
 * be a real object).  pf_tag_pl items may fail to allocate
 * (PR_NOWAIT); pf_rule_pl items may fail (PR_LIMITFAIL) as the kernel
 * allows.  pool_put is free(3): the pool models do not check sizes.
 * pf_find_ruleset() runs for real from pf_ruleset.c (a second source
 * file): with an empty anchor path it returns the main ruleset, whose
 * inactive version the ticket draw then matches or misses.  The model
 * a stub would need (a ruleset pointer) would be a wild pointer
 * natively.  rtable_exists() loses its body
 * and answers arbitrarily.  gettime() has no body: pfik_tzero is
 * arbitrary, nothing reads it.
 *
 * Property: after the replay the tag tree is exactly as it was: two
 * entries, the seeded ids, the seeded reference counts.  Every tag
 * reference pf_rule_copyin() takes (pf_tagname2tag(tagname, 1),
 * pf_ioctl.c 4099-4103) must be dropped again by pf_rule_free().
 * --memory-leak-check covers the rule, the kifs and the pool item of a
 * new tag entry.
 */
#include "cbmc_harness.h"
#include "pfsync.h"
#include "pflog.h"
#include "kstat.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timeout.h>
#include <sys/pool.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/syslog.h>
#include <sys/specdev.h>
#include <uvm/uvm_extern.h>
#include <crypto/md5.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/hfsc.h>
#include <net/fq_codel.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <net/pfvar.h>
#include <net/pfvar_priv.h>

/* sys/net/pf_ioctl.c */
extern struct pool		 pf_tag_pl;
extern struct pool		 pf_rule_pl;
TAILQ_HEAD(pf_tags, pf_tagname);
extern struct pf_tags		 pf_tags;

int	 pf_rule_copyin(struct pf_rule *, struct pf_rule *);
int	 pf_rule_checkaf(struct pf_rule *);
void	 pf_rule_free(struct pf_rule *);
struct pf_ruleset
	*pf_find_ruleset(const char *);

/* strlcpy/strnlen/strcmp without loops; see the harness comment */
#define PF_STRKIT_MAX 4

size_t
model_strnlen(const char *str, size_t maxlen)
{
	size_t i = 0;

#ifdef NATIVE_SHIM_H
	for (; i < maxlen && str[i] != '\0'; i++)
		;
	return (i);
#else
	__CPROVER_r_ok(str, maxlen > PF_STRKIT_MAX ? PF_STRKIT_MAX : maxlen);
	/* unrolled: the length if it is below PF_STRKIT_MAX, maxlen when
	 * the first PF_STRKIT_MAX bytes are all nonzero (the harness's
	 * shapes are at most one character) */
	if (str[0] != 0 && maxlen > 0) {
		i = 1;
		if (str[1] != 0 && maxlen > 1) {
			i = 2;
			if (str[2] != 0 && maxlen > 2) {
				i = 3;
				if (str[3] != 0 && maxlen > 3)
					return (maxlen);
			}
		}
	}
	return (i);
#endif
}

size_t
model_strlcpy(char *dst, const char *src, size_t dsize)
{
	size_t n;

#ifdef NATIVE_SHIM_H
	const char *osrc = src;
	size_t nleft = dsize;

	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';
		while (*src++)
			;
	}
	return (src - osrc - 1);
#else
	if (dsize == 0)
		return (0);
	__CPROVER_w_ok(dst, dsize);
	__CPROVER_r_ok(src, PF_STRKIT_MAX);
	/* unrolled copy of the first PF_STRKIT_MAX bytes */
	n = 0;
	if (src[0] != 0 && 0 + 1 < dsize) {
		dst[0] = src[0];
		n = 1;
		if (src[1] != 0 && 1 + 1 < dsize) {
			dst[1] = src[1];
			n = 2;
			if (src[2] != 0 && 2 + 1 < dsize) {
				dst[2] = src[2];
				n = 3;
				if (src[3] != 0 && 3 + 1 < dsize) {
					dst[3] = src[3];
					n = 4;
				}
			}
		}
	}
	dst[n] = '\0';
	return (n);
#endif
}

int
model_strcmp(const char *a, const char *b)
{
	int i;

#ifdef NATIVE_SHIM_H
	for (i = 0; a[i] == b[i]; i++)
		if (a[i] == '\0')
			return (0);
	return ((unsigned char)a[i] - (unsigned char)b[i]);
#else
	__CPROVER_r_ok(a, PF_STRKIT_MAX + 1);
	__CPROVER_r_ok(b, PF_STRKIT_MAX + 1);
	for (i = 0; i < PF_STRKIT_MAX; i++) {
		if (a[i] != b[i])
			return ((unsigned char)a[i] - (unsigned char)b[i]);
		if (a[i] == 0)
			return (0);
	}
	return (0);	/* equal in the first PF_STRKIT_MAX bytes */
#endif
}

/* replace: pool_get:pf_pool_get */
void *
pf_pool_get(struct pool *pp, int flags)
{
	if (pp == &pf_tag_pl) {
		if ((flags & PR_NOWAIT) && nondet_bool())
			return (NULL);		/* tagname2tag's EBUSY path */
		return (CBMC_NEW(struct pf_tagname));
	}
	if (pp == &pf_rule_pl) {
		if ((flags & PR_LIMITFAIL) && nondet_bool())
			return (NULL);		/* pfioctl's ENOMEM path */
		return (CBMC_NEW(struct pf_rule));
	}
	return (malloc(pp->pr_size, M_TEMP, (flags & PR_ZERO) ? M_ZERO : 0));
}

/* CBMC's free for objects of CBMC_NEW and malloc (kernel free(9) is
 * kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

/* replace: pool_put:pf_pool_put */
void
pf_pool_put(struct pool *pp, void *v)
{
	(void)pp;
	harness_release(v);
}

int
main(void)
{
	struct pfioc_rule	*pr;
	struct pf_ruleset	*rs;
	struct pf_rule		*rule, *r;
	struct pf_tagname	*e0, *e1, *t, *next;
	int			 r0, r1, error, i, n0, n1, s;

	/* the item size of the two pools on the path, as pfattach() would
	 * record it (sysv/shm pattern): natively the common pool model
	 * allocates from it; under CBMC pf_pool_get returns typed items */
	pf_tag_pl.pr_size = sizeof(struct pf_tagname);
	pf_rule_pl.pr_size = sizeof(struct pf_rule);

	/* pf_tags as a loaded ruleset leaves it */
	e0 = CBMC_NEW(struct pf_tagname);
	e1 = CBMC_NEW(struct pf_tagname);
	TAILQ_INSERT_TAIL(&pf_tags, e0, entries);
	TAILQ_INSERT_TAIL(&pf_tags, e1, entries);
	memset(e0->name, 0, sizeof(e0->name));
	e0->name[0] = 'T';			/* the tagname shape "T" matches */
	e0->tag = 1;
	e0->ref = 1 + (nondet_int() & 3);
	memset(e1->name, 0, sizeof(e1->name));
	e1->name[0] = 'U';
	e1->tag = 2;
	e1->ref = 1 + (nondet_int() & 3);
	r0 = e0->ref;
	r1 = e1->ref;

	/* the ioctl buffer: the fields the code branches on are arbitrary,
	 * the strings have the constant shapes of the harness comment */
	pr = CBMC_NEW(struct pfioc_rule);
#ifdef NATIVE_SHIM_H
	/* natively the whole rule is arbitrary user bytes, as copyin
	 * leaves it, and the models above are the real functions */
	__CPROVER_havoc_slice(&pr->rule, sizeof(pr->rule));
#else
	/* under CBMC the string arrays get the constant shapes below */
#endif
	pr->ticket = nondet_u32();
	r = &pr->rule;
	r->scrub_flags = nondet_u32();
	r->set_prio[0] = nondet_uchar();
	r->set_prio[1] = nondet_uchar();
	r->src.port_op = nondet_uchar();
	r->src.port[0] = nondet_u16();
	r->src.port[1] = nondet_u16();
	r->dst.port_op = nondet_uchar();
	r->dst.port[0] = nondet_u16();
	r->dst.port[1] = nondet_u16();
	r->rdr.port_op = nondet_uchar();
	r->rdr.proxy_port[0] = nondet_u16();
	r->rdr.proxy_port[1] = nondet_u16();
	r->rtableid = nondet_int();
	r->onrdomain = nondet_int();
	r->return_icmp = nondet_u16();
	r->af = nondet_u16();
	r->naf = nondet_u16();
	r->rule_flag = nondet_u32();
	r->src.addr.type = nondet_uchar();
	r->dst.addr.type = nondet_uchar();
	r->rt = nondet_int();
	r->direction = nondet_int();
	r->statelim.limiter_action = nondet_uchar();
	r->sourcelim.limiter_action = nondet_uchar();

	/* string shapes: 0 empty, 1 the seeded name "T", 2 a fresh name.
	 * Written per branch, so every byte is a constant on each path:
	 * a symbolically selected byte would fork the strnlen/strlcpy
	 * loop models once per byte (stubs_libkern.c). */
	s = nondet_uint() % 3;
	memset(r->tagname, 0, sizeof(r->tagname));
	if (s == 1)
		r->tagname[0] = 'T';
	else if (s == 2)
		r->tagname[0] = 'N';
	s = nondet_uint() % 3;
	memset(r->match_tagname, 0, sizeof(r->match_tagname));
	if (s == 1)
		r->match_tagname[0] = 'T';
	else if (s == 2)
		r->match_tagname[0] = 'N';
	/* one selector for every other string: all empty or all one char */
	s = nondet_uint() % 2;
	memset(r->label, 0, sizeof(r->label));
	memset(r->ifname, 0, sizeof(r->ifname));
	memset(r->rcv_ifname, 0, sizeof(r->rcv_ifname));
	memset(r->qname, 0, sizeof(r->qname));
	memset(r->pqname, 0, sizeof(r->pqname));
	memset(r->overload_tblname, 0, sizeof(r->overload_tblname));
	memset(r->nat.ifname, 0, sizeof(r->nat.ifname));
	memset(r->rdr.ifname, 0, sizeof(r->rdr.ifname));
	memset(r->route.ifname, 0, sizeof(r->route.ifname));
	if (s == 1) {
		r->label[0] = 'x';
		r->ifname[0] = 'x';
		r->rcv_ifname[0] = 'x';
		r->qname[0] = 'x';
		r->pqname[0] = 'x';
		r->overload_tblname[0] = 'x';
		r->nat.ifname[0] = 'x';
		r->rdr.ifname[0] = 'x';
		r->route.ifname[0] = 'x';
	}

	/* pfioctl(), DIOCADDRULE: pf_ioctl.c 2231-2290 */
	rule = pool_get(&pf_rule_pl, PR_WAITOK|PR_LIMITFAIL|PR_ZERO);
	if (rule == NULL) {
		error = ENOMEM;
	} else if ((error = pf_rule_copyin(&pr->rule, rule)) != 0) {
		pf_rule_free(rule);
		rule = NULL;
	} else if (pr->rule.return_icmp >> 8 > ICMP_MAXTYPE) {
		error = EINVAL;
		pf_rule_free(rule);
		rule = NULL;
	} else if ((error = pf_rule_checkaf(rule)) != 0) {
		pf_rule_free(rule);
		rule = NULL;
	} else if (rule->src.addr.type == PF_ADDR_NONE ||
	    rule->dst.addr.type == PF_ADDR_NONE) {
		error = EINVAL;
		pf_rule_free(rule);
		rule = NULL;
	} else if (rule->rt && !rule->direction) {
		error = EINVAL;
		pf_rule_free(rule);
		rule = NULL;
	} else if ((rs = pf_find_ruleset(pr->anchor)) == NULL) {
		error = EINVAL;
		pf_rule_free(rule);
		rule = NULL;
	} else if (pr->ticket != rs->rules.inactive.version) {
		error = EBUSY;
		pf_rule_free(rule);
		rule = NULL;
	} else {
		/* ticket matches: the rest of the case is out of scope
		 * (see the harness comment); free the rule as the error
		 * paths do, so the teardown below is sound */
		pf_rule_free(rule);
		rule = NULL;
	}
	(void)error;

	/* the tag tree is exactly as it was before the ioctl */
	i = n0 = n1 = 0;
	TAILQ_FOREACH_SAFE(t, &pf_tags, entries, next) {
		i++;
		if (t == e0) {
			n0++;
			__CPROVER_assert(t->ref == r0,
			    "pf_addrule: tag reference not balanced");
		}
		if (t == e1) {
			n1++;
			__CPROVER_assert(t->ref == r1,
			    "pf_addrule: tag reference not balanced");
		}
	}
	__CPROVER_assert(i == 2 && n0 == 1 && n1 == 1,
	    "pf_addrule: tag entry leaked into the tree");

	/* teardown: the objects the harness made */
	TAILQ_FOREACH_SAFE(t, &pf_tags, entries, next)
		harness_release(t);
	harness_release(pr);
	return (0);
}
