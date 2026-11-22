/*
 * pf_sourcelim_add: pf_sourcelim_add() of sys/net/pf_ioctl.c (1402-1527),
 * the DIOCADDSOURCELIM case of pfioctl() (pf_ioctl.c 2194-2195).
 *
 * Input: pfioctl() passes the kernel buffer the ioctl layer copied in,
 * exactly sizeof(struct pfioc_sourcelim) = 208 bytes, every byte of
 * which is user input.  ioc is a CBMC_NEW object of that size.  The
 * fields the function branches on are arbitrary: id, entries, limit,
 * rate.limit, rate.seconds, overload_hwm, overload_lwm, inet_prefix and
 * inet6_prefix as nondet_uchar() (0..255 covers both sides of every
 * range check on them: id 0, 1, 2, 255, 256 is out of reach only as a
 * value above the byte, which the same "> MAX" test sees; inet_prefix
 * 0, 32, 33; inet6_prefix 0, 128, 129); ticket is nondet_u32().
 * description is never read and stays zero.
 *
 * The strings are not per-byte arbitrary under CBMC: every byte of a
 * symbolic string forks the strnlen/strlcpy loop models (stubs_
 * libkern.c) once per byte and runs out of memory.  They get constant
 * shapes written per branch: name is "" or "S" (the seeded entry's
 * name) or "N"; overload_tblname is "" or "x".  Long and unterminated
 * names (the ENAMETOOLONG returns) are the native engine's to cover:
 * it havoc's the whole struct and runs the real strnlen/strlcpy.
 *
 * Globals: pf_main_ruleset.rules.inactive.version is arbitrary, so the
 * ticket compare goes both ways.  pf_sourcelim_id_tree_inactive and
 * pf_sourcelim_nm_tree_inactive hold one CBMC_NEW entry (id 1, name
 * "S") inserted with the real RBT_INSERT, so the duplicate-id and
 * duplicate-name EBUSY paths (1489-1503) are reachable (id 1: a
 * duplicate; id 2..255: fresh).  pf_sourcelim_list_inactive starts
 * empty.  The real RBT functions (pf_sourcelim_*_tree_RBT_*, from
 * RBT_GENERATE in pf.c) keep their bodies.
 *
 * Models: pool_get(&pf_sourcelim_pl) returns a typed zeroed object
 * (PR_WAITOK|PR_ZERO never fails); pool_put is CBMC's free.  pfr_attach_table returns NULL or a
 * static model table and counts the reference in
 * pfrkt_ts.pfrts_refcnt[PFR_REFCNT_RULE]; pfr_detach_table asserts the
 * count is 1 and drops it.  pc_lock_init records the masks (see
 * below).  The locks (rw_enter_write, rw_exit_write, rw_status) have no
 * body: no out-parameter, no ownership, a single thread.
 *
 * Properties: no out-of-bounds access, no leak, no division by zero,
 * every table reference taken is dropped on the error returns (and kept
 * by the entry on success), and the masks.  For every bit b of the IPv4
 * mask, bit b counted from the most significant bit of the host order
 * value (b = 0 is 0x80000000) is set iff b < inet_prefix; for the IPv6
 * mask bit b of word w is set iff 32 * w + b < inet6_prefix.
 * The reference is built bit by bit with no shifts.  The masks are
 * recorded by the pc_lock_init() model, which pf_sourcelim_add() calls
 * right after computing them and before any exit that frees the entry,
 * and checked once at the end of main().
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
extern struct pool		 pf_sourcelim_pl;
int	 pf_sourcelim_add(const struct pfioc_sourcelim *);

static const struct pfioc_sourcelim	*the_ioc;
static struct pfr_ktable		 model_kt;
static int				 table_attached;

/* replace: pfr_attach_table:model_pfr_attach_table */
struct pfr_ktable *
model_pfr_attach_table(struct pf_ruleset *rs, char *name, int intr)
{
	(void)rs;
	(void)name;
	(void)intr;
	if (nondet_bool())
		return (NULL);
	table_attached = 1;
	model_kt.pfrkt_ts.pfrts_refcnt[PFR_REFCNT_RULE]++;
	return (&model_kt);
}

/* replace: pfr_detach_table:model_pfr_detach_table */
void
model_pfr_detach_table(struct pfr_ktable *kt)
{
	__CPROVER_assert(kt == &model_kt &&
	    kt->pfrkt_ts.pfrts_refcnt[PFR_REFCNT_RULE] == 1,
	    "pfr_detach_table: a reference is held");
	kt->pfrkt_ts.pfrts_refcnt[PFR_REFCNT_RULE]--;
}

/* the masks of the entry, saved where it is last visible, so that the
 * (large) bit-by-bit check is unrolled once and not on every path */
static struct pf_addr	 saved_v4, saved_v6;
static int		 have_masks;

static void
save_masks(const struct pf_sourcelim *e)
{
	saved_v4 = e->pfsrlim_ipv4_mask;
	saved_v6 = e->pfsrlim_ipv6_mask;
	have_masks = 1;
}

/* the masks the entry holds must be the prefixes' masks */
static void
check_masks(void)
{
	unsigned int v, bit, b, w;

	v = ntohl(saved_v4.v4.s_addr);
	bit = 0x80000000u;
	for (b = 0; b < 32; b++) {
		__CPROVER_assert(((v & bit) != 0) == (b < the_ioc->inet_prefix),
		    "pf_sourcelim_add: IPv4 mask bit does not match prefix");
		bit /= 2;
	}
	for (w = 0; w < 4; w++) {
		v = ntohl(saved_v6.addr32[w]);
		bit = 0x80000000u;
		for (b = 0; b < 32; b++) {
			__CPROVER_assert(((v & bit) != 0) ==
			    (32 * w + b < the_ioc->inet6_prefix),
			    "pf_sourcelim_add: IPv6 mask bit does not match "
			    "prefix");
			bit /= 2;
		}
	}
}

/*
 * kern/subr_tree.c converts between a node and its rb_entry through
 * unsigned long (rb_n2e, rb_e2n).  CBMC turns every integer to pointer
 * conversion into a case split over all objects of the program, which
 * made the check phase run out of memory (310,000 steps in symex before
 * the first SAT call).  The models do the same arithmetic on a char
 * pointer, which keeps the object; the tree algorithm itself (_rb_insert,
 * _rb_remove, rbe_insert_color, rbe_remove, ...) is the kernel's.
 */
/* replace: rb_n2e:model_rb_n2e */
struct rb_entry *
model_rb_n2e(const struct rb_type *t, void *node)
{
	return ((struct rb_entry *)((char *)node + t->t_offset));
}

/* replace: rb_e2n:model_rb_e2n */
void *
model_rb_e2n(const struct rb_type *t, struct rb_entry *rbe)
{
	return ((void *)((char *)rbe - t->t_offset));
}

/*
 * pc_lock_init() is called on the new entry right after both masks are
 * computed, before the first exit that frees it (pf_ioctl.c 1491): the
 * model records the masks there, which both engines honour (natively a
 * replace of pool_put, defined by the common model, is not applied).
 * Same effect as the kernel's: the generation counter starts at 0.
 */
/* replace: pc_lock_init:model_pc_lock_init */
void
model_pc_lock_init(struct pc_lock *lk)
{
	struct pf_sourcelim *e;

	e = (struct pf_sourcelim *)((char *)lk -
	    offsetof(struct pf_sourcelim, pfsrlim_lock));
	save_masks(e);
	lk->pcl_gen = 0;
}

/* replace: pool_get:pf_pool_get */
void *
pf_pool_get(struct pool *pp, int flags)
{
	if (pp == &pf_sourcelim_pl)
		return (CBMC_NEW(struct pf_sourcelim));
	return (malloc(pp->pr_size, M_TEMP, 0));
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
	harness_release(v);
}

int
main(void)
{
	struct pfioc_sourcelim	*ioc;
	struct pf_sourcelim	*seed, *e;
	int			 error, s;

	/* the common pool model (native engine) sizes items by pr_size */
	pf_sourcelim_pl.pr_size = sizeof(struct pf_sourcelim);

	/* the seeded entry: id 1, name "S" */
	seed = CBMC_NEW(struct pf_sourcelim);
	seed->pfsrlim_id = 1;
	seed->pfsrlim_nm[0] = 'S';
	if (RBT_INSERT(pf_sourcelim_id_tree,
	    &pf_sourcelim_id_tree_inactive, seed) != NULL)
		return (0);
	if (RBT_INSERT(pf_sourcelim_nm_tree,
	    &pf_sourcelim_nm_tree_inactive, seed) != NULL)
		return (0);

	pf_main_ruleset.rules.inactive.version = nondet_u32();

	/* the ioctl buffer */
	ioc = CBMC_NEW(struct pfioc_sourcelim);
	ioc->ticket = nondet_u32();
	ioc->id = nondet_uchar();
	ioc->entries = nondet_uchar();
	ioc->limit = nondet_uchar();
	ioc->rate.limit = nondet_uchar();
	ioc->rate.seconds = nondet_uchar();
	ioc->overload_hwm = nondet_uchar();
	ioc->overload_lwm = nondet_uchar();
	ioc->inet_prefix = nondet_uchar();
	ioc->inet6_prefix = nondet_uchar();
	/* string shapes, written per branch (see the comment above) */
	s = nondet_uint() % 3;
	if (s == 1)
		ioc->name[0] = 'S';
	else if (s == 2)
		ioc->name[0] = 'N';
	if (nondet_bool())
		ioc->overload_tblname[0] = 'x';
	the_ioc = ioc;

	error = pf_sourcelim_add(ioc);

	if (table_attached)
		__CPROVER_assert(model_kt.pfrkt_ts.pfrts_refcnt[
		    PFR_REFCNT_RULE] == (error == 0 ? 1 : 0),
		    "pf_sourcelim_add: table reference not balanced");
	if (error == 0) {
		e = TAILQ_FIRST(&pf_sourcelim_list_inactive);
		__CPROVER_assert(e != NULL, "pf_sourcelim_add: not on the list");
		save_masks(e);
		TAILQ_REMOVE(&pf_sourcelim_list_inactive, e, pfsrlim_list);
		harness_release(e);
	}

	if (have_masks)
		check_masks();
	harness_release(seed);
	harness_release(ioc);
	return (0);
}
