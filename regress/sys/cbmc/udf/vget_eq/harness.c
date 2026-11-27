/*
 * Refinement of udf_vget() (sys/isofs/udf/udf_vfsops.c) by 9a103f788,
 * c05d2c931 and f61f24bf6.  The current udf_vget comes from the tree
 * (#included); the one before them is extracted mechanically into
 * old_vget.h and renamed old_udf_vget (udf_checktag is the same in
 * both).
 *
 * One file entry block of BSIZE arbitrary bytes (g_blk), read by both.
 * The environment makes the same choices for both runs: bread fails or
 * not (g_bread_fail), the M_NOWAIT allocation fails or not
 * (g_nowait_fail), udf_allocv fails or not (g_allocv_fail).
 *
 * Well-formed entry: the tag is a valid (extended) file entry tag and
 * hdr + l_ea + l_ad <= BSIZE, computed without wrap (hdr 216 or 176).
 * Properties:
 *   well-formed:  same return value; on success one bcopy from the
 *                 block of the same length, the same vnode type; the
 *                 u_fentry allocation is hdr + l_ea + l_ad (it was
 *                 216 + l_ea + l_ad).
 *   invalid tag:  EINVAL where it was ENOMEM (otherwise the same).
 *   valid tag, entry larger than the block:  the current one returns
 *                 EINVAL and releases everything it took (the old one
 *                 is not run: its bcopy overruns the block).
 */
#include "cbmc_harness.h"
#include <sys/param.h>
#include <sys/systm.h>
static struct proc	 harness_proc;
#undef curproc
#define curproc		(&harness_proc)
#include "udf_vfsops.c"
#include "old_vget.h"

/* CBMC's heap: the kernel names are macros for kmalloc/kfree here */
#undef malloc
#undef free
void *malloc(size_t);
void *calloc(size_t, size_t);
void free(void *);
static void *heap_alloc(size_t n, int zero)
{
	return (zero ? calloc(1, n) : malloc(n));
}
static void heap_free(void *p)
{
	free(p);
}
#define malloc kmalloc
#define free kfree

#define BSIZE	512

static unsigned char	*g_blk;
static _Bool		 g_bread_fail, g_nowait_fail, g_allocv_fail;
static int		 g_live;		/* allocations outstanding */
static size_t		 g_fentry_n;		/* u_fentry allocation size */
static const void	*g_bcopy_src;
static size_t		 g_bcopy_n;
static int		 g_bcopies;

void *
model_kmalloc(size_t size, int type, int flags)
{
	void *p;

	if ((flags & M_NOWAIT) && g_nowait_fail)
		return (NULL);
	__CPROVER_assert(size <= 65535UL * 4096,
	    "malloc: not too large (the kernel panics)");
	p = heap_alloc(size, flags & M_ZERO);
	if (type == M_UDFFENTRY)
		g_fentry_n = size;
	g_live++;
	return (p);
}

void
model_kfree(void *p, int type, size_t size)
{
	if (p == NULL)
		return;
	g_live--;
	heap_free(p);
}

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	if (g_bread_fail) {
		*bpp = NULL;
		return (EIO);
	}
	bp = model_kmalloc(sizeof(*bp), M_TEMP, M_WAITOK | M_ZERO);
	bp->b_data = (caddr_t)g_blk;	/* the same block for both runs */
	bp->b_bufsize = BSIZE;
	*bpp = bp;
	return (0);
}

void
model_brelse(struct buf *bp)
{
	model_kfree(bp, M_TEMP, sizeof(*bp));
}

void
model_bcopy(const void *src, void *dst, size_t n)
{
	__CPROVER_assert(__CPROVER_r_ok(src, n), "bcopy: source readable");
	__CPROVER_assert(__CPROVER_w_ok(dst, n),
	    "bcopy: destination writable");
	g_bcopy_src = src;
	g_bcopy_n = n;
	g_bcopies++;
}

int
udf_hashlookup(struct umount *ump, udfino_t id, int flags,
    struct vnode **vpp)
{
	*vpp = NULL;
	return (0);
}

int
udf_hashins(struct unode *up)
{
	return (0);
}

int
udf_allocv(struct mount *mp, struct vnode **vpp, struct proc *p)
{
	if (g_allocv_fail)
		return (ENOMEM);
	*vpp = model_kmalloc(sizeof(struct vnode), M_TEMP, M_WAITOK | M_ZERO);
	return (0);
}

int
udf_vat_map(struct umount *ump, uint32_t *sector)
{
	return (0);
}

int
main(void)
{
	static struct umount ump;
	static struct mount mnt;
	static struct vnode devvp;
	struct vnode *vpa, *vpb;
	struct extfile_entry *xfe;
	struct file_entry *fe;
	uint64_t hdr, l_ea, l_ad;
	int ext, valid, wellformed, erra, errb, live0;
	size_t na, nb, ca;
	int bca;
	enum vtype ta;
	ino_t ino = (ino_t)nondet_uint();

	unode_pool.pr_size = sizeof(struct unode);
	ump.um_bsize = BSIZE;
	ump.um_bshift = 9;
	ump.um_bmask = BSIZE - 1;
	ump.um_devvp = &devvp;
	mnt.mnt_data = &ump;
	g_blk = heap_alloc(BSIZE, 0);		/* arbitrary content */
	g_bread_fail = nondet_bool();
	g_nowait_fail = nondet_bool();
	g_allocv_fail = nondet_bool();

	xfe = (struct extfile_entry *)g_blk;
	fe = (struct file_entry *)g_blk;
	ext = udf_checktag(&xfe->tag, TAGID_EXTFENTRY) == 0;
	valid = ext || udf_checktag(&fe->tag, TAGID_FENTRY) == 0;
	hdr = ext ? UDF_EXTFENTRY_SIZE : UDF_FENTRY_SIZE;
	l_ea = ext ? letoh32(xfe->l_ea) : letoh32(fe->l_ea);
	l_ad = ext ? letoh32(xfe->l_ad) : letoh32(fe->l_ad);
	wellformed = valid && hdr + l_ea + l_ad <= BSIZE;

	if (wellformed || !valid) {
		/* original: only where it is defined (memory safe) */
		g_fentry_n = 0; g_bcopies = 0;
		erra = old_udf_vget(&mnt, ino, &vpa);
		na = g_fentry_n; ca = g_bcopy_n; bca = g_bcopies;
		ta = erra == 0 ? vpa->v_type : VNON;

		g_fentry_n = 0; g_bcopies = 0;
		errb = udf_vget(&mnt, ino, &vpb);
		nb = g_fentry_n;

		if (valid)
			__CPROVER_assert(erra == errb,
			    "refinement: same result");
		else
			__CPROVER_assert(errb == (erra == ENOMEM ? EINVAL : erra),
			    "refinement: invalid tag: EINVAL where it was ENOMEM");
		if (erra == 0 && errb == 0) {
			__CPROVER_assert(!valid || (na == UDF_EXTFENTRY_SIZE +
			    l_ea + l_ad && nb == hdr + l_ea + l_ad),
			    "refinement: u_fentry is hdr + l_ea + l_ad (was 216 + l_ea + l_ad)");
			__CPROVER_assert(bca == 1 && g_bcopies == 1 &&
			    ca == g_bcopy_n && g_bcopy_src == (void *)g_blk,
			    "refinement: the same bcopy from the block");
			__CPROVER_assert(ta == vpb->v_type,
			    "refinement: same vnode type");
		}
	} else {
		live0 = g_live;
		errb = udf_vget(&mnt, ino, &vpb);
		__CPROVER_assert(g_bread_fail || errb == EINVAL,
		    "current: an entry larger than the block is rejected");
		__CPROVER_assert(g_live == live0,
		    "current: a rejected entry releases what it took");
	}
	return (0);
}
