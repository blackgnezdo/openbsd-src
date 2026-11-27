/*
 * Harness: udf_vget() of sys/isofs/udf/udf_vfsops.c (the file is
 * #included) on one file entry block of arbitrary content: the block
 * udf_vget reads with RDSECTOR (bread of um_bsize bytes) comes from the
 * medium.  BSIZE is the volume's logical block size (UDF allows 512 and
 * up; 2048 on optical media; the bug does not depend on it).
 *
 * Properties: no access outside an object (the block, the u_fentry
 * allocation); and, when udf_vget returns a vnode, the file entry it
 * keeps holds what its readers take from it: l_ea bytes of extended
 * attributes then l_ad bytes of allocation descriptors (or embedded
 * data) after the fixed part, inside u_fentry (udf_readatoffset
 * and udf_bmap_internal in udf_vnops.c index data[] by l_ea and l_ad),
 * and the fixed part of the entry's type (176 or 216 bytes) is readable
 * (readers use the fields of either type after checking the tag).
 *
 * Models: bread hands out a buffer of BSIZE arbitrary bytes or fails;
 * brelse frees it.  udf_hashlookup finds nothing; udf_allocv makes a
 * vnode or fails; udf_hashins, udf_vat_map: nothing.  No body: vref,
 * rrw_init_flags, checkalias, printf.  pool_get, malloc: common/ stubs
 * (M_NOWAIT may fail).
 */
#include "cbmc_harness.h"
#include <sys/param.h>
#include <sys/systm.h>
/* curproc is only passed to udf_allocv (a model here): no per-CPU data */
static struct proc	 harness_proc;
#undef curproc
#define curproc		(&harness_proc)
#include "udf_vfsops.c"

#ifndef BSIZE
#define BSIZE	512
#endif

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	__CPROVER_assert(size == BSIZE, "bread: one logical block");
	if (nondet_bool()) {
		*bpp = NULL;
		return (EIO);
	}
	bp = malloc(sizeof(*bp), M_TEMP, M_WAITOK | M_ZERO);
	bp->b_data = malloc(BSIZE, M_TEMP, M_WAITOK);	/* arbitrary bytes */
	bp->b_bufsize = BSIZE;
	*bpp = bp;
	return (0);
}

void
model_brelse(struct buf *bp)
{
	free(bp->b_data, M_TEMP, BSIZE);
	free(bp, M_TEMP, sizeof(*bp));
}

/*
 * bcopy contract: the whole source range is readable, the whole
 * destination range writable (checked here, for every length); the
 * fixed part of the entry (the first UDF_EXTFENTRY_SIZE bytes, which
 * hold the tag, icbtag, l_ea and l_ad the checks below read) is copied,
 * the rest of the destination is left as it is.
 */
void
model_bcopy(const void *src, void *dst, size_t n)
{
	size_t i, k;

	__CPROVER_assert(__CPROVER_r_ok(src, n), "bcopy: source readable");
	__CPROVER_assert(__CPROVER_w_ok(dst, n),
	    "bcopy: destination writable");
	k = n < UDF_EXTFENTRY_SIZE ? n : UDF_EXTFENTRY_SIZE;
	for (i = 0; i < k; i++)
		((char *)dst)[i] = ((const char *)src)[i];
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
	if (nondet_bool())
		return (ENOMEM);
	*vpp = malloc(sizeof(struct vnode), M_TEMP, M_WAITOK | M_ZERO);
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
	struct vnode *vp;
	struct unode *up;
	uint32_t l_ea, l_ad;
	int error;

	unode_pool.pr_size = sizeof(struct unode);
	ump.um_bsize = BSIZE;
	ump.um_bshift = (BSIZE == 512) ? 9 : 11;
	ump.um_bmask = BSIZE - 1;
	ump.um_devvp = &devvp;
	mnt.mnt_data = &ump;

	error = udf_vget(&mnt, (ino_t)nondet_uint(), &vp);
	if (error != 0)
		return (0);

	up = VTOU(vp);
	__CPROVER_assert(__CPROVER_r_ok(up->u_fentry, UDF_FENTRY_SIZE),
	    "u_fentry: file entry fixed part readable");
	if (udf_checktag(&up->u_fentry->tag, TAGID_EXTFENTRY) == 0)
		__CPROVER_assert(__CPROVER_r_ok(up->u_fentry,
		    UDF_EXTFENTRY_SIZE),
		    "u_fentry: extended file entry fixed part readable");
	if (udf_checktag(&up->u_fentry->tag, TAGID_EXTFENTRY) == 0) {
		struct extfile_entry *xfe = up->u_fentry;

		l_ea = letoh32(xfe->l_ea);
		l_ad = letoh32(xfe->l_ad);
		__CPROVER_assert(__CPROVER_r_ok(xfe->data, l_ea) &&
		    __CPROVER_r_ok(&xfe->data[l_ea], l_ad),
		    "extended file entry: l_ea and l_ad bytes inside u_fentry");
	} else {
		struct file_entry *fe = (struct file_entry *)up->u_fentry;

		l_ea = letoh32(fe->l_ea);
		l_ad = letoh32(fe->l_ad);
		__CPROVER_assert(__CPROVER_r_ok(fe->data, l_ea) &&
		    __CPROVER_r_ok(&fe->data[l_ea], l_ad),
		    "file entry: l_ea and l_ad bytes inside u_fentry");
	}
	return (0);
}
