/*
 * Harness: udf_mountfs() of sys/isofs/udf/udf_vfsops.c (the file is
 * #included) on a medium of arbitrary content: every block bread hands
 * out holds arbitrary bytes.  udf_find_partmaps is a model here (the
 * partition map parsing is not covered, see FINDINGS): it fails, or sets
 * any of the outcomes of the partition map handlers (metadata partition
 * with an arbitrary start, virtual partition, a sparing table
 * allocated).
 *
 * Properties:
 *   - no access outside an object (descriptor blocks, the sparing table,
 *     the umount), no division by zero, no undefined shift;
 *   - bread is asked for 0 < size <= MAXBSIZE (buffer cache limit);
 *   - no leak on any return (--memory-leak-check; on success the harness
 *     frees what udf_unmount frees);
 *   - on success the root file entry passes udf_vget's checks (a
 *     valid tag; hdr + l_ea + l_ad <= um_bsize): otherwise the mount
 *     cannot be looked up through, hence not unmounted;
 *   - on success um_bsize is a power of two in [DEV_BSIZE, MAXBSIZE]
 *     with matching um_bmask and um_bshift: RDSECTOR, udf_readlblks,
 *     udf_bmap (um_bshift - DEV_BSHIFT) and the udf_vget entry size
 *     check (um_bsize - hdr) rely on it.
 *
 * Models: bread allocates size arbitrary bytes or fails; at most NREADS
 * reads per run (longer runs are cut: a bound, not a property).
 * udf_vat_get fails or succeeds without setting up a VAT; udf_vat_map
 * adds um_start (the no-VAT branch).  bcopy checks both ranges and
 * writes arbitrary bytes into the destination.  hashinit allocates,
 * hashfree frees.  No body: the vnode operations (arbitrary result).
 */
#include "cbmc_harness.h"
#include <sys/param.h>
#include <sys/systm.h>
#include "udf_vfsops.c"

#ifndef NREADS
#define NREADS	5
#endif

static int	g_reads;
/* the fixed part of the last block released (on success: the root's) */
static struct extfile_entry	g_last;
static int			g_last_ok;

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	__CPROVER_assert(size > 0 && size <= MAXBSIZE,
	    "bread: 0 < size <= MAXBSIZE");
	__CPROVER_assume(size > 0 && size <= MAXBSIZE);
	__CPROVER_assume(g_reads < NREADS);
	g_reads++;
	if (nondet_bool()) {
		*bpp = NULL;
		return (EIO);
	}
	bp = malloc(sizeof(*bp), M_TEMP, M_WAITOK | M_ZERO);
	bp->b_data = malloc(size, M_TEMP, M_WAITOK);	/* arbitrary bytes */
	bp->b_bufsize = size;
	*bpp = bp;
	return (0);
}

void
model_brelse(struct buf *bp)
{
	g_last_ok = bp->b_bufsize >= sizeof(g_last);
	if (g_last_ok)
		g_last = *(struct extfile_entry *)bp->b_data;
	free(bp->b_data, M_TEMP, 0);
	free(bp, M_TEMP, 0);
}

void
model_bcopy(const void *src, void *dst, size_t n)
{
	__CPROVER_assert(__CPROVER_r_ok(src, n), "bcopy: source readable");
	__CPROVER_assert(__CPROVER_w_ok(dst, n),
	    "bcopy: destination writable");
	__CPROVER_havoc_slice(dst, n);
}

void *
hashinit(int elements, int type, int flags, u_long *hashmask)
{
	*hashmask = UDF_HASHTBLSIZE - 1;
	return (malloc(UDF_HASHTBLSIZE * sizeof(void *), type,
	    M_WAITOK | M_ZERO));
}

void
hashfree(void *hashtbl, int elements, int type)
{
	free(hashtbl, type, 0);
}

int
model_find_partmaps(struct umount *ump, struct logvol_desc *lvd)
{
	if (nondet_bool())
		return (EINVAL);
	if (nondet_bool()) {
		ump->um_flags |= UDF_MNT_USES_META;
		ump->um_meta_start = nondet_uint();
	}
	if (nondet_bool())
		ump->um_flags |= UDF_MNT_FIND_VAT;
	if (nondet_bool() && ump->um_stbl == NULL) {
		ump->um_stbl = malloc(sizeof(*ump->um_stbl), M_UDFMOUNT,
		    M_WAITOK);
		ump->um_psecs = nondet_int();
	}
	return (0);
}

int
udf_vat_get(struct umount *ump, uint32_t lb)
{
	if (nondet_bool())
		return (EINVAL);
	ump->um_flags &= ~UDF_MNT_FIND_VAT;
	return (0);
}

int
udf_vat_map(struct umount *ump, uint32_t *sector)
{
	*sector += ump->um_start;
	return (0);
}

int
main(void)
{
	static struct mount mnt;
	static struct vfsconf vfc;
	static struct vnode devvp;
	static struct proc proc;
	static struct ucred cred;
	static struct specinfo si;
	struct umount *ump;
	int error, bs;

	mnt.mnt_vfc = &vfc;
	devvp.v_specinfo = &si;
	proc.p_ucred = &cred;

	error = udf_mountfs(&devvp, &mnt, nondet_uint(), &proc);
	if (error != 0) {
		__CPROVER_assert(mnt.mnt_data == NULL,
		    "failure: no umount left on the mount");
		return (0);
	}
	ump = mnt.mnt_data;
	bs = ump->um_bsize;
	__CPROVER_assert(bs >= DEV_BSIZE && bs <= MAXBSIZE && powerof2(bs),
	    "success: um_bsize a power of two in [DEV_BSIZE, MAXBSIZE]");
	__CPROVER_assert(ump->um_bmask == bs - 1 &&
	    (1 << ump->um_bshift) == bs,
	    "success: um_bmask and um_bshift match um_bsize");
	/*
	 * the root file entry (the last block read) is one udf_vget
	 * accepts: a valid tag, and the fixed part, l_ea and l_ad bytes
	 * fit in one block
	 */
	{
		struct file_entry *fe = (struct file_entry *)&g_last;
		uint64_t hdr, l_ea, l_ad;
		int ext = udf_checktag(&g_last.tag, TAGID_EXTFENTRY) == 0;

		hdr = ext ? UDF_EXTFENTRY_SIZE : UDF_FENTRY_SIZE;
		l_ea = ext ? letoh32(g_last.l_ea) : letoh32(fe->l_ea);
		l_ad = ext ? letoh32(g_last.l_ad) : letoh32(fe->l_ad);
		__CPROVER_assert(g_last_ok && (ext ||
		    udf_checktag(&fe->tag, TAGID_FENTRY) == 0) &&
		    hdr + l_ea + l_ad <= (uint64_t)bs,
		    "success: the root file entry is one udf_vget accepts");
	}
	/* what udf_unmount frees (no VAT here) */
	free(ump->um_stbl, M_UDFMOUNT, 0);
	hashfree(ump->um_hashtbl, UDF_HASHTBLSIZE, M_UDFMOUNT);
	free(ump, M_UDFMOUNT, 0);
	return (0);
}
