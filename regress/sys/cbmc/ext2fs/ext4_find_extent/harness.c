/*
 * Harness: ext4_ext_find_extent() of
 * sys/ufs/ext2fs/ext2fs_extents.c (#included) on an inode whose dinode
 * (a pool item of sizeof(struct ext2fs_dinode) bytes) has arbitrary
 * content, so the in-inode extent root (e2di_blocks, 60 bytes) is
 * arbitrary, and on extent blocks of arbitrary content: bread hands out
 * FSIZE arbitrary bytes (e2fs_fsize, the size ext4_ext_find_extent
 * reads), or fails (it still hands out a buffer, as bread(9) does).
 * At most NREADS reads per run (longer runs are cut: a bound).
 *
 * Properties:
 *   - no access outside an object (the dinode, the extent blocks);
 *   - on return with path->ep_ext set: ep_ext is one of the entries
 *     its header counts (header + 1 .. + eh_ecount), inside the block:
 *     ext4_bmapext, ext4_ext_read and ext2fs_bufatoff read e_blk and
 *     e_start_* through it;
 *   - the only buffer held on return is path->ep_bp (NULL on a NULL
 *     return); the others are released.
 */
#include "cbmc_harness.h"
#include "ext2fs_extents.c"

#ifndef FSIZE
#define FSIZE	64	/* the kernel's is 1024 << n; 64 holds a header and 4 entries */
#endif
#ifndef NREADS
#define NREADS	2
#endif

static int	g_reads, g_live;

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	__CPROVER_assume(g_reads < NREADS);
	g_reads++;
	bp = malloc(sizeof(*bp), M_TEMP, M_WAITOK | M_ZERO);
	bp->b_data = malloc(size, M_TEMP, M_WAITOK);	/* arbitrary bytes */
	bp->b_bufsize = size;
	g_live++;
	*bpp = bp;
	return (nondet_bool() ? EIO : 0);
}

void
model_brelse(struct buf *bp)
{
	g_live--;
	free(bp->b_data, M_TEMP, 0);
	free(bp, M_TEMP, 0);
}

int
main(void)
{
	static struct m_ext2fs fs;
	static struct inode ino;
	static struct vnode vn, devvp;
	static struct ufsmount ump;
	struct ext4_extent_path path, *ret;
	struct ext4_extent_header *ehp;
	struct ext4_extent *first;
	daddr_t lbn = nondet_long();

	fs.e2fs_fsize = FSIZE;
	fs.e2fs_bsize = FSIZE;
	fs.e2fs_fsbtodb = 1;
	ino.i_vnode = &vn;
	ump.um_devvp = &devvp;
	ino.i_ump = &ump;
	ino.i_e2fs = &fs;
	ino.i_e2din = malloc(sizeof(struct ext2fs_dinode), M_TEMP,
	    M_WAITOK);				/* arbitrary content */
	memset(&path, 0, sizeof(path));		/* as the callers do */

	ret = ext4_ext_find_extent(&fs, &ino, lbn, &path);

	if (ret == NULL)
		__CPROVER_assert(path.ep_bp == NULL,
		    "find: no buffer held on failure");
	if (ret != NULL && path.ep_ext != NULL) {
		ehp = path.ep_header;
		first = (struct ext4_extent *)(ehp + 1);
		__CPROVER_assert(
		    path.ep_ext >= first && path.ep_ext < first + ehp->eh_ecount,
		    "find: ep_ext is one of its header's entries");
		__CPROVER_assert(__CPROVER_r_ok(path.ep_ext,
		    sizeof(struct ext4_extent)),
		    "find: ep_ext readable");
	}
	__CPROVER_assert(g_live == (path.ep_bp != NULL),
	    "find: only path->ep_bp is held");
	if (path.ep_bp != NULL)
		model_brelse(path.ep_bp);
	free(ino.i_e2din, M_TEMP, 0);
	return (0);
}
