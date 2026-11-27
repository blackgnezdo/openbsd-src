/*
 * Harness: ext2fs_bufatoff() of sys/ufs/ext2fs/ext2fs_subr.c
 * (#included), a caller of ext4_ext_find_extent().  ext4_ext_find_extent
 * is a model of
 * its contract (proven by ext2fs/ext4_find_extent): it returns NULL
 * leaving path as it was (bad root header), or it releases an
 * earlier path->ep_bp, as the real one does before reading an extent
 * block, and then returns NULL (read or header failure, ep_bp NULL) or
 * path with ep_bp NULL or a held buffer and ep_ext NULL or an extent
 * (inside the held buffer if there is one, else in the inode).
 *
 * Properties: no access outside an object (no use of an uninitialised
 * path), and on return no buffer is held but the one ext2fs_bufatoff
 * hands back on success.
 */
#include "cbmc_harness.h"
#include <sys/param.h>
#include <sys/malloc.h>
#include "ext2fs_subr.c"

#ifndef NREADS
#define NREADS	3
#endif

static int		g_reads, g_live;
static struct ext4_extent	g_ext;

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	__CPROVER_assume(g_reads < NREADS);
	g_reads++;
	bp = malloc(sizeof(*bp), M_TEMP, M_WAITOK | M_ZERO);
	bp->b_data = malloc(size, M_TEMP, M_WAITOK);
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

struct ext4_extent_path *
model_find_extent(struct m_ext2fs *fs, struct inode *ip, daddr_t lbn,
    struct ext4_extent_path *path)
{
	struct buf *bp;

	if (nondet_bool())
		return (NULL);			/* bad root header */
	if (nondet_bool()) {			/* depth > 0 */
		if (path->ep_bp != NULL) {
			model_brelse(path->ep_bp);
			path->ep_bp = NULL;
		}
		path->ep_ext = NULL;
		if (nondet_bool())
			return (NULL);		/* read or header failure */
		model_bread(NULL, 0, fs->e2fs_fsize, &bp);
		path->ep_bp = bp;
	}
	if (nondet_bool())
		path->ep_ext = NULL;
	else				/* in the block read, or in the inode */
		path->ep_ext = path->ep_bp != NULL ?
		    (struct ext4_extent *)path->ep_bp->b_data : &g_ext;
	path->ep_index = NULL;
	return (path);
}

int
main(void)
{
	static struct m_ext2fs fs;
	static struct inode ino;
	static struct vnode vn, devvp;
	static struct ufsmount ump;
	static struct ext2fs_dinode din;
	static struct uio uio;
	struct buf *bp = NULL;
	char *res;
	daddr_t bn;
	int error, held;

	fs.e2fs_fsize = fs.e2fs_bsize = 1024;
	fs.e2fs_bshift = 10;
	fs.e2fs_qbmask = 1023;
	fs.e2fs_bmask = ~1023;
	fs.e2fs_fsbtodb = 1;
	ump.um_devvp = &devvp;
	__CPROVER_havoc_object(&g_ext);	/* an arbitrary in-inode extent */
	ino.i_ump = &ump;
	ino.i_vnode = &vn;
	ino.i_e2fs = &fs;
	ino.i_e2din = &din;
	din.e2di_flags = EXT4_EXTENTS;
	vn.v_data = &ino;

	error = ext2fs_bufatoff(&ino, nondet_long() & 0xffffff, &res, &bp);
	held = error == 0;
	__CPROVER_assert(g_live == held,
	    "callers: no buffer held on return but the one handed back");
	if (held && bp != NULL)
		model_brelse(bp);
	return (0);
}
