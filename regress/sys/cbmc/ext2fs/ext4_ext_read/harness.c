/*
 * Harness: ext4_ext_read() of sys/ufs/ext2fs/ext2fs_readwrite.c
 * (#included), a caller of ext4_ext_find_extent(); at most 3 breads;
 * uiomove has no body; the extent cache (ext4_ext_in_cache,
 * ext4_ext_put_cache) is a model.  ext4_ext_find_extent is a model of
 * its contract (proven by ext2fs/ext4_find_extent): it returns NULL
 * leaving path as it was (bad root header), or it releases an
 * earlier path->ep_bp, as the real one does before reading an extent
 * block, and then returns NULL (read or header failure, ep_bp NULL) or
 * path with ep_bp NULL or a held buffer and ep_ext NULL or an extent.
 *
 * Properties: no access outside an object (no use of an uninitialised
 * path), and on return no buffer is held but the one ext2fs_bufatoff
 * hands back on success.
 */
#include "cbmc_harness.h"
#include <sys/param.h>
#include <sys/malloc.h>
#include "ext2fs_readwrite.c"

/* as ext2fs_extents.h (for mutants predating it: headers are not overridden) */
#ifndef EXT4_EXT_INIT_MAX_LEN
#define EXT4_EXT_INIT_MAX_LEN	32768
#endif
int	ext4_ext_maps(struct ext4_extent *, daddr_t);

#ifndef NREADS
#define NREADS	3
#endif

static int		g_reads, g_live;
static struct ext4_extent	g_ext;
/* the extent the caller was handed for g_lbn (find or cache) */
static struct ext4_extent	g_used;
static daddr_t			g_lbn;
static int			g_used_set;
static struct vnode		*g_devvp;

/* as ext2fs_extents.c: lbn is in a written extent (the file is not included: ufs/inode.h has no guard) */
int
ext4_ext_maps(struct ext4_extent *ep, daddr_t lbn)
{
	if (ep->e_len > EXT4_EXT_INIT_MAX_LEN)
		return (0);
	return (lbn >= ep->e_blk && lbn < (daddr_t)ep->e_blk + ep->e_len);
}

/* blkno (DEV_BSIZE units, fsbtodb shift 1) is lbn's block in g_used */
static int
in_used(daddr_t blkno)
{
	daddr_t s = (daddr_t)g_used.e_start_hi << 32 | g_used.e_start_lo;

	return (g_used_set && g_used.e_len <= EXT4_EXT_INIT_MAX_LEN &&
	    g_lbn >= g_used.e_blk &&
	    g_lbn < (daddr_t)g_used.e_blk + g_used.e_len &&
	    blkno == (s + g_lbn - g_used.e_blk) << 1);
}

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *bp;

	__CPROVER_assume(g_reads < NREADS);
	g_reads++;
	if (vp == g_devvp)
		__CPROVER_assert(in_used(blkno),
		    "data read: lbn's block in a written extent that has it");
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

static uint64_t	g_size;		/* the file's size, fixed per run */

uint64_t
ext2fs_size(struct inode *ip)
{
	return (g_size);
}

/* uiomove: the kernel buffer is readable; resid and offset advance */
int
uiomove(void *cp, size_t n, struct uio *uio)
{
	__CPROVER_assert(__CPROVER_r_ok(cp, n), "uiomove: source readable");
	uio->uio_resid -= n;
	uio->uio_offset += n;
	return (nondet_bool() ? EFAULT : 0);
}

/* the extent cache: empty, or an extent that maps lbn */
int
ext4_ext_in_cache(struct inode *ip, daddr_t lbn, struct ext4_extent *ep)
{
	struct ext4_extent c;

	/* ext4_ext_read puts only extents that map their block there */
	if (nondet_bool())
		return (EXT4_EXT_CACHE_NO);
	c = g_ext;
	__CPROVER_assume(ext4_ext_maps(&c, lbn));
	*ep = c;
	g_used = c;
	g_lbn = lbn;
	g_used_set = 1;
	return (EXT4_EXT_CACHE_IN);
}

void
ext4_ext_put_cache(struct inode *ip, struct ext4_extent *ep, int type)
{
	__CPROVER_assert(__CPROVER_r_ok(ep, sizeof(*ep)),
	    "put_cache: extent readable");
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
	else {
		/* in the block read, or in the in-inode root */
		path->ep_ext = path->ep_bp != NULL ?
		    (struct ext4_extent *)path->ep_bp->b_data : &g_ext;
		g_used = *path->ep_ext;
		g_lbn = lbn;
		g_used_set = 1;
	}
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
	g_devvp = &devvp;
	__CPROVER_havoc_object(&g_ext);	/* an arbitrary extent */
	ino.i_ump = &ump;
	ino.i_vnode = &vn;
	ino.i_e2fs = &fs;
	ino.i_e2din = &din;
	din.e2di_flags = EXT4_EXTENTS;
	vn.v_data = &ino;

	held = 0;
	g_size = nondet_ulong() & 0xffffff;
	uio.uio_offset = nondet_long() & 0xffffff;
	uio.uio_resid = nondet_long() & 0xfff;
	uio.uio_rw = UIO_READ;
	error = ext4_ext_read(&vn, &ino, &fs, &uio);
	__CPROVER_assert(g_live == held,
	    "callers: no buffer held on return but the one handed back");
	if (held && bp != NULL)
		model_brelse(bp);
	return (0);
}
