/*
 * Harness: ffs_mountfs() on a device whose blocks have arbitrary content.
 *
 * bread() is replaced by a model (see the replace file).
 * Assumed contract of bread(vp, blkno, size, &bp): on success bp->b_data
 * is valid for size bytes.  A request with size <= 0 or size > MAXBSIZE
 * is reported, since the buffer cache is not part of the model.
 */
/* Same headers as ffs_vfsops.c, so that struct types match at link time. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/mbuf.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/pool.h>
#include <sys/dkio.h>
#include <sys/disk.h>
#include <sys/specdev.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/dir.h>
#include <ufs/ufs/ufs_extern.h>
#include <ufs/ufs/dirhash.h>
#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>
#include <uvm/uvm_extern.h>

_Bool nondet_bool(void);
int nondet_int(void);

struct vnode *rootvp;

int
model_bread(struct vnode *vp, daddr_t blkno, int size, struct buf **bpp)
{
	struct buf *b;

	__CPROVER_assert(size > 0 && size <= MAXBSIZE,
	    "bread called with a valid size");
	if (size <= 0 || size > MAXBSIZE)
		size = 1;
	b = malloc(sizeof(*b), M_TEMP, M_WAITOK | M_ZERO);
	b->b_data = malloc(size, M_TEMP, M_WAITOK);	/* arbitrary content */
	*bpp = b;		/* set on error too; the caller releases it */
	return (nondet_bool() ? EIO : 0);
}

void
model_brelse(struct buf *bp)
{
	free(bp->b_data, M_TEMP, 0);
	free(bp, M_TEMP, sizeof(*bp));
}

int ffs_mountfs(struct vnode *, struct mount *, struct proc *);

int
main(void)
{
	static struct vfsconf vfc;
	static struct mount mnt;
	static struct specinfo si;
	static struct vnode devvp;

	mnt.mnt_vfc = &vfc;
	mnt.mnt_flag = nondet_int();	/* MNT_RDONLY, MNT_FORCE, ... */
	devvp.v_specinfo = &si;

	(void)ffs_mountfs(&devvp, &mnt, NULL);
	return (0);
}
