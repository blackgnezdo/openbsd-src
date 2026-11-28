/*
 * Harness: ext2fs_readdir() of sys/ufs/ext2fs/ext2fs_lookup.c
 * (#included) on a directory of BSIZE-byte blocks whose contents are
 * arbitrary: VOP_READ is a model that reads up to the requested number
 * of arbitrary bytes.  An arbitrary starting offset (lseek(2) may put it
 * anywhere) and getdents(2) length; uiomove is a model.
 *
 * Properties (with RDSIZE: only the first):
 *   - malloc(9) is not asked for more than MALLOC_MAX (it panics);
 *   - no access outside the buffer read into (entry headers);
 *   - every name copied out lies in the bytes read;
 *   - uio_offset does not move backwards.
 */
#define RDSIZE
#include "cbmc_harness.h"
#include "ext2fs_lookup.c"

#ifndef BSIZE
#define BSIZE	32
#endif
#ifndef MAXRESID
#define MAXRESID	96
#endif

int	dirchk;
static char	*g_buf;
static size_t	 g_cnt;

/* readdir must not call it: it panics on a writable mount, and the offset comes from the user */
void
ufs_dirbad(struct inode *ip, doff_t offset, char *how)
{
	__CPROVER_assert(0, "readdir: no ufs_dirbad (it panics on rw mounts)");
}

int
VOP_READ(struct vnode *vp, struct uio *uio, int ioflag, struct ucred *cred)
{
	size_t n = nondet_ulong();

#ifdef RDSIZE
	return (EIO);
#endif
	__CPROVER_assume(n <= uio->uio_resid);
	g_buf = uio->uio_iov->iov_base;
	g_cnt = n;
	__CPROVER_havoc_slice(g_buf, n);
	uio->uio_resid -= n;
	return (0);
}

int
uiomove(void *cp, size_t n, struct uio *uio)
{
	__CPROVER_assert(__CPROVER_r_ok(cp, n), "uiomove: source readable");
	if (n > uio->uio_resid)
		n = uio->uio_resid;
	uio->uio_resid -= n;
	uio->uio_offset += n;
	return (nondet_bool() ? EFAULT : 0);
}

char *
strncpy(char *dst, const char *src, size_t n)
{
	__CPROVER_assert(src >= g_buf && src + n <= g_buf + g_cnt,
	    "readdir: the name lies in the bytes read");
	return (dst);
}

int
main(void)
{
	static struct m_ext2fs fs;
	static struct inode ino;
	static struct vnode vn;
	static struct uio uio;
	static struct vop_readdir_args a;
	int eof;
	off_t off0;

	fs.e2fs_bsize = BSIZE;
	ino.i_e2fs = &fs;
	ino.i_vnode = &vn;
	vn.v_data = &ino;
	vn.v_type = VDIR;
	off0 = nondet_long();
	__CPROVER_assume(off0 >= 0 && off0 <= 4 * BSIZE);
	uio.uio_offset = off0;
#ifdef RDSIZE
	uio.uio_resid = nondet_ulong();
	__CPROVER_assume(uio.uio_resid <= INT_MAX);
#else
	uio.uio_resid = nondet_ulong();
	__CPROVER_assume(uio.uio_resid <= MAXRESID);
#endif
	uio.uio_rw = UIO_READ;
	a.a_vp = &vn;
	a.a_uio = &uio;
	a.a_eofflag = &eof;
	ext2fs_readdir(&a);
	__CPROVER_assert(uio.uio_offset >= off0,
	    "readdir: uio_offset does not move backwards");
	return (0);
}
