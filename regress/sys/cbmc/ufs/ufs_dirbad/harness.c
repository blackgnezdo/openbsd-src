/*
 * Harness: ufs_dirbad() of sys/ufs/ufs/ufs_lookup.c (#included) on a
 * mount whose mnt_flag and mnt_stat.f_flags are arbitrary: mnt_stat is
 * only refreshed by the statfs system calls, so it can disagree with
 * mnt_flag (mount -r before any statfs, mount -u since the last one).
 * Property: it panics only on a writable mount (MNT_RDONLY clear in
 * mnt_flag).
 */
#include "cbmc_harness.h"
#include "ufs_lookup.c"

static int	g_rdonly;

void
panic(const char *fmt, ...)
{
	__CPROVER_assert(!g_rdonly,
	    "ufs_dirbad: panics only on a writable mount");
	__CPROVER_assume(0);		/* panic does not return */
}

int
main(void)
{
	static struct mount mnt;
	static struct vnode vn;
	static struct inode ino;

	mnt.mnt_flag = nondet_int();
	mnt.mnt_stat.f_flags = nondet_uint();
	vn.v_mount = &mnt;
	ino.i_vnode = &vn;
	g_rdonly = (mnt.mnt_flag & MNT_RDONLY) != 0;
	ufs_dirbad(&ino, nondet_int(), "mangled entry");
	/* reached only if it returned */
	__CPROVER_assert(g_rdonly, "ufs_dirbad: returns only on a read-only mount");
	return (0);
}
