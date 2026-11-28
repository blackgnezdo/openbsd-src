/*
 * Harness: ext2fs_search_dirblock() of sys/ufs/ext2fs/ext2fs_lookup.c
 * (#included) on one directory block of BSIZE arbitrary bytes (the
 * kernel's is e2fs_bsize, 1024 << n), from an arbitrary starting offset
 * in it (0: ext2fs_lookup passes 0 for every block), for an arbitrary name of 1..NAMEMAX bytes, with an arbitrary
 * slot search state.  dirchk is DIRCHK (1 with option DIAGNOSTIC, as in
 * GENERIC; 0 otherwise).  ufs_dirbad is a model that returns (it panics
 * only for a writable mount).
 *
 * Properties:
 *   - termination: every call returns (unwinding bound BSIZE + 1
 *     iterations: each pass advances offset by at least 1, or ends);
 *   - no access outside the block or the name (see AROUND);
 *   - found: the entry at data + *entryoffsetinblockp is a used entry
 *     with the name, and ip->i_offset moved as much as the offset;
 *   - not found: ip->i_offset ends at the end of the block (where the
 *     caller reads the next block from).
 */
#include "cbmc_harness.h"
#include "ext2fs_lookup.c"

#ifndef BSIZE
#define BSIZE	32
#endif
#ifndef NAMEMAX
#define NAMEMAX	4
#endif
#ifndef DIRCHK
#define DIRCHK	0
#endif

int	dirchk = DIRCHK;
static int	g_bad;
static char	*g_data;

/*
 * The block lies at the start of one object large enough for any
 * offset the scan can form (BSIZE + 65535 + an entry), as kernel memory
 * around a buffer: ep < lim then compares addresses as the kernel does.
 * Entry headers are read only while ep < lim (inside the block); names
 * are read only by memcmp, which must stay inside the block.
 */
#ifndef AROUND
#define AROUND	BSIZE
#endif

int
model_memcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	size_t i;

	__CPROVER_assert((const char *)b2 >= g_data &&
	    (const char *)b2 + n <= g_data + BSIZE,
	    "name compare: the entry's name inside the block");
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i])
			return (p1[i] - p2[i]);
	return (0);
}

void
ufs_dirbad(struct inode *ip, doff_t offset, char *how)
{
	g_bad++;		/* a read-only mount: printf only */
}

static struct m_ext2fs		fs;
static struct inode		ino;
static struct vnode		vn;
static struct componentname	cn;
static struct ext2fs_searchslot	ss;

int
main(void)
{
	char *data, *name;
	int found = 0, off0, eoff;
	doff_t prevoff = 0, enduseful = 0, i0;
	size_t namelen;

	fs.e2fs_bsize = BSIZE;
	fs.e2fs.e2fs_icount = nondet_uint();
	ino.i_e2fs = &fs;
	ino.i_vnode = &vn;
	vn.v_data = &ino;
	data = malloc(AROUND, M_TEMP, M_WAITOK);	/* arbitrary */
	g_data = data;
	namelen = nondet_ulong();
	__CPROVER_assume(namelen >= 1 && namelen <= NAMEMAX);
	name = malloc(namelen, M_TEMP, M_WAITOK);
	cn.cn_nameptr = name;
	cn.cn_namelen = namelen;
	ss.slotstatus = nondet_int();
	__CPROVER_assume(ss.slotstatus == NONE || ss.slotstatus == COMPACT ||
	    ss.slotstatus == FOUND);
	ss.slotneeded = nondet_int();
	ss.slotoffset = nondet_int();
	ss.slotfreespace = nondet_int();
	__CPROVER_assume(ss.slotneeded >= 0 && ss.slotneeded <= 1024 &&
	    ss.slotfreespace >= 0 && ss.slotfreespace <= 1024 &&
	    ss.slotoffset >= -1 && ss.slotoffset <= 1 << 20);
	off0 = nondet_int();
	__CPROVER_assume(off0 == 0);	/* ext2fs_lookup resets it per block */
	i0 = nondet_int();		/* the block's place in the directory */
	__CPROVER_assume(i0 >= 0 && i0 <= 1 << 20 && i0 % BSIZE == 0);
	ino.i_offset = i0 + off0;
	eoff = off0;

	ext2fs_search_dirblock(&ino, data, &found, &cn, &eoff, &prevoff,
	    &enduseful, &ss);

	if (found) {
		struct ext2fs_direct *ep =
		    (struct ext2fs_direct *)(data + eoff);

		__CPROVER_assert(eoff >= 0 && eoff + 8 <= BSIZE &&
		    ep->e2d_ino != 0 && ep->e2d_namlen == namelen,
		    "found: *entryoffsetinblockp is the entry found");
		__CPROVER_assert(ino.i_offset == i0 + eoff,
		    "found: i_offset is the entry's offset");
	} else
		__CPROVER_assert(ino.i_offset == i0 + BSIZE,
		    "not found: i_offset ends at the end of the block");
	free(name, M_TEMP, 0);
	free(data, M_TEMP, 0);
	return (0);
}
