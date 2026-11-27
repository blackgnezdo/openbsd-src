/* GENERATED from udf_vfsops.c before 9a103f788: udf_vget renamed old_udf_vget */
int
old_udf_vget(struct mount *mp, ino_t ino, struct vnode **vpp)
{
	struct buf *bp;
	struct vnode *devvp;
	struct umount *ump;
	struct proc *p;
	struct vnode *vp;
	struct unode *up;
	struct extfile_entry *xfe;
	struct file_entry *fe;
	uint32_t sector;
	int error, size;

	if (ino > (udfino_t)-1)
		panic("udf_vget: alien ino_t %llu", (unsigned long long)ino);

	p = curproc;
	bp = NULL;
	*vpp = NULL;
	ump = VFSTOUDFFS(mp);

	/* See if we already have this in the cache */
	if ((error = udf_hashlookup(ump, ino, LK_EXCLUSIVE, vpp)) != 0)
		return (error);
	if (*vpp != NULL)
		return (0);

	/*
	 * Allocate memory and check the tag id's before grabbing a new
	 * vnode, since it's hard to roll back if there is a problem.
	 */
	up = pool_get(&unode_pool, PR_WAITOK | PR_ZERO);

	/*
	 * Copy in the file entry.  Per the spec, the size can only be 1 block.
	 */
	sector = ino;
	devvp = ump->um_devvp;
	udf_vat_map(ump, &sector);
	if ((error = RDSECTOR(devvp, sector, ump->um_bsize, &bp)) != 0) {
		printf("Cannot read sector %d\n", sector);
		pool_put(&unode_pool, up);
		if (bp != NULL)
			brelse(bp);
		return (error);
	}

	xfe = (struct extfile_entry *)bp->b_data;
	fe = (struct file_entry *)bp->b_data;
	error = udf_checktag(&xfe->tag, TAGID_EXTFENTRY);
	if (error == 0) {
		size = letoh32(xfe->l_ea) + letoh32(xfe->l_ad);
	} else {
		error = udf_checktag(&fe->tag, TAGID_FENTRY);
		if (error) {
			printf("Invalid file entry!\n");
			pool_put(&unode_pool, up);
			if (bp != NULL)
				brelse(bp);
			return (ENOMEM);
		} else
			size = letoh32(fe->l_ea) + letoh32(fe->l_ad);
	}

	/* Allocate max size of FE/XFE. */
	up->u_fentry = malloc(size + UDF_EXTFENTRY_SIZE, M_UDFFENTRY, M_NOWAIT | M_ZERO);
	if (up->u_fentry == NULL) {
		pool_put(&unode_pool, up);
		if (bp != NULL)
			brelse(bp);
		return (ENOMEM); /* Cannot allocate file entry block */
	}

	if (udf_checktag(&xfe->tag, TAGID_EXTFENTRY) == 0)
		bcopy(bp->b_data, up->u_fentry, size + UDF_EXTFENTRY_SIZE);
	else
		bcopy(bp->b_data, up->u_fentry, size + UDF_FENTRY_SIZE);
	
	brelse(bp);
	bp = NULL;

	if ((error = udf_allocv(mp, &vp, p))) {
		free(up->u_fentry, M_UDFFENTRY, 0);
		pool_put(&unode_pool, up);
		return (error); /* Error from udf_allocv() */
	}

	up->u_vnode = vp;
	up->u_ino = ino;
	up->u_devvp = ump->um_devvp;
	up->u_dev = ump->um_dev;
	up->u_ump = ump;
	vp->v_data = up;
	vref(ump->um_devvp);

	rrw_init_flags(&up->u_lock, "unode", RWL_DUPOK | RWL_IS_VNODE);

	/*
	 * udf_hashins() will lock the vnode for us.
	 */
	udf_hashins(up);

	switch (up->u_fentry->icbtag.file_type) {
	default:
		printf("Unrecognized file type (%d)\n", vp->v_type);
		vp->v_type = VREG;
		break;
	case UDF_ICB_FILETYPE_DIRECTORY:
		vp->v_type = VDIR;
		break;
	case UDF_ICB_FILETYPE_BLOCKDEVICE:
		vp->v_type = VBLK;
		break;
	case UDF_ICB_FILETYPE_CHARDEVICE:
		vp->v_type = VCHR;
		break;
	case UDF_ICB_FILETYPE_FIFO:
		vp->v_type = VFIFO;
		break;
	case UDF_ICB_FILETYPE_SOCKET:
		vp->v_type = VSOCK;
		break;
	case UDF_ICB_FILETYPE_SYMLINK:
		vp->v_type = VLNK;
		break;
	case UDF_ICB_FILETYPE_RANDOMACCESS:
	case UDF_ICB_FILETYPE_REALTIME:
	case UDF_ICB_FILETYPE_UNKNOWN:
		vp->v_type = VREG;
		break;
	}

	/* check if this is a vnode alias */
	checkalias(vp, up->u_dev);

	*vpp = vp;

	return (0);
}
