/*
 * Harness: iterate over a UDF directory whose contents are arbitrary.
 *
 * udf_opendir/udf_getfid/udf_closedir are static, so the driver file is
 * included here instead of being compiled on its own.
 */
#include "udf_vnops.c"

#define BSIZE	48		/* logical block size of the mounted volume */
#define MAXEXT	64			/* largest extent udf_readatoffset returns */
#define NFIDS	3		/* directory entries fetched before closing */

int nondet_int(void);
unsigned nondet_uint(void);
_Bool nondet_bool(void);

struct pool udf_ds_pool;
static uint8_t *embedded;	/* file entry with embedded data */

/*
 * Model of udf_readatoffset() (see the replace file): fails, or hands out an extent of
 * 0..MAXEXT bytes of arbitrary content.  The extent either belongs to
 * a buffer that must be released with brelse(), or (data embedded in
 * the file entry) to no buffer at all.
 *
 * Assumed contract: on success *data is valid for *size bytes.
 */
int
model_readatoffset(struct unode *up, int *size, off_t offset,
    struct buf **bp, uint8_t **data)
{
	struct buf *b;
	int n = nondet_uint() % (MAXEXT + 1);

	*bp = NULL;
	if (nondet_bool()) {
		/* "note: *bp may be non-NULL" on error */
		if (nondet_bool()) {
			b = malloc(sizeof(*b), M_TEMP, M_WAITOK | M_ZERO);
			b->b_data = malloc(1, M_TEMP, M_WAITOK);
			*bp = b;
		}
		return (EIO);
	}
	if (nondet_bool()) {
		*data = embedded;
	} else {
		b = malloc(sizeof(*b), M_TEMP, M_WAITOK | M_ZERO);
		b->b_data = malloc(n ? n : 1, M_TEMP, M_WAITOK);
		*bp = b;
		*data = (uint8_t *)b->b_data;
	}
	*size = n;
	return (0);
}

void
model_brelse(struct buf *bp)
{
	free(bp->b_data, M_TEMP, 0);
	free(bp, M_TEMP, sizeof(*bp));
}

int
main(void)
{
	static struct umount ump;
	static struct unode up;
	struct udf_dirstream *ds;
	struct fileid_desc *fid;
	uint8_t sink;
	int i, total;

	udf_ds_pool.pr_size = sizeof(struct udf_dirstream);
	embedded = malloc(MAXEXT, M_TEMP, M_WAITOK);	/* arbitrary content */
	ump.um_bsize = BSIZE;
	up.u_ump = &ump;

	/* offset comes from the caller's uio, fsize from the file entry */
	ds = udf_opendir(&up, nondet_int(), nondet_int(), &ump);

	for (i = 0; i < NFIDS; i++) {
		if ((fid = udf_getfid(ds)) == NULL)
			break;
		/*
		 * What udf_readdir and udf_lookup do with a FID: read the
		 * fixed part, then the name that follows the
		 * implementation use area.
		 */
		total = UDF_FID_SIZE + letoh16(fid->l_iu) + fid->l_fi;
		sink = fid->file_char;
		sink = ((uint8_t *)fid)[total - 1];
		if (nondet_bool())
			break;		/* callers may stop early */
	}
	udf_closedir(ds);
	free(embedded, M_TEMP, MAXEXT);
	return (0);
}
