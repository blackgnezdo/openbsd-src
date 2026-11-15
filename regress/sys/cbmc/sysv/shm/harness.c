/*
 * Harness: NCALLS arbitrary System V shared memory system calls by one
 * process, on a segment table of SHMMNI entries.
 *
 * sysv_shm.c is included because the code under test is partly static
 * in effect (shm_* helpers are reached only through the entry points).
 *
 * State is what shminit() leaves, with small tables.  UVM is not part
 * of the model; see the model_* functions (replace file).
 *
 * Process exit is modelled by shmexit(), which uvmspace_purge() calls
 * (uvm_map.c) when vm_shm != NULL.
 */
#include "sysv_shm.c"

#define NCALLS	3
#define SHMMNI	2	/* shminfo.shmmni; the default is 128 */
#define SHMSEG	2	/* shminfo.shmseg; the default is 128 */

unsigned nondet_uint(void);
unsigned long nondet_ulong(void);
int nondet_int(void);
_Bool nondet_bool(void);

/* conf/param.c defines this; shmmax and shmall are as large as an int */
struct shminfo shminfo = {
	0x7ffff000,	/* shmmax: bytes, as after shminit()'s *= PAGE_SIZE */
	1,		/* shmmin */
	SHMMNI,
	SHMSEG,
	0x7fffffff	/* shmall: pages */
};

/*
 * uao_create: a fresh heap object with one reference.  uao_reference and
 * uao_detach count references so that the detach in the failure path of
 * sys_shmat does not free an object the segment still holds.  A
 * successful uvm_map takes over the reference shmat acquired: the model
 * drops it, as uvm_unmap is a no-op and mappings are not tracked.  The
 * last uao_detach frees the object, so a leak or a use after
 * shm_deallocate_segment is visible.
 */
struct uvm_object *
model_uao_create(vsize_t size, int flags)
{
	struct uvm_object *o;

	o = malloc(sizeof(*o), M_TEMP, M_WAITOK | M_ZERO);
	o->uo_refs = 1;
	return (o);
}

void
model_uao_detach(struct uvm_object *o)
{
	if (--o->uo_refs == 0)
		free(o, M_TEMP, sizeof(*o));
}

void
model_uao_reference(struct uvm_object *o)
{
	o->uo_refs++;
}

/* fails with ENOMEM, or maps at an arbitrary page-aligned address */
int
model_uvm_map(vm_map_t map, vaddr_t *addr, vsize_t sz,
    struct uvm_object *o, voff_t off, vsize_t align, unsigned int flags)
{
	if (nondet_bool())
		return (ENOMEM);
	*addr = nondet_ulong() & ~(vaddr_t)PAGE_MASK;
	o->uo_refs--;	/* the mapping now owns the reference taken by shmat */
	return (0);
}

void
model_uvm_unmap(struct vm_map *map, vaddr_t start, vaddr_t end)
{
}

/*
 * A segment and its handle share one pool item, the handle placed right
 * behind the segment.  The common pool model allocates an untyped byte
 * array, and CBMC then encodes every field access through a symbolic
 * segment pointer byte by byte, which made this target intractable.
 * Allocate the item with its real layout instead.
 */
struct shm_item {
	struct shmid_ds_kern	ds;
	struct shm_handle	handle;
};

void *
model_pool_get(struct pool *pp, int flags)
{
	struct shm_item *it;

	it = __CPROVER_allocate(sizeof(struct shm_item), 1);
	return (it);
}

int
main(void)
{
	static struct proc p;
	static struct ucred cred;
	static struct process pr;
	static struct vmspace vm;
	struct shmid_ds_kern *seg;
	register_t retval;
	int i;

	p.p_ucred = &cred;
	p.p_p = &pr;
	p.p_vmspace = &vm;

	/* shminit() */
	shm_pool.pr_size = sizeof(struct shmid_ds_kern) +
	    sizeof(struct shm_handle);
	shmsegs = malloc(SHMMNI * sizeof(struct shmid_ds_kern *),
	    M_TEMP, M_WAITOK | M_ZERO);
	shmseqs = malloc(SHMMNI * sizeof(unsigned short),
	    M_TEMP, M_WAITOK | M_ZERO);
	shm_last_free = 0;
	shm_nused = 0;
	shm_committed = 0;

	for (i = 0; i < NCALLS; i++) {
		switch (nondet_uint() % 4) {
		case 0: {
			struct sys_shmget_args a;
			SCARG(&a, key) = nondet_int();
			SCARG(&a, size) = nondet_ulong();
			SCARG(&a, shmflg) = nondet_int();
			(void)sys_shmget(&p, &a, &retval);
			break;
		}
		case 1: {
			struct sys_shmat_args a;
			SCARG(&a, shmid) = nondet_int();
			SCARG(&a, shmaddr) = (const void *)nondet_ulong();
			SCARG(&a, shmflg) = nondet_int();
			(void)sys_shmat(&p, &a, &retval);
			break;
		}
		case 2: {
			struct sys_shmdt_args a;
			SCARG(&a, shmaddr) = (const void *)nondet_ulong();
			(void)sys_shmdt(&p, &a, &retval);
			break;
		}
		default: {
			struct sys_shmctl_args a;
			SCARG(&a, shmid) = nondet_int();
			SCARG(&a, cmd) = nondet_int();
			SCARG(&a, buf) = (struct shmid_ds *)nondet_ulong();
			(void)sys_shmctl(&p, &a, &retval);
			break;
		}
		}
	}

	/* process exit: uvmspace_purge() */
	if (vm.vm_shm != NULL)
		shmexit(&vm);

	/*
	 * Segments nobody removed still exist, as in a running system;
	 * they are not leaks.  Release them here, with their object.
	 */
	for (i = 0; i < SHMMNI; i++) {
		if ((seg = shmsegs[i]) != NULL) {
			struct shm_handle *h = seg->shm_internal;

			free(h->shm_object, M_TEMP, sizeof(struct uvm_object));
			free(seg, M_TEMP, shm_pool.pr_size);
		}
	}
	free(shmsegs, M_TEMP, 0);
	free(shmseqs, M_TEMP, 0);
	return (0);
}
