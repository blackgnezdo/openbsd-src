/*
 * Harness: one semop(2) call by a process, on a semaphore table with one
 * set, while another process may change or remove the set during the
 * sleep that sys_semop() does when it must wait.
 *
 * sys_semop() and the helpers it calls for undo bookkeeping are analysed;
 * sleeping (tsleep_nsec) and reference counting (refcnt_*, kern/kern_synch.c)
 * are replaced by models here.  The refcnt models are plain counters with
 * the KASSERTs of kern_synch.c.
 *
 * Sizes, and what they stand for:
 *   seminfo.semmni = 2	two semaphore identifiers; set 0 is used, 1 stays free
 *   NSEMS = 2		semaphores in the set
 *   seminfo.semopm = 2	operations per semop(2) call (loop bound); 3 gave
 *			SAT problems beyond the time limit
 *   SEMUME = 1		undo entries per process (defined before the include,
 *			sem.h only defaults it); with 2 operations this makes
 *			the "too many undo entries" rollback reachable
 *   seminfo.semmnu = 2	undo structures in the system
 *
 * Environment bound: the sleep model is called at most 3 times per run.
 * The first two calls may change the set, remove it, or return 0 (woken
 * up); the third and later calls return EINTR.  This bounds the environment
 * (other processes), not the code under test.
 *
 * Arguments are arbitrary: semid, sops (a user address, never dereferenced)
 * and nsops.  ipcperm() is not modelled: its body is removed, so it returns
 * an arbitrary value.
 */
#define SEMUME	1
#include "sysv_sem.c"
#include "cbmc_harness.h"

#define NSEMS	2


/* sysv_sem.c uses seminfo; conf/param.c defines it and is not part of this target */
struct seminfo seminfo;

static struct proc p;
static struct process pr;
static struct ucred cred;
static struct semid_ds_kern *set0;	/* the one set, in sema[0] */
static int set_removed;			/* the sleep model removed it */
static int sleep_calls;			/* calls to model_tsleep so far */

/*
 * Models of refcnt(9) as used by sem_ref()/sem_rele() and sys_semget().
 * The KASSERTs of kern/kern_synch.c are kept.
 */
void
model_refcnt_init(struct refcnt *r)
{
	r->r_traceidx = 0;
	r->r_refs = 1;
}

void
model_refcnt_take(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs >= 1, "refcnt_take on a released object");
	r->r_refs++;
}

int
model_refcnt_rele(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs != 0, "refcnt_rele below zero");
	r->r_refs--;
	return (r->r_refs == 0);
}

/*
 * Model of tsleep_nsec() in sys_semop(): another process runs while this
 * one sleeps.  It may leave the set alone, change the semaphore values, or
 * remove the set as sys___semctl(IPC_RMID) does.  Then it returns 0 (woken
 * up) or EINTR.
 */
int
model_tsleep(const volatile void *ident, int prio, const char *wmesg,
    uint64_t nsecs)
{
	struct semid_ds_kern *s;
	unsigned int i;

	(void)ident;
	(void)prio;
	(void)wmesg;
	(void)nsecs;

	/* bound on the environment: the third and later sleeps are interrupted */
	if (++sleep_calls > 2)
		return (EINTR);

	s = sema[0];
	switch (nondet_uint() % 3) {
	case 0:
		break;
	case 1:
		if (s != NULL)
			for (i = 0; i < s->sem_nsems; i++)
				s->sem_base[i].semval = nondet_uint();
		break;
	case 2:
		if (s != NULL) {
			sema[0] = NULL;
			set_removed = 1;
			sem_rele(s);
			semundo_clear(0, -1);
		}
		break;
	}
	return (nondet_bool() ? 0 : EINTR);
}

/* An undo structure with room for SEMUME entries, as SEMUSZ provides. */
struct semu_item {
	struct sem_undo	u;
	struct undo	more[SEMUME];
};

void *
model_pool_get(struct pool *pp, int flags)
{
	if ((flags & PR_NOWAIT) && nondet_bool())
		return (NULL);
	return (CBMC_NEW(struct semu_item));
}

int
main(void)
{
	struct sys_semop_args args;
	register_t retval = 0;
	unsigned int i;
	int error;

	/* what seminit() sets up, with small sizes */
	seminfo.semmni = 2;
	seminfo.semmns = NSEMS;
	seminfo.semmnu = 2;
	seminfo.semmsl = NSEMS;
	seminfo.semopm = 2;
	seminfo.semume = SEMUME;
	seminfo.semusz = SEMUSZ;
	seminfo.semvmx = SEMVMX;
	seminfo.semaem = SEMAEM;

	sema_pool.pr_size = sizeof(struct semid_ds_kern);
	semu_pool.pr_size = SEMUSZ;
	/*
	 * Objects are allocated with their real types (CBMC_NEW, see the
	 * README); with the common byte-array models this target did not
	 * solve.
	 */
	sema = CBMC_NEW_ARRAY(struct semid_ds_kern *, 2);

	/* what sys_semget() does for a new set, with its arguments arbitrary */
	p.p_ucred = &cred;
	p.p_p = &pr;
	set0 = CBMC_NEW(struct semid_ds_kern);
	set0->sem_base = CBMC_NEW_ARRAY(struct sem, NSEMS);
	refcnt_init(&set0->sem_refcnt);
	set0->sem_perm.seq = nondet_uint() & 0x7fff;
	set0->sem_nsems = NSEMS;
	for (i = 0; i < NSEMS; i++)
		set0->sem_base[i].semval = nondet_uint();
	semtot += NSEMS;
	sema[0] = set0;

	/* arbitrary arguments; sops is a user address and is never dereferenced */
	SCARG(&args, semid) = nondet_int();
	SCARG(&args, sops) = (struct sembuf *)(unsigned long)nondet_ulong();
	SCARG(&args, nsops) = nondet_ulong();

	error = sys_semop(&p, &args, &retval);
	(void)error;

	/* tear down: the set if the sleep model did not remove it already */
	if (!set_removed) {
		sema[0] = NULL;
		sem_rele(set0);
	}
	/* undo structures left by a successful call; all have semid 0 */
	semundo_clear(0, -1);
	free(sema, M_SEM, seminfo.semmni * sizeof(struct semid_ds_kern *));
	return (0);
}
