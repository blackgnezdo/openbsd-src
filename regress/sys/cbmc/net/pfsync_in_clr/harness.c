/*
 * Harness: pfsync_in_clr() of sys/net/if_pfsync.c (static, so the file is
 * #included), the CLR handler that net/pfsync_input calls as
 * in(sc, buf, mlen, count).  Per message: an empty ifname clears every
 * state of clr->creatorid; otherwise pfi_kif_find(clr->ifname) (real,
 * pf_if.c: strlcpy of the 16 byte name, which the peer may send without a
 * NUL, into s.pfik_name, then RB_FIND) and the states of that interface.
 *
 * Framing, as net/pfsync_input proves it: count is 1..2, mlen is the
 * struct size (20) or the size plus 4 (a peer may send larger messages;
 * the choice is nondet), and buf is an object of exactly mlen * count
 * bytes with arbitrary content, the data ending where the object ends:
 * a read past the last message is out of bounds.  Messages are at
 * buf + i * mlen.
 *
 * Softc: set up as pfsync_input does (pfsyncif, sc_sync_ifidx 1); the
 * handler itself does not read it.
 *
 * State list: 0..2 states, each with an arbitrary creatorid and a kif
 * that is NULL or the one interface, on pf_state_list.  Models:
 *   pfi_ifhead_RB_FIND	the tree lookup: NULL or the one kif (the key
 *			is not compared)
 *   pf_remove_state	asserts the state is on pf_state_list and marks it
 *			PFTM_UNLINKED, as pf.c does; the state stays on the
 *			list (pf_free_state takes it off, later), so the
 *			head and tail the handler holds stay valid
 * Locks (rw_enter_read, rw_exit_read, mtx_enter, mtx_leave, PF_LOCK,
 * PF_STATE_ENTER_WRITE and their exits, the rw_status assertions) have
 * no body: they protect nothing the handler reads in a way this harness
 * could see other threads change.  Not modelled, no body (NOBODY line):
 * splassert_fail, reached only through a failing lock assertion;
 * counters_inc (pfsyncstat_inc, statistics).
 *
 * Properties: no out-of-bounds access, in the buffer or past it, no leak
 * or double free, the states the handler removes were on the list.
 */
#include "cbmc_harness.h"
#include "pfsync.h"
#include "pflog.h"
#include "kstat.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timeout.h>
#include <sys/pool.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/syslog.h>
#include <sys/specdev.h>
#include <uvm/uvm_extern.h>
#include <crypto/md5.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/hfsc.h>
#include <net/fq_codel.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <net/pfvar.h>
#include <net/pfvar_priv.h>

/* sys/net/pf.c defines the state list, which is not compiled here */
struct pf_state_list	pf_state_list;

/* CBMC's free for objects of CBMC_NEW and malloc (kernel free(9) is
 * kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

#include "if_pfsync.c"

static struct pfi_kif	*model_kif;

/* RB_FIND of pf_if.c: NULL, or the one interface */
struct pfi_kif *
model_pfi_ifhead_RB_FIND(struct pfi_ifhead *head, struct pfi_kif *key)
{
	if (nondet_bool())
		return (NULL);
	return (model_kif);
}

/* pf_remove_state: the state must be on the list; it is marked unlinked */
void
model_pf_remove_state(struct pf_state *st)
{
	struct pf_state *p;
	int listed = 0;

	TAILQ_FOREACH(p, &pf_state_list.pfs_list, entry_list) {
		if (p == st)
			listed = 1;
	}
	__CPROVER_assert(listed, "pf_remove_state: state is listed");
	st->timeout = PFTM_UNLINKED;
}

/*
 * One case per framing shape: count messages of mlen bytes, the buffer
 * a constant-size object of exactly mlen * count bytes (the constants
 * are the arguments of run_case at its call sites: a symbolic size
 * made the cover run run out of memory before the solver).
 */
static void
run_case(struct pfsync_softc *sc, unsigned int mlen, unsigned int count)
{
	unsigned char *buf;
	struct pf_state *st;
	unsigned int nstates, i, n;

	n = mlen * count;
	/* arbitrary content, ending where the object ends */
	buf = CBMC_NEW_ARRAY(unsigned char, n);
	for (i = 0; i < n; i++)
		buf[i] = nondet_uchar();

	/* 0..2 states on the list */
	nstates = nondet_bool() + nondet_bool();
	for (i = 0; i < nstates; i++) {
		st = CBMC_NEW(struct pf_state);
		st->creatorid = nondet_uint();
		st->kif = nondet_bool() ? NULL : model_kif;
		TAILQ_INSERT_TAIL(&pf_state_list.pfs_list, st, entry_list);
	}

	pfsync_in_clr(sc, (caddr_t)buf, mlen, count);

	/* the states not removed are still listed: free them here */
	while ((st = TAILQ_FIRST(&pf_state_list.pfs_list)) != NULL) {
		TAILQ_REMOVE(&pf_state_list.pfs_list, st, entry_list);
		harness_release(st);
	}
	harness_release(buf);
}

int
main(void)
{
	static struct pfsync_softc softc;
	struct pfsync_softc *sc = &softc;

	pf_status.running = 1;
	sc->sc_sync_ifidx = 1;
	pfsyncif = sc;
	TAILQ_INIT(&pf_state_list.pfs_list);
	model_kif = CBMC_NEW(struct pfi_kif);

	/* 1 or 2 messages, each the struct size (20) or 24 bytes */
	if (nondet_bool()) {
		if (nondet_bool())
			run_case(sc, sizeof(struct pfsync_clr), 1);
		else
			run_case(sc, sizeof(struct pfsync_clr) + 4, 1);
	} else {
		if (nondet_bool())
			run_case(sc, sizeof(struct pfsync_clr), 2);
		else
			run_case(sc, sizeof(struct pfsync_clr) + 4, 2);
	}
	harness_release(model_kif);
	return (0);
}
