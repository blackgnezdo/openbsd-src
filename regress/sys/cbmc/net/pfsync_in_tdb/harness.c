/*
 * Harness: pfsync_in_tdb() and pfsync_update_net_tdb() of
 * sys/net/if_pfsync.c, compiled with IPSEC, on a message buffer the peer
 * controls, against the real gettdb_dir()/tdb_ref()/tdb_unref() of
 * sys/netinet/ip_ipsp.c.  Both files are #included (static functions,
 * the static tdb hash table the harness seeds).
 *
 * Configuration: config(8) would define IPSEC for the kernel compile;
 * cbmc.sh cannot pass -D, so it is defined here, before the includes
 * (as net/rtm_xaddrs does for INET6).
 *
 * Caller guarantee (net/pfsync_input, sys/net/if_pfsync.c pfsync_input
 * ~2687-2740): in(sc, buf, mlen, count) with buf readable for
 * mlen * count contiguous bytes, mlen a multiple of 4 and at least
 * sizeof(struct pfsync_tdb) (52, packed), count from the peer.  Nothing
 * else about the content is checked: every byte is the peer's.
 *
 * Buffer: an object of exactly mlen * count bytes, every byte arbitrary,
 * the data ending where the object ends (a read past the last message
 * is out of bounds).  count 1..2; mlen 52 (the struct size) or 56 (a
 * peer may send larger messages).  Sizes are small constants per case.
 *
 * Table: the kernel's tdbh[] has TDB_HASHSIZE_INIT (32) buckets; here
 * tdb_hashmask is 0 and the model of tdb_hash returns 0, one bucket,
 * holding none or one tdb (the table's own reference, r_refs 1).  When
 * present, the tdb's key (spi, sproto, rdomain, dst) either equals the
 * one of a message chosen by the harness or is arbitrary, so that both
 * the miss and the update path run; tdb_rpl and tdb_cur_bytes are
 * arbitrary (below 2^63: only compared).
 *
 * Models (replace file):
 *   tdb_hash	what the real one reads, asserted, in place of SipHash:
 *		the SPI is not reserved (ntohl(spi) > SPI_RESERVED_MAX) and
 *		the family is AF_INET or AF_INET6 (what pfsync_update_net_tdb
 *		validates), and dst is readable for dst->sa.sa_len bytes
 *		(SipHash24_Update(&ctx, dst, dst->sa.sa_len)), the same
 *		bytes gettdb_dir's memcmp reads; the read stays inside the
 *		message dst belongs to.  Returns 0 (hash mask 0).
 *   refcnt_take, refcnt_rele	count r_refs; rele asserts one is held.
 *   tdb_free	asserts it is not reached: the table holds a reference.
 *   mtx_enter, mtx_leave	track mtx_owner (as netinet/igmp_input).
 *   rw_status	the net lock is held (NET_ASSERT_LOCKED).
 * No body (NOBODY line): splassert_fail (only called when the net lock
 * is not held, which the model rules out), counters (statistics).
 *
 * Properties: no out-of-bounds access in or past the buffer, the bytes
 * hashed and compared lie within the message, the lookup is made only
 * with a valid SPI and family, the tdb's reference is dropped (r_refs back
 * to 1), the mutexes are balanced, tdb_rpl and tdb_cur_bytes never
 * decrease, and an update stores the message's values only when neither
 * would decrease.
 */
#define IPSEC	1
#include "cbmc_harness.h"
#include "if_pfsync.c"
#include "ip_ipsp.c"

/* CBMC's free for objects of CBMC_NEW (kernel free(9) is kfree here) */
#undef free
void free(void *);
#define free kfree

static char *g_buf;
static unsigned int g_mlen;

void
model_refcnt_take(struct refcnt *r)
{
	r->r_refs++;
}

int
model_refcnt_rele(struct refcnt *r)
{
	__CPROVER_assert(r->r_refs > 0, "refcnt_rele: reference held");
	r->r_refs--;
	return (r->r_refs == 0);
}

void
model_tdb_free(struct tdb *tdb)
{
	__CPROVER_assert(0, "tdb_free: the last reference was dropped");
}

void
model_mtx_enter(struct mutex *mtx)
{
	__CPROVER_assert(mtx->mtx_owner == 0, "mtx_enter: not held");
	mtx->mtx_owner = mtx_curcpu();
}

void
model_mtx_leave(struct mutex *mtx)
{
	__CPROVER_assert(mtx_owner(mtx) == mtx_curcpu(), "mtx_leave: held");
	mtx->mtx_owner = 0;
}

int
model_rw_status(const struct rwlock *rwl)
{
	return (RW_WRITE);
}

int
model_tdb_hash(u_int32_t spi, union sockaddr_union *dst, u_int8_t proto)
{
	unsigned int sa_len = dst->sa.sa_len;
	unsigned int off = (char *)dst - g_buf;

	__CPROVER_assert(ntohl(spi) > SPI_RESERVED_MAX,
	    "gettdb: reserved spi");
	__CPROVER_assert(dst->sa.sa_family == AF_INET ||
	    dst->sa.sa_family == AF_INET6, "gettdb: address family");
	if (sa_len > 0)
		__CPROVER_assert(__CPROVER_r_ok(dst, sa_len),
		    "gettdb: dst readable for sa_len bytes");
	/* dst is at offset 4 of its message; count is at most 2 */
	if (off >= g_mlen)
		off -= g_mlen;
	__CPROVER_assert(off + sa_len <= g_mlen,
	    "gettdb: dst read within its message");
	return (0);
}

static void
release(void *p)
{
#undef free
	if (p != NULL)
		free(p);
#define free kfree
}

int
main(void)
{
	static struct pfsync_softc softc;
	struct pfsync_softc *sc = &softc;
	struct tdb *tdb = NULL;
	unsigned int mlen, count, i, n;
	const struct pfsync_tdb *pt;
	u_int64_t rpl0 = 0, bytes0 = 0;
	unsigned char *b;

	pf_status.running = 1;
	pfsyncif = sc;

	mlen = nondet_bool() ? sizeof(struct pfsync_tdb) :
	    sizeof(struct pfsync_tdb) + 4;
	count = nondet_bool() ? 1 : 2;
	n = mlen * count;
	/* exactly n bytes, arbitrary content, the data ends the object */
	b = (mlen == 52) ? (count == 1 ? CBMC_NEW_ARRAY(unsigned char, 52) :
	    CBMC_NEW_ARRAY(unsigned char, 104)) :
	    (count == 1 ? CBMC_NEW_ARRAY(unsigned char, 56) :
	    CBMC_NEW_ARRAY(unsigned char, 112));
	for (i = 0; i < n; i++)
		b[i] = nondet_uchar();
	g_buf = (char *)b;
	g_mlen = mlen;

	tdbh = CBMC_NEW_ARRAY(struct tdb *, 1);
	tdb_hashmask = 0;
	if (nondet_bool()) {
		tdb = CBMC_NEW(struct tdb);
		tdb->tdb_refcnt.r_refs = 1;
		tdb->tdb_rpl = nondet_u64() >> 1;
		tdb->tdb_cur_bytes = nondet_u64() >> 1;
		tdb->tdb_spi = nondet_u32();
		tdb->tdb_sproto = nondet_u8();
		tdb->tdb_rdomain = nondet_u16();
		if (nondet_bool()) {
			/* the key of a message */
			pt = (const struct pfsync_tdb *)(g_buf +
			    mlen * (count - 1 > 0 && nondet_bool() ? 1 : 0));
			tdb->tdb_spi = pt->spi;
			tdb->tdb_sproto = pt->sproto;
			tdb->tdb_rdomain = ntohs(pt->rdomain);
			memcpy(&tdb->tdb_dst, &pt->dst, sizeof(tdb->tdb_dst));
		}
		tdbh[0] = tdb;
		rpl0 = tdb->tdb_rpl;
		bytes0 = tdb->tdb_cur_bytes;
	}

	pfsync_in_tdb(sc, (const caddr_t)g_buf, mlen, count);

	if (tdb != NULL) {
		__CPROVER_assert(tdb->tdb_refcnt.r_refs == 1,
		    "tdb reference dropped");
		__CPROVER_assert(tdb->tdb_mtx.mtx_owner == 0,
		    "tdb_mtx released");
		__CPROVER_assert(tdb->tdb_rpl >= rpl0,
		    "tdb_rpl did not decrease");
		__CPROVER_assert(tdb->tdb_cur_bytes >= bytes0,
		    "tdb_cur_bytes did not decrease");
	}
	__CPROVER_assert(tdb_sadb_mtx.mtx_owner == 0, "tdb_sadb_mtx released");
	release(tdb);
	release(tdbh);
	release(b);
	return (0);
}
