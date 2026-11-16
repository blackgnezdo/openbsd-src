/*
 * Harness: bpf_validate() and then the interpreter, on a filter program
 * and a packet of arbitrary content.
 *
 * cbmc.sh defines _KERNEL, so net/bpf_filter.c contributes bpf_validate()
 * and _bpf_lfilter().  bpf_filter(), _bpf_filter() and the bpf_mem_*
 * accessors exist only in the userland copy of the file and are not
 * compiled here.  _bpf_filter() is _bpf_lfilter() with pc_len 0, so the
 * interpreter is called that way.
 *
 * The kernel's packet accessors (bpf_mbuf_ldw and friends, net/bpf.c) are
 * outside the target and are replaced by the model below.  The model has
 * their contract on one flat buffer: an access that does not lie inside
 * the packet fails with *err set, and one that does reads those bytes
 * (bpf_mbuf_copy() with a single mbuf).
 *
 * Shapes: the program is exactly len instructions, len in 1..NINSNS, all
 * fields arbitrary.  The packet is exactly buflen bytes, buflen in
 * 0..PKTMAX, arbitrary content.  Both arrays are allocated with their real
 * sizes, so a read past the end of either is reported.  wirelen is
 * arbitrary.
 *
 * NINSNS and PKTMAX are small; what they stand for: NINSNS 3 allows a
 * jump over one instruction, a store followed by a load of the scratch
 * memory, and a division by X.  PKTMAX 8 allows packet loads of 1, 2 and
 * 4 bytes at offsets up to 4 that succeed, and loads that fail.
 *
 * Termination: the loops of bpf_validate() and _bpf_lfilter() are bounded
 * by unwindset NINSNS+1 (a validated program runs at most len <= NINSNS
 * instructions, see opts); the unwinding assertion in the check run
 * proves the bound holds.
 */
#include "bpf_filter.c"
#include <sys/malloc.h>
#include "cbmc_harness.h"

#define NINSNS	4	/* largest program */
#define PKTMAX	8	/* largest packet */

/* bpf.c defines this; bpf_validate() compares load offsets with it */
int bpf_maxbufsize = BPF_MAXBUFSIZE;

/* what the accessors see: the packet bytes and their length */
struct harness_pkt {
	const u_char	*pkt;
	u_int		 len;
};

/* bpf_mbuf_copy() on one buffer: n bytes at offset k, or -1 */
static int
harness_copy(const struct harness_pkt *hp, u_int32_t k, void *buf, size_t n)
{
	if (hp->len < k)
		return -1;
	if (hp->len - k < n)
		return -1;
	memcpy(buf, hp->pkt + k, n);
	return 0;
}

static u_int32_t
harness_ldw(const void *m0, u_int32_t k, int *err)
{
	const struct harness_pkt *hp = m0;
	u_int32_t v;

	if (harness_copy(hp, k, &v, sizeof(v)) != 0) {
		*err = 1;
		return (0);
	}
	*err = 0;
	return ntohl(v);
}

static u_int32_t
harness_ldh(const void *m0, u_int32_t k, int *err)
{
	const struct harness_pkt *hp = m0;
	u_int16_t v;

	if (harness_copy(hp, k, &v, sizeof(v)) != 0) {
		*err = 1;
		return (0);
	}
	*err = 0;
	return ntohs(v);
}

static u_int32_t
harness_ldb(const void *m0, u_int32_t k, int *err)
{
	const struct harness_pkt *hp = m0;
	u_int8_t v;

	if (harness_copy(hp, k, &v, sizeof(v)) != 0) {
		*err = 1;
		return (0);
	}
	*err = 0;
	return v;
}

static const struct bpf_ops harness_ops = {
	harness_ldw,
	harness_ldh,
	harness_ldb,
};

#define NPKT	PKTMAX

int
main(void)
{
	struct bpf_insn *prog;
	struct harness_pkt hp;
	u_char *pkt;
	u_int len, buflen, wirelen, i;

	len = 1 + nondet_uint() % NINSNS;
	prog = CBMC_NEW_ARRAY(struct bpf_insn, len);	/* arbitrary content */
	for (i = 0; i < len; i++) {
		prog[i].code = nondet_ushort();
		prog[i].jt = nondet_uchar();
		prog[i].jf = nondet_uchar();
		prog[i].k = nondet_uint();
	}

	buflen = nondet_uint() % (NPKT + 1);
	pkt = CBMC_NEW_ARRAY(u_char, buflen);		/* arbitrary content */
	for (i = 0; i < buflen; i++)
		pkt[i] = nondet_uchar();
	wirelen = nondet_uint();

	if (bpf_validate(prog, len)) {
		hp.pkt = pkt;
		hp.len = buflen;
		(void)_bpf_lfilter(prog, 0, &harness_ops, &hp, wirelen);
	}

	free(pkt, M_TEMP, buflen);
	free(prog, M_TEMP, sizeof(*prog) * len);
	return (0);
}
