/*
 * Harness: bpe_add_addr() of sys/net/if_bpe.c on one SIOCBRDGSADDR
 * request, the path bpe_ioctl takes with the ioctl buffer.  if_bpe.c is
 * #included so that the static bpe_add_addr() is reached.
 *
 * Buffer: sys_ioctl copies IOCPARM_LEN(cmd) bytes of user data, which is
 * exactly sizeof(struct ifbareq) for SIOCBRDGSADDR (sys/sys/sockio.h).
 * ifba is an object of exactly that size.  The fields the code reads are
 * arbitrary: ifba_flags, ifba_dstsa.ss_family (AF_LINK in about half of
 * the runs), and of the sockaddr_dl laid over ifba_dstsa, sdl_type,
 * sdl_nlen and sdl_alen.  The rest stays zero.  ifba_dstsa is the last
 * member, so with sdl_nlen up to 255 the endpoint read by the code, at
 * offsetof(sdl_data) + sdl_nlen, reaches 13 bytes past the object.
 *
 * sc is a zeroed bpe_softc; only &sc->sc_eb is formed by the code.
 *
 * Model: etherbridge_add_addr() is replaced by a model with the same
 * signature (sys/net/if_etherbridge.h).  The real function stores the
 * ETHER_ADDR_LEN bytes at its port argument, which is the endpoint
 * address; the model reads those bytes, so an out-of-bounds read of
 * ifba is reported.  Its result is arbitrary; the model touches nothing
 * else.
 *
 * No postcondition: the target proves memory safety of the request path.
 * The must_reach anchors show the three returns and the call are reached.
 */
#include "if_bpe.c"
#include "cbmc_harness.h"

/*
 * Model of etherbridge_add_addr() (replace file).  Reads the endpoint's
 * ETHER_ADDR_LEN bytes at port, as the real function does, and returns
 * an arbitrary result.
 */
int
model_etherbridge_add_addr(struct etherbridge *eb, void *port,
    uint16_t vp, uint16_t vs, const struct ether_addr *ea, unsigned int type)
{
	unsigned char addr[ETHER_ADDR_LEN];

	memcpy(addr, port, ETHER_ADDR_LEN);
	(void)eb;
	(void)vp;
	(void)vs;
	(void)ea;
	(void)type;
	return (nondet_int());
}

/* CBMC's free for objects of CBMC_NEW (kernel free(9) is kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

int
main(void)
{
	struct ifbareq *ifba;
	struct bpe_softc *sc;
	struct sockaddr_dl *sdl;

	ifba = CBMC_NEW(struct ifbareq);	/* sizeof(struct ifbareq) bytes */
	sc = CBMC_NEW(struct bpe_softc);

	ifba->ifba_flags = nondet_uchar();
	ifba->ifba_dstsa.ss_family = nondet_bool() ? AF_LINK : nondet_uchar();
	sdl = (struct sockaddr_dl *)&ifba->ifba_dstsa;
	sdl->sdl_type = nondet_uchar();
	sdl->sdl_nlen = nondet_uchar();
	sdl->sdl_alen = nondet_uchar();

	(void)bpe_add_addr(sc, ifba);

	harness_release(ifba);
	harness_release(sc);
	return (0);
}
