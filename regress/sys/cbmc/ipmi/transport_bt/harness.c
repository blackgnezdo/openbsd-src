/*
 * Harness: one IPMI command over the BT interface, with a BMC that
 * answers anything.
 *
 * This is the transport half of an assume/guarantee split; ioctl/ipmi is
 * the other half and assumes what is asserted here.
 *
 * Contract of ipmi_cmd() towards its callers: c_data points to a buffer
 * of c_maxrxlen bytes, of which the first c_txlen are the request.  On
 * return at most c_maxrxlen bytes have been stored there, and unless
 * c_ccode is -1 (failure), 0 <= c_rxlen <= c_maxrxlen.
 * Hardware contract: every register read returns an arbitrary byte.
 */
#include "ipmi.c"

#define MAXBUF	16	/* callers use buffers from 1 byte to IPMI_MAX_RX */

unsigned nondet_uint(void);
unsigned long nondet_ulong(void);
int nondet_int(void);
uint8_t nondet_u8(void);

int cold = 1;
const char *panicstr;

u_int8_t
model_bmc_read(struct ipmi_softc *sc, int offset)
{
	return (nondet_u8());
}

void
model_bmc_write(struct ipmi_softc *sc, int offset, u_int8_t val)
{
}

int
model_bmc_io_wait(struct ipmi_softc *sc, struct ipmi_iowait *a)
{
	int v = nondet_int();

	return (v < 0 ? -1 : (v & 0xff));
}

int
main(void)
{
	static struct ipmi_softc softc;
	struct ipmi_cmd c;
	int maxrx = 1 + nondet_uint() % MAXBUF;

	softc.sc_if = &bt_if;

	memset(&c, 0, sizeof(c));
	c.c_sc = &softc;
	c.c_rssa = BMC_SA;
	c.c_netfn = nondet_u8();
	c.c_cmd = nondet_u8();
	c.c_data = malloc(maxrx, M_TEMP, M_WAITOK);
	c.c_maxrxlen = maxrx;
	c.c_txlen = nondet_uint() % (maxrx + 1);

	ipmi_cmd(&c);

	/* c_ccode is -1 when the exchange failed; c_rxlen is then unused */
	__CPROVER_assert(c.c_ccode == -1 ||
	    (c.c_rxlen >= 0 && c.c_rxlen <= maxrx),
	    "contract: 0 <= c_rxlen <= c_maxrxlen on success");
	free(c.c_data, M_TEMP, maxrx);
	return (0);
}
