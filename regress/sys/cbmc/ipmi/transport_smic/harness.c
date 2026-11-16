/*
 * Harness: one IPMI command over the SMIC interface, with a BMC that
 * answers anything.
 *
 * Sibling of ipmi/transport_bt, same contract, same split: ioctl/ipmi
 * assumes what is asserted here.
 *
 * Contract of ipmi_cmd() towards its callers: c_data points to a buffer
 * of c_maxrxlen bytes, of which the first c_txlen are the request.  On
 * return at most c_maxrxlen bytes have been stored there, and unless
 * c_ccode is -1 (failure), 0 <= c_rxlen <= c_maxrxlen.
 * Hardware contract: every register read returns an arbitrary byte and
 * a wait for a flag either fails or returns an arbitrary status.
 *
 * smic_recvmsg stores the reply in sc_buf, which is IPMI_MAX_RX + 16
 * bytes; ipmi_recvcmd lends it c_maxrxlen + IPMI_MSG_DATARCV of them.
 * A store past that is the finding: it is asserted on a byte of sc_buf
 * chosen by the checker (no store beyond the lent part), which needs a
 * loop bound of a few more than the lent part and not the 1040 bytes
 * of the real buffer.  The loops of smic_sendmsg and smic_recvmsg are
 * checked for termination with the unwinding assertions; the loops of
 * the real bmc_io_wait (5000000 reads, then failure) are modelled.
 *
 * Bounds: buffers of 1 to 16 bytes (callers use up to IPMI_MAX_RX).
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
	u_int8_t v = nondet_u8();

	/*
	 * Still any value.  The second choice only biases the native
	 * engine's draw towards the status codes 0xc0-0xc7, so that a
	 * fuzzer reaches a complete exchange; cbmc sees no difference.
	 */
	if (offset == _SMIC_CTRL_REG && (nondet_u8() & 1))
		v = 0xc0 | (v & 7);
	return (v);
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
	unsigned k = nondet_uint() % sizeof(softc.sc_buf);

	softc.sc_if = &smic_if;

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
	/* sc_buf starts zero: a byte beyond the lent part is a stray store */
	__CPROVER_assert(k < maxrx + IPMI_MSG_DATARCV || softc.sc_buf[k] == 0,
	    "contract: no store into sc_buf beyond c_maxrxlen + datarcv");
	free(c.c_data, M_TEMP, maxrx);
	return (0);
}
