/*
 * Harness: two arbitrary ioctl(2) calls on /dev/ipmi.
 *
 * ioctl contract, from sys_ioctl(): the handler gets a kernel buffer of
 * exactly IOCPARM_LEN(cmd) bytes whose content comes from the user.
 * Pointers inside that buffer are user addresses: arbitrary values that
 * must only reach copyin/copyout (common/stubs_user.c).
 *
 * This is the ioctl half of an assume/guarantee split.  ipmi_cmd() is
 * replaced by a model that does what ipmi/transport_bt shows the real
 * one to guarantee: it stores at most c_maxrxlen bytes in c_data and
 * leaves either c_ccode == -1 or 0 <= c_rxlen <= c_maxrxlen.
 */
#include "ipmi.c"

#define NCALLS	2

unsigned long nondet_ulong(void);
int nondet_int(void);
uint8_t nondet_u8(void);

int cold = 1;
const char *panicstr;

static struct ipmi_softc softc;

struct ipmi_softc *
model_ipmilookup(dev_t dev)
{
	return (&softc);
}

void
model_ipmi_cmd(struct ipmi_cmd *c)
{
	int n = nondet_int();

	if (c->c_maxrxlen > 0)
		__CPROVER_havoc_slice(c->c_data, c->c_maxrxlen);
	if (nondet_int() < 0) {
		c->c_ccode = -1;
		c->c_rxlen = nondet_int();	/* unspecified on failure */
	} else {
		c->c_ccode = nondet_u8();
		c->c_rxlen = (n < 0 || n > c->c_maxrxlen) ? 0 : n;
	}
}

int
main(void)
{
	struct ipmi_cmd *c = &softc.sc_ioctl.cmd;
	int i;

	/* what ipmi_attach_common() sets up */
	softc.sc_ioctl.req.msgid = -1;
	c->c_sc = &softc;
	c->c_ccode = -1;

	for (i = 0; i < NCALLS; i++) {
		u_long cmd = nondet_ulong();
		u_int size = IOCPARM_LEN(cmd);
		caddr_t data;

		data = malloc(size ? size : 1, M_TEMP, M_WAITOK);
		(void)ipmiioctl(0, cmd, data, nondet_int(), NULL);
		free(data, M_TEMP, size);
	}
	return (0);
}
