/*
 * Harness: build a zeroed ubcmtp softc by hand (no attach), then run the
 * trackpad/button pipe setup and the teardown.  Built with kernel headers.
 *
 * The private types below are verbatim copies from sys/dev/usb/ubcmtp.c.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/errno.h>
#include <machine/bus.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbhid.h>
#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wsmousevar.h>

/* ---- copied from ubcmtp.c ---- */
#define UBCMTP_TYPE1		1
#define UBCMTP_TYPE1_TPOFF	(13 * sizeof(uint16_t))
#define UBCMTP_TYPE1_TPLEN	UBCMTP_TYPE1_TPOFF + UBCMTP_ALL_FINGER_SIZE
#define UBCMTP_TYPE1_TPIFACE	1
#define UBCMTP_TYPE1_BTIFACE	2

#define UBCMTP_MAX_FINGERS	16
#define UBCMTP_ALL_FINGER_SIZE	(UBCMTP_MAX_FINGERS * sizeof(struct ubcmtp_finger))

struct ubcmtp_button {
	uint8_t		unused;
	uint8_t		button;
	uint8_t		rel_x;
	uint8_t		rel_y;
};

struct ubcmtp_finger {
	uint16_t	origin;
	uint16_t	abs_x;
	uint16_t	abs_y;
	uint16_t	rel_x;
	uint16_t	rel_y;
	uint16_t	tool_major;
	uint16_t	tool_minor;
	uint16_t	orientation;
	uint16_t	touch_major;
	uint16_t	touch_minor;
	uint16_t	unused[2];
	uint16_t	pressure;
	uint16_t	multi;
} __packed __attribute((aligned(2)));

struct ubcmtp_limit {
	int limit;
	int min;
	int max;
};

struct ubcmtp_dev {
	int vendor;			/* vendor */
	int ansi, iso, jis;		/* 3 types of product */
	int type;			/* 1 (normal) or 2 (integrated btn) */
	struct ubcmtp_limit l_pressure;	/* finger pressure */
	struct ubcmtp_limit l_width;	/* finger width */
	struct ubcmtp_limit l_x;
	struct ubcmtp_limit l_y;
	struct ubcmtp_limit l_orientation;
};

struct ubcmtp_softc {
	struct device		sc_dev;		/* base device */

	const struct ubcmtp_dev	*dev_type;

	struct usbd_device	*sc_udev;
	struct device		*sc_wsmousedev;

	struct usbd_interface	*sc_tp_iface;	/* trackpad interface */
	struct usbd_pipe	*sc_tp_pipe;	/* trackpad pipe */
	int			sc_tp_epaddr;	/* endpoint addr */
	int			tp_maxlen;	/* max size of tp data */
	int			tp_offset;	/* finger offset into data */
	int			tp_fingerpad;	/* padding between finger data */
	uint8_t			*tp_pkt;

	struct usbd_interface	*sc_bt_iface;	/* button interface */
	struct usbd_pipe	*sc_bt_pipe;	/* button pipe */
	int			sc_bt_epaddr;	/* endpoint addr */
	int			bt_maxlen;	/* max size of button data */
	uint8_t			*bt_pkt;

	uint32_t		sc_status;
#define UBCMTP_ENABLED		1

	struct mtpoint		frame[UBCMTP_MAX_FINGERS];
	int			contacts;
	int			btn;
};

int	ubcmtp_setup_pipes(struct ubcmtp_softc *);
void	ubcmtp_disable(void *);

/* ---- host controller model ---- */
usbd_status nondet_status(void);
uint8_t nondet_u8(void);

static void hc_pipe_close(struct usbd_pipe *p) { }
static const struct usbd_pipe_methods hc_pipe_methods = {
	.close = hc_pipe_close,
};
static usbd_status hc_open_pipe(struct usbd_pipe *p)
{
	usbd_status err = nondet_status();
	if (err)
		return err;
	p->methods = &hc_pipe_methods;
	return USBD_NORMAL_COMPLETION;
}
static struct usbd_xfer *hc_allocx(struct usbd_bus *bus)
{
	return malloc(sizeof(struct usbd_xfer), M_USB, M_NOWAIT | M_ZERO);
}
static void hc_freex(struct usbd_bus *bus, struct usbd_xfer *xfer)
{
	free(xfer, M_USB, sizeof(*xfer));
}
static const struct usbd_bus_methods hc_bus_methods = {
	.open_pipe = hc_open_pipe,
	.allocx = hc_allocx,
	.freex = hc_freex,
};

int main(void)
{
	static struct usbd_bus bus;
	static struct usbd_device dev;
	static struct usbd_interface bt_iface, tp_iface;
	static usb_interface_descriptor_t bt_idesc, tp_idesc;
	static usb_endpoint_descriptor_t bt_edesc, tp_edesc;
	static struct usbd_endpoint bt_ep, tp_ep;
	static struct ubcmtp_dev devtype;
	static struct ubcmtp_softc sc;	/* zeroed: no attach */

	bus.methods = &hc_bus_methods;
	bus.pipe_size = sizeof(struct usbd_pipe);
	dev.bus = &bus;

	/* device-controlled endpoint addresses */
	bt_edesc.bEndpointAddress = nondet_u8();
	tp_edesc.bEndpointAddress = nondet_u8();
	bt_ep.edesc = &bt_edesc;
	tp_ep.edesc = &tp_edesc;
	bt_idesc.bNumEndpoints = 1;
	tp_idesc.bNumEndpoints = 1;

	bt_iface.device = &dev;
	bt_iface.idesc = &bt_idesc;
	bt_iface.endpoints = &bt_ep;
	LIST_INIT(&bt_iface.pipes);

	tp_iface.device = &dev;
	tp_iface.idesc = &tp_idesc;
	tp_iface.endpoints = &tp_ep;
	LIST_INIT(&tp_iface.pipes);

	/* fields ubcmtp_setup_pipes() and ubcmtp_disable() read */
	devtype.type = UBCMTP_TYPE1;
	sc.dev_type = &devtype;
	sc.sc_udev = &dev;
	sc.sc_tp_iface = &tp_iface;
	sc.sc_bt_iface = &bt_iface;
	sc.tp_maxlen = UBCMTP_TYPE1_TPLEN;
	sc.tp_offset = UBCMTP_TYPE1_TPOFF;
	sc.bt_maxlen = sizeof(struct ubcmtp_button);

	/* what ubcmtp_enable() does on success */
	if (ubcmtp_setup_pipes(&sc) == 0)
		sc.sc_status |= UBCMTP_ENABLED;

	ubcmtp_disable(&sc);		/* unplug / close */
	return 0;
}
