/* Harness: attach a umcs device, then unplug it.  Built with kernel headers. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <machine/bus.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>

#define NEP	8		/* 4-port layout: endpoints 0..7 */

usbd_status nondet_status(void);
int nondet_int(void);

/* ---- host controller model ---- */
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

void umcs_attach(struct device *, struct device *, void *);
int umcs_detach(struct device *, int);
extern const struct cfattach umcs_ca;

int main(void)
{
	static struct usbd_bus bus;
	static struct usbd_device dev;
	static struct usbd_interface iface;
	static usb_interface_descriptor_t idesc;
	static usb_endpoint_descriptor_t edesc[NEP];
	static struct usbd_endpoint ep[NEP];
	struct usb_attach_arg uaa;
	struct device *self;
	int i;

	bus.methods = &hc_bus_methods;
	bus.pipe_size = sizeof(struct usbd_pipe);
	dev.bus = &bus;

	/*
	 * Endpoint 0 is the interrupt IN endpoint umcs_attach searches for.
	 * The others are bulk endpoints for the per-port ucom pipes; the
	 * driver does not check their direction or type.
	 */
	for (i = 0; i < NEP; i++) {
		if (i == 0) {
			edesc[i].bEndpointAddress = 0x81;
			edesc[i].bmAttributes = UE_INTERRUPT;
			USETW(edesc[i].wMaxPacketSize, 8);
		} else {
			edesc[i].bEndpointAddress =
			    (i & 1) ? (uint8_t)i : (uint8_t)(0x80 | i);
			edesc[i].bmAttributes = UE_BULK;
			USETW(edesc[i].wMaxPacketSize, 64);
		}
		ep[i].edesc = &edesc[i];
	}
	idesc.bNumEndpoints = NEP;
	iface.device = &dev;
	iface.idesc = &idesc;
	iface.endpoints = ep;
	LIST_INIT(&iface.pipes);

	uaa.device = &dev;
	uaa.iface = &iface;
	uaa.product = nondet_int();

	/* autoconf allocates a zeroed softc of ca_devsize */
	self = malloc(umcs_ca.ca_devsize, M_DEVBUF, M_WAITOK | M_ZERO);

	umcs_attach(NULL, self, &uaa);
	umcs_detach(self, 0);		/* unplug */
	return 0;
}
