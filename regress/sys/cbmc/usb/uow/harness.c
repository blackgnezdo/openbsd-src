/* Harness: attach a uow (DS2490) device, then unplug it.  Built with kernel headers. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <machine/bus.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>

usbd_status nondet_status(void);

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

void uow_attach(struct device *, struct device *, void *);
int uow_detach(struct device *, int);
extern const struct cfattach uow_ca;

int main(void)
{
	static struct usbd_bus bus;
	static struct usbd_device dev;
	static struct usbd_interface iface;
	static usb_config_descriptor_t cdesc;
	static usb_interface_descriptor_t idesc;
	static usb_endpoint_descriptor_t edesc[3];
	static struct usbd_endpoint ep[3];
	struct usb_attach_arg uaa;
	struct device *self;
	int i;

	bus.methods = &hc_bus_methods;
	bus.pipe_size = sizeof(struct usbd_pipe);
	dev.bus = &bus;
	dev.cdesc = &cdesc;
	dev.ifaces = &iface;
	cdesc.bNumInterfaces = 1;

	/*
	 * The DS2490 interface has three endpoints that uow_attach looks for:
	 * bulk-in, bulk-out and interrupt-in.  Addresses are distinct so the
	 * lookup in usbd_open_pipe_ival finds the intended endpoint.
	 */
	edesc[0].bEndpointAddress = 0x81;		/* IN */
	edesc[0].bmAttributes = UE_BULK;
	edesc[1].bEndpointAddress = 0x02;		/* OUT */
	edesc[1].bmAttributes = UE_BULK;
	edesc[2].bEndpointAddress = 0x83;		/* IN */
	edesc[2].bmAttributes = UE_INTERRUPT;
	for (i = 0; i < 3; i++) {
		ep[i].edesc = &edesc[i];
		edesc[i].wMaxPacketSize[0] = 8;
	}
	idesc.bNumEndpoints = 3;
	iface.device = &dev;
	iface.idesc = &idesc;
	iface.endpoints = ep;
	LIST_INIT(&iface.pipes);

	uaa.device = &dev;
	uaa.iface = &iface;

	/* autoconf allocates a zeroed softc of ca_devsize */
	self = malloc(uow_ca.ca_devsize, M_DEVBUF, M_WAITOK | M_ZERO);

	uow_attach(NULL, self, &uaa);
	uow_detach(self, 0);		/* unplug */
	return 0;
}
