/*
 * Harness: acpimadt_validate() alone on an MADT with arbitrary content.
 *
 * Contract taken from acpi_maptable(): a driver gets a copy of the table
 * that is exactly hdr.length bytes long.  Nothing guarantees that
 * hdr.length covers the fixed part of the table.
 */
/* Same headers as acpimadt.c, so that struct types match at link time. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <machine/apicvar.h>
#include <machine/cpuvar.h>
#include <machine/bus.h>
#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>
#include <dev/acpi/acpidev.h>
#include <dev/acpi/amltypes.h>
#include <dev/acpi/dsdt.h>
#include <machine/i8259.h>
#include <machine/i82093reg.h>
#include <machine/i82093var.h>
#include <machine/i82489reg.h>
#include <machine/i82489var.h>
#include <machine/mpbiosvar.h>
#include "ioapic.h"

#define MAXLEN	(sizeof(struct acpi_madt) + 20)
/*
 * CBMC treats entry->field as an access to the whole union, so a record
 * shorter than the union at the end of the table is reported even when
 * the field is in bounds.  SLACK bytes after the table avoid that; the
 * price is that an overrun of up to SLACK bytes goes unnoticed.
 */
#define SLACK	(sizeof(union acpi_madt_entry) - 2)

unsigned nondet_uint(void);
_Bool nondet_bool(void);

int acpimadt_validate(struct acpi_madt *);

int
main(void)
{
	struct acpi_madt *madt;
	size_t len;

	len = sizeof(struct acpi_table_header) +
	    nondet_uint() % (MAXLEN - sizeof(struct acpi_table_header) + 1);
	madt = malloc(len + SLACK, M_DEVBUF, M_WAITOK);		/* arbitrary content */
	madt->hdr.length = len;

	(void)acpimadt_validate(madt);
	return (0);
}
