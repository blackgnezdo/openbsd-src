/*
 * Harness: the AML decoding primitives on a truncated byte stream.
 *
 * A scope covers [pos, end) of the AML in a table copy that is exactly
 * hdr.length bytes long (see acpi/madt).  Each primitive is started at an
 * arbitrary position inside the scope.
 */
#include "dsdt.c"

#define MAXLEN	10

unsigned nondet_uint(void);

int
main(void)
{
	struct aml_scope scope;
	struct aml_value val;
	uint8_t *buf;
	size_t len;
	static const char args[] = { AML_ARG_BYTE, AML_ARG_WORD,
	    AML_ARG_DWORD, AML_ARG_QWORD };

	len = 1 + nondet_uint() % MAXLEN;
	buf = malloc(len, M_ACPI, M_WAITOK);		/* arbitrary content */

	memset(&scope, 0, sizeof(scope));
	memset(&val, 0, sizeof(val));
	scope.pos = buf + nondet_uint() % len;
	scope.end = buf + len;

	switch (nondet_uint() % 3) {
	case 0:
		(void)aml_parseopcode(&scope);
		break;
	case 1:
		(void)aml_parseend(&scope);
		break;
	case 2:
		(void)aml_parsesimple(&scope, args[nondet_uint() % 4], &val);
		break;
	}
	free(buf, M_ACPI, len);
	return (0);
}
