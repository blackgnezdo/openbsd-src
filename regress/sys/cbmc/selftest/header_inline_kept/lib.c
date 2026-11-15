/* Includes the header, so hdr_add belongs to this object, not the harness. */
#include "hdr.h"

int
wrap_add(int a, int b)
{
	return hdr_add(a, b);
}
