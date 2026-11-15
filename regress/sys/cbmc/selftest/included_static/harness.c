/*
 * A static function of an included file is callable from the harness,
 * and keeps its body when listed in keep.
 */
#include <incl_static.c>

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(st_twice(21) == 42, "st_twice(21) == 42");
	return (0);
}
