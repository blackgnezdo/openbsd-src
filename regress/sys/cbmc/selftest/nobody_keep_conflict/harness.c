/*
 * A function listed in both keep and nobody is a configuration error
 * that cbmc.sh must refuse (no RESULT line, status 2).
 */
int f(void);

int
main(void)
{
#include <anchor.inc>
	return (f());
}
