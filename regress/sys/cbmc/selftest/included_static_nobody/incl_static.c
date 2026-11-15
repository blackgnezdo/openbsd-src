/*
 * "Kernel file" for included_static*: the harness includes it to reach
 * the static function.  The unique name matters: included files are
 * staged by basename and found through -I.
 */
static int
st_twice(int x)
{
	return 2 * x;
}
