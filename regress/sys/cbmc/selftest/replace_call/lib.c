/* h() calls g(), which has no body anywhere: replace must redirect it. */
int g(void);

int
h(void)
{
	return g() + 100;
}
