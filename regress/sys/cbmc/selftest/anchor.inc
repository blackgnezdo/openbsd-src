/* must_reach anchor, see run.sh; "if" makes it start a coverage block */
if (sizeof(int) > 1) {
	volatile int st_anchor = 1;
}
