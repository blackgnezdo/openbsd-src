# Brief template for a target-building subagent

Copy, fill the bracketed parts, delete what does not apply. Each
clause is here because leaving it out cost a round; the reason is
given so you can judge when a clause is not needed.

Before sending: grep the tree for every function name, signature,
struct member and line you mention. If the brief and the tree
disagree, the subagent builds against the tree and loses time finding
out.

```
You are adding one CBMC proof target to an existing harness in
/home/user/openbsd-src/regress/sys/cbmc (an OpenBSD source tree).
Follow the README literally and record every place where it was not
enough. Where this brief and the source tree disagree, the tree is
right: say so in your report.

Read first, in the README: "Environment", "Reading the output",
"Run budget", "Adding a target", "Rules for a harness"[, "Writing a
packet parser target"][, "When a run exhausts time or memory"][,
"When the only failures are pointer arithmetic"].
Then read the worked example(s) completely: [target dirs closest in
shape], every file in them[, and common/mbufcontract.h].

Facts (checked; sizes from a compile): [sizeof and offsetof of every
struct whose size an input depends on, e.g. sizeof(struct sockaddr_dl)
is 32, offsetof(struct sockaddr_dl, sdl_data) is 8].

Target: [function](signature) in [file]. New directory: [dir].
[What the callers guarantee, with file:line, or "read the callers and
state what they guarantee in the harness comment".]
[Input shape: flat buffer of 0..N bytes as a constant-size object
with the data at its end / mc_build packet of up to N bytes / ...]
[Which callees to replace by models and what each model must do;
which go to nobody.]

Properties: no out-of-bounds access; loops terminate; no leak or
double free (--memory-leak-check)[; postcondition ...].

Required outcome: `sh cbmc.sh [dir]` gives RESULT: VERIFIED, or
VIOLATED with a failure you can explain as a kernel defect by reading
the source and giving the concrete input bytes that trigger it (not a
harness or model artifact). must_reach: at least four anchors in
different cases of the function. A mutant/[file] with one length
check removed must give VIOLATED. Write `expect`. Run
`sh suite.sh -m [dir]` and `sh native.sh [dir] 60` and report both.

If you reduce a size bound, drop a check, or replace a callee to get
a result, that is allowed but must be stated in the harness comment
and at the top of your report, with the reason.

Rules:
- Create files only under [dir] and the scratch directory [path].
  Do not edit cbmc.sh, native.sh, suite.sh, loopmap.py, README,
  common/, selftest/, other targets, or kernel sources in place. Do
  not commit or push. If something in a shared file blocks you, stop
  and report exactly what is missing, with a proposed diff.
- Do not edit the kernel to fix a defect you find. Report it.
- Real runs: only through cbmc.sh, with
  CBMC_BUDGET_FILE=[scratch]/budget CBMC_BUDGET=25, one at a time
  (the machine is shared). Never call cbmc directly.
- `CBMC_DRY=1 sh cbmc.sh [dir]` after every edit, before a real run:
  it is free, lists loop ids and shows configuration errors.
- Variables do not persist between your shell calls: put
  CBMC_BUDGET_FILE and CBMC_BUDGET on every cbmc.sh or suite.sh
  command line.
- For a VIOLATED result, get the concrete input with
  `CBMC_TRACE=1` (one extra run) and check it against every guard on
  the path before reporting it.
- must_reach anchors: text that every mutant keeps (an anchor a
  mutant removes turns its VIOLATED into VACUOUS), on the first line
  of a statement (a continuation line of a condition is never
  reached), and unique enough to pin the branch.
- Bound nondet times and counters (below 2^40) so the native engine's
  UBSan does not report overflows in kernel arithmetic on them.
- A run can take minutes. If your tool call is moved to the
  background, wait for it; do not start another run and do not kill
  it before its timeout.
- Keep [scratch]/NOTES: append after every run what you tried, the
  result and the next step. If it exists when you start, you are
  resuming: read it first.

Final report (short): RESULT lines from both engines; PHASE check
time and vars; anchors; the NOBODY line; mutation result; bounds as
built versus as asked; any kernel finding with file:line and input
bytes; counts of real and dry runs; and a numbered list "README
gaps" (each thing you needed that the README or the example did not
tell you, and what you did instead).
```

## Clauses and why they exist

| Clause | What happened without it |
|---|---|
| "the tree is right" | A brief named `nd6_option()` and a ten-member struct; neither exists |
| Named README sections and a worked example | Three README-only attempts on new shapes all ran out of time or memory; once a worked example of the shape existed, most later attempts finished |
| "concrete input bytes" | Subagents reported a NULL counter array and 900 post-contract failures as kernel results |
| "state any reduced bound" | A packet bound went from 48 to 24 bytes and was mentioned only in a caveat line |
| No shared-file edits | One subagent's new shared models turned two other targets VACUOUS |
| Budget through `cbmc.sh` only | A private copy of the script and direct `cbmc` calls bypassed the budget |
| `CBMC_DRY=1` first | Three to four budgeted runs per target were lost to symbol-map, syntax and loop-id errors |
| Wait for background runs | Subagents started a second run or killed the first, then waited on nothing |
| NOTES file | The container restarted mid-round four times; without notes the work was redone |
| "Do not fix the kernel" | The orchestrator decides the form of a fix and whether it may be public |
| Struct sizes in the brief | Two reports gave sizeof(struct sockaddr_dl) as 20 and inputs the code rejects |
| Budget variables on every command | Six runs went unlogged |
| `CBMC_TRACE=1` for inputs | Hand-derived inputs were wrong twice |
| Anchor rules | A mutant came back VACUOUS; a condition's second line was never reached |
| Bounded nondet times | Native runs reported UBSan overflow in kernel time arithmetic |

## Resuming a subagent after a restart

```
You are resuming an interrupted task: [target and directory]. The
previous worker was killed by a machine restart. Its notes are at
[scratch]/NOTES: read them first, then the target's files, then
[README sections].

State when it stopped: [two or three lines from the notes].
[Anything that changed since: a kernel fix applied, a framework
change that removes its blocker.]

Your job: [numbered remaining steps].
[Same rules block; say how many budget slots are used.]
```
