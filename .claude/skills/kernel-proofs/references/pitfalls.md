# Pitfalls met so far, and how to resolve them without escalating

Each entry: what you see, what is behind it, what to do. Grouped by
where the symptom shows up. All of these were resolved by the
orchestrator; none needs the user.

Contents
1. Results that look good and are not
2. Results that look bad and are not
3. Cost: time and memory
4. Loop contracts
5. Subagent behaviour
6. Shared framework and environment
7. Fixes and mutants
8. What the checker does not look at

## 1. Results that look good and are not

**VERIFIED, few or shallow anchors.** The proof may cover only the
early exits. A loop bound that is too small cuts paths silently unless
`--unwinding-assertions` fires; `cbmc.sh` always passes it, but anchors
are the only check that the interesting code ran. Require anchors in
distinct deep cases and reject entry-level ones.

**VERIFIED, with a function on the NOBODY line that should have had
an effect.** A bodiless function returns an arbitrary value and
touches nothing. If it should fill an out-parameter, the caller reads
whatever was there; if it should free or consume an object, the leak
check and use-after-free checks are blind to it. Go through the line
name by name: hardware access, logging and counters are fine;
anything with an out-pointer or ownership needs a model in the
harness.

**VERIFIED after the subagent shrank the problem.** Look for a
smaller size macro, a lower segment count, a lookup model that returns
NULL, a dropped `--memory-leak-check`, an emptied `loops` file. Each
can be legitimate. Each must be in the harness comment and the README
entry, and you must check that the defect classes the target is for
still fit (a 6-byte request was enough for the LCP defect; a bound of
4 would not have been).

**VERIFIED because an assumption is too strong.** The harness comment
lists what callers guarantee. Open the callers. If a caller can pass
something the harness excludes, either widen the harness or add the
caller as its own target that proves the guarantee.

**VERIFIED with a model that discards the property.** `MEMCPY_TRACK`
checks both regions and stores nothing; a `model_bcopy` that asserts
ranges copies nothing; the pool model zeroes mbufs. Content-dependent
bugs (validate a byte, re-read it through a copy) and uninitialised
reads are then invisible to CBMC. The native engine covers some of
this only if the model does real work natively.

**Native FINDING on the harness postcondition, not on the memory
error.** The fuzzer reaches the cheapest failing assertion first. To
show the sanitizer report on a pre-fix source, add a seed in
`native/seeds/<target>/`. The seed is the byte stream of nondet draws
in call order, including the return values of bodiless functions
(timeout_add_sec in arpinit drew the first 4 bytes of
netinet/arp_rtrequest's seed); a harness change can shift it.

**Native CLEAN after 20 seconds.** The fuzzer may not have reached the
case. Check the native anchors; rerun with a longer time and
`NATIVE_SEED=2`, `3`. Tags that need specific multi-byte values are
rarely reached without a seed input in `native/seeds`.

**Mutant VIOLATED, for the wrong reason.** A mutant can fail on an
unwinding assertion or on an old unrelated failure. `suite.sh -m`
prints the first failed properties of each mutant under its line
(and keeps the full log with `SUITE_LOGDIR`); one of them must be the
access the removed check protected.

**Concrete inputs in a report that the code rejects.** `cbmc.sh`
prints no trace, so subagents derive inputs by reading, and get them
wrong: the arp_rtrequest report gave sa_len 20 for a gateway that
both versions reject below sizeof(struct sockaddr_dl) = 32, and the
nd6_rtrequest report repeated the same error (it is 32: sdl_data is
24 bytes). Put struct sizes the inputs depend on in the brief. The
result stood; the inputs did not. Check every reported input against
each guard on the path, or reproduce it natively. A CBMC_TRACE
option in cbmc.sh would remove this; not done yet.

**VACUOUS where VIOLATED was expected, on a scratch or pinned copy.**
The cover run stops at an out-of-bounds write, so anchors after it are
unreached. suite.sh runs mutants with CBMC_NO_COVER=1 and sees
VIOLATED; a direct cbmc.sh run on the same copy can say VACUOUS. Read
the failed properties, not only the RESULT word.

## 2. Results that look bad and are not

**Native FINDING on signed overflow in a nondet time or counter.**
cbmc.sh runs CBMC with --no-standard-checks; the native engine's UBSan
still checks overflow, so an arbitrary time_t plus a constant fails
there only. Bound such draws (arp_consumers: times below 2^40) and say
so.

**The m_freem model of netinet/arp_rtrequest in a target with a hold
queue.** It asserts m_nextpkt is NULL and returns NULL; ml_purge calls
m_freem on queued packets. Return m_nextpkt as the kernel does
(netinet/arp_consumers).

**`rw_status` and `splassert_fail` on the NOBODY line.** They come
from NET_ASSERT_LOCKED under DIAGNOSTIC: no out-parameter, and
splassert_fail does not end the path. Harmless.

**A NULL dereference in a statistics or counter helper.**
`ip6stat_inc`, `tcpstat_inc` and friends are header inlines over a
per-CPU array the harness never allocates. Put `counters_inc`
(and `counters_add`) in `nobody`.

**Hundreds of failures after adding a loop contract.** The code after
the loop runs from an arbitrary state that satisfies only the
invariant. A pointer the invariant does not pin (a softc, the mbuf's
fields) is arbitrary there. Strengthen the invariant; these are not
kernel failures.

**"pointer outside object bounds" on a `union` member.** CBMC treats
access through a pointer to a union as access to the whole union.
See README "Known limits of the checker" (slack bytes).

**Leak reported for a static or model object.** Models must use
static objects or free what they allocate; the leak check sees
`CBMC_NEW` objects since the fix in `cbmc_harness.h`.

**`conflicting function declarations 'log'`.** The kernel's `log()`
collides with CBMC's builtin `log(double)`. `#define log
kern_log_model` before the includes, or put `log` in `nobody`.

**VACUOUS on a target nobody touched.** A shared model gained a body
(a `strlcpy` loop now needs unwinding). Add the `--unwindset` the HINT
names, or replace the function in that target.

**A failure only on pointer arithmetic, nothing dereferenced.** This
is the UB class (see SKILL.md, "Deciding what is a finding"; steps in
the README, "When the only failures are pointer arithmetic"). With
the data at the end of its object every pointer formed past the data
is visible, including constant-offset tests: `frm + 4 > efrm` fails
once `frm == efrm`. A prediction of three failing tests from reading
came back as nine. In the kernel the pointer leaves its object only
when the data ends its buffer, so the class stays "no memory effect";
do not count the extra failures as extra findings.

## 3. Cost: time and memory

Start from the `PHASE` line, not from the HINT text alone.

**OOM, `vars=0`, symex a few seconds.** An object of symbolic size
read through a struct pointer. Constant size, data at the end.

**Symex minutes, loops listed are library loops.** Real mbuf code or
byte-copy loops below the parser. Use `common/mbufcontract.h`; under
CBMC it has no loops.

**Symex or vars scale with a loop bound of the function under test.**
Loop contract (section 4). Case-splitting on the input length did not
help: the largest single case was as expensive as the whole.

**Solver-bound at 1–4M variables with everything above done.** Options
that worked: split at an interface; shrink the packet to what the
anchors need (count the bytes each anchor needs and add them up);
`MC_COPY_LOOP` when no loop contract is involved. An external
CaDiCaL gave 1.3–1.6 times on one target and cannot be used for the
coverage run. Raising the timeout past about 15 minutes has not once
turned a timeout into a result.

**Symex explodes after a contracted loop.** An unpinned pointer
(`sc`) after the loop makes every later dereference a case split over
all objects. Pin it in the invariant (`sc == 0`).

**Two segments is the limit for the real mbuf code.** Three took
`m_pullup` past 150 s. Do not ask for more; the contract models are
also two-segment.

## 4. Loop contracts

README section "When a run exhausts time or memory", item 3, has the
recipe. Additional judgement:

**When not to use one.** The loop body allocates (the `m_pulldown`
model inside the PPPoE tag loop: `assigns` cannot name objects that do
not exist before the loop). The invariant would need to describe data
not yet visited (pass 2 of a validate-then-act pair relying on pass 1
having checked the whole chain). In both cases use `--unwindset` on a
small packet and write the bound down. Do not let a subagent spend a
budget discovering this again.

**goto-instrument dies with no message.** A typedef name in a clause
(`u_char`). Use builtin type names.

**A clause seems to have no effect.** `__CPROVER_pointer_object`,
`__CPROVER_pointer_offset`, `__CPROVER_dynamic_object` in a clause
become bodiless calls; they show on the NOBODY line.

**`sizeof(struct T)` is "incomplete type" in a clause.** Use the
number.

**"Inner loop ... unwind it first".** A callee of the contracted loop
contains a loop; a `do { } while (0)` macro counts. Replace the callee
by a loop-free model. A loop contract on the callee's loop inside
another contracted loop has crashed goto-instrument.

**The contracted loop's body appears twice.** The transformation
copies the body (base and step). A nested uncontracted loop is then
unwound in both copies, and `CBMC_DRY=1` lists one id where the run
shows two. Give both ids an `--unwindset`, or bound the nested loop's
data.

**Invariant on a pointer the loop writes.** `<` and `>` on a havocked
pointer fail as cross-object comparisons. Equalities against a ghost
end pointer work (`netinet6/nd6_options` generates 63 of them); the
clause is long and slow to check. Keep the ghost in the harness.

**"invariant before entry" fails.** Code before the loop changed what
the invariant ties to (an `m_adj` that trims `m_pkthdr.len`). Derive
the constant from the code before the loop, or tie the invariant to a
ghost the harness sets after that code would have run.

**"invariant preserved" fails with no trace.** Remove conjuncts one at
a time on `CBMC_NO_COVER=1` runs.

## 5. Subagent behaviour

**"Waiting on its own background work" for a long time.** Normal when
a run exceeds the tool's foreground limit. It becomes a stall when
the subagent started a second run, killed the first, or waits on a
job that a container restart removed. Check `uptime` and its NOTES;
relaunch from the notes if the container restarted.

**Budget used up on configuration errors.** Brief did not require
`CBMC_DRY=1`, or the error is one a dry run cannot see (link
conflicts, NOBODY effects). Add the pattern here and to the README.

**The subagent reports your own activity as suspicious.** It sees
other cbmc processes and commits to shared files. Expected; ignore.

**The subagent "fixed" the kernel in its scratch copy to get
VERIFIED.** Useful as evidence. The fix that goes in the tree is
yours to write and review.

**The report's table and the tree disagree.** The tree wins. Rerun.

**A cheaper model keeps failing on one target.** Count attempts: after
two, the obstacle is the framework or the brief, not effort. Take the
target yourself far enough to find which, fix that, then delegate
again. PPPoE took three delegations because the first two obstacles
(loops in the models, loop ids) were framework problems.

## 6. Shared framework and environment

**After any edit to `common/`, `cbmc.sh`, `native.sh`, `suite.sh`,
`loopmap.py`:** `sh selftest/run.sh` (about 3 minutes) and
`sh suite.sh -m` (the plain suite takes over half an hour and the
mutants add to it; run it in the background with `SUITE_LOGDIR` on
the scratchpad so a restart loses only the unfinished part).

**Container restart.** Background jobs and subagents die; the working
tree and the scratchpad have survived every time so far, installed
packages too. Check `git status`, the scratch NOTES files, and
`which cbmc cadical`.

**The scratchpad is not durable.** Anything the user must keep goes
in the repository or in the reply.

**Contention.** With four or five subagents each running cbmc, quiet
timings double. Do not conclude that a framework change made targets
slower from a loaded run.

**Stop-hook pressure.** The hook asks for a commit whenever the tree
is dirty. Subagents' in-progress directories and embargoed fixes stay
uncommitted; answer in one line.

**README growth.** Every round adds rules. When a section stops being
a recipe a small model can follow top to bottom, restructure it
rather than append; the brief names sections, so keep section titles
stable.

## 7. Fixes and mutants

**Conventions.** `mutant/`: current source with one check removed.
`mutant_prefix/`: the source before a fix. Both must be VIOLATED
under `suite.sh -m`.

**After a kernel fix,** rebuild `mutant/` from the fixed source,
otherwise it carries the old defect and fails for that reason.

**Fix shape.** Prefer the form the neighbouring code uses
(`kcs_recvmsg` for `smic_recvmsg`). If the proof framework makes one
form easier to test, that is not a reason to choose it.

**Same pattern elsewhere.** After a finding, have a subagent read
sibling functions for the pattern (the IPCP and IPv6CP option
handlers after the LCP one) and report candidates without building
targets.

**Commit order for a public fix:** kernel fix alone; then the target
with `expect` VERIFIED and `mutant_prefix/`. For an embargoed one see
SKILL.md.

## 8. What the checker does not look at

So that a VERIFIED is not read as more than it is:

- Arithmetic: `cbmc.sh` runs `--pointer-check` (which brings the
  bounds checks), unwinding assertions and what `opts` adds
  (`--memory-leak-check`, `--div-by-zero-check`). Signed overflow,
  narrowing conversions and shifts are not checked. A truncation is
  found only when it leads to an out-of-bounds access
  (`msg_copyout`).
- Uninitialised reads: only natively, with `NATIVE_SAN=msan`, and
  only for copies to user space.
- Interrupts, other threads, locks, sleeping: not modelled, except
  where a target models a sleep point explicitly (`sysv/shm`,
  `sysv/semop`).
- Sizes beyond the bounds in the harness comment.
- Paths cut by a model.
- The models themselves: `common/mbufcontract.h` states what the mbuf
  functions promise, and nothing mechanically ties those statements
  to the `net/mbuf_*` proofs of the real functions.
- Counterexample inputs: `cbmc.sh` prints failed properties, not
  traces. To get concrete bytes, reproduce natively or derive them by
  reading.
