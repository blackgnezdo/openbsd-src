---
name: kernel-proofs
description: Drive bounded-model-checking proofs and proof-backed fixes of OpenBSD kernel code with the harness in regress/sys/cbmc (CBMC plus a native ASan/libFuzzer engine), delegating target construction to cheaper subagents. Use this skill whenever the user asks to prove, verify, model-check, harden or bug-hunt kernel code in this tree, to add or repair a target under regress/sys/cbmc, to turn a finding into a fix with a proof, to run or triage the proof suite, or to scale proof work with subagents — even if they only say "pick more targets", "keep going" or "practice more with proofs".
---

# Kernel proofs with cheaper subagents

You are the orchestrator. Cheaper models build targets; you pick the
targets, write the briefs, verify what comes back, fix the shared
framework when it is the obstacle, and decide what is a finding. The
mechanics of a target (file formats, harness rules, recipes) live in
`regress/sys/cbmc/README`. Read it once in full before your first
round; subagents read only the sections their brief names.

The goal the user set for this work: maximize future bug-fixing
velocity with provers, using many cheap models on a strong checker.
That makes the framework and the README the product, and each target
a test of them. When a subagent struggles, the valuable output is the
change that stops the next subagent struggling the same way.

## The loop

1. **Pick targets** (you). See "Picking targets".
2. **Check the brief against the tree** (you). Grep every function
   name, signature and struct member you are about to put in a brief.
   Briefs written from memory have named functions that do not exist.
3. **Delegate** one target per subagent, in parallel, with the brief
   template in `references/brief-template.md`. Three to five subagents
   at once on a 4-core machine; each runs one checker job at a time.
4. **Verify the hand-back yourself** before believing or committing
   anything. See "Verifying a hand-back".
5. **Fold the lessons back**: every "README gap" a subagent reports is
   either a README edit, a framework change, or a note in
   `references/pitfalls.md` saying why it is neither.
6. **Commit** (you, never the subagent): kernel fixes as their own
   commits, target directories separately, shared-framework changes
   only after `sh selftest/run.sh` and `sh suite.sh -m` pass.
7. **Record** in `regress/sys/cbmc/FINDINGS` what stays open after
   the round: unfixed findings, observations made by reading, and
   gaps in a target. A finding fixed in the same round, with its
   `mutant_prefix/` committed, gets no entry; the target's README
   entry describes it.

## Which model for what

From the delegations in this tree so far:

| Work | Model | Why |
|---|---|---|
| A target that follows an existing worked example (flat-buffer parser, attach/detach, validator-then-consumer) | Haiku | Succeeds when the brief names the example and the README sections |
| A target that needs a design choice (where to split, what the caller guarantees), finding-to-fix with mutants, scripting | Sonnet | Handles specified multi-step work and stateful targets |
| A new technique, a change to `common/`, `cbmc.sh`, `native.sh`, a cost problem nobody has solved yet | You | Cheaper models stall when the obstacle is in shared models or solver cost; they shrink the problem until it passes instead |

A stalled cheap subagent is not a reason to relaunch it with a longer
budget. Read its notes, find which rung of the cost ladder it is on
(README "When a run exhausts time or memory"), fix that yourself, add
the fix to the README, then hand the target back.

## Picking targets

Good targets, in the order they have paid off here:

- A function that walks untrusted bytes in a loop: option, tag and TLV
  parsers, table validators, on-disk structure readers. Four of the
  five most recent ones produced a defect or a UB cleanup.
- A two-pass shape (validate, then act on the validated data). The
  second pass trusts the first; check that it can.
- Error paths that hand ownership back and forth (`m = NULL; goto
  done`). The leak check finds these cheaply.
- Attach/detach and ioctl dispatch with a small callee surface.

Poor targets: large state machines, code dominated by function
pointers, code whose interesting behaviour is concurrency or sleeping
(not modelled).

Prefer a function whose callers' guarantees you can state in two
lines. If you cannot, split: one target for the caller that proves the
guarantee, one for the callee that assumes it
(`netinet6/ip6_hopopts_input` with `netinet6/ip6_hopopts`).

## Verifying a hand-back

A subagent's report is a claim. Before committing, do these yourself;
they take a few minutes and each has caught a wrong report.

1. `sh suite.sh -m <target>` and `sh native.sh <target>`. Compare with
   the report.
2. Read `must_reach`. Anchors must sit inside the cases that matter,
   not at the function's entry. A VERIFIED with weak anchors is the
   vacuous proof this framework exists to prevent.
3. Read the `NOBODY` line. A function with no body returns an
   arbitrary value and has **no side effects**: it does not write its
   out-parameters, free what it owns, or consume an mbuf. Any name
   there that fills a buffer or takes ownership needs a model, or the
   proof silently skips the writes and the leak check lies.
4. Diff the bounds against the brief. Subagents reduce packet sizes,
   segment counts and option counts until the run passes, and say so
   only in passing. A smaller bound is acceptable when stated in the
   harness comment and the README entry, and when the defect class
   you care about fits inside it.
5. Read every model the harness adds. A model that replaces `bcopy`
   by a range check is sound only if nothing later reads the copied
   bytes; a model that returns NULL to cut a path removes that path
   from the proof. Check that native builds do real work in such
   models (`#ifdef NATIVE_SHIM_H`), otherwise ASan sees nothing.
6. Check each assumption in the harness comment against the callers'
   source. An assumption stronger than what callers guarantee gives a
   false VERIFIED.
7. A mutant must exist and be VIOLATED for the reason intended, on a
   mutant built from the current kernel source.

## Deciding what is a finding

Subagents report three different things as "kernel finding". Sort them
before acting.

- **Harness artifact.** The failing state cannot occur: an
  uninitialised global the harness never set up (`ip6counters`), a
  struct field left arbitrary that the kernel always initialises,
  hundreds of failures after a loop contract (a havocked state, not
  hundreds of bugs). Ask for the concrete external input (bytes on
  the wire, bytes on disk, ioctl arguments) that triggers it. No such
  input, no finding.
- **Undefined behaviour without a memory effect.** Pointer arithmetic
  that leaves the object before a bounds test, then a comparison
  (`rtm_xaddrs`, `ip6_process_hopopts`, `nd6_options`,
  `ieee80211_parse_rsn_body`). The user has accepted rewriting these
  as length comparisons, each as its own small commit with the
  pre-fix source kept as `mutant_prefix/`. The README section "When
  the only failures are pointer arithmetic" has the steps; name it in
  the brief of any parser target.
- **A defect with a memory or resource effect.** Confirm it three
  ways before calling it one: read the source and write down the
  input; see it fail under CBMC; see it under the native engine on
  the pre-fix source. Then stop and follow "Things only the user
  decides".

A fix must be right for the kernel, not convenient for the harness.
One subagent chose the form of a fix so that a `must_reach` anchor
would still exist in the mutant. Review kernel diffs as kernel diffs.

## Things only the user decides

Resolve harness, model, cost and delegation problems yourself. Go to
the user for these, and only these:

- **Anything that looks exploitable by an untrusted party** (remote
  peer, unprivileged user, on-link host). The branch is on GitHub.
  Do not commit or push the fix, a `mutant_prefix/`, or text that
  describes the defect. Tell the user, offer a private patch with a
  description, and wait. After they have reported it, the failing
  target may be committed with a neutral message and `expect` set to
  its current result.
- **A fix that could reject input the kernel accepts today** (for
  example removing the early `break` in `rtm_xaddrs`).
- **Policy**: whether a reachable `panic()` on corrupt input counts
  as a finding; whether to draft larger validation code
  (`ffs_mountfs` geometry checks).
- **Pull requests.** Never open one unasked.

A stop hook will ask you to commit whenever the tree is dirty. Do not
commit a running subagent's half-finished directory or an embargoed
fix to satisfy it; say why in one line and move on.

## Operating rules that keep rounds from being wasted

- **Subagents never edit shared files** (`cbmc.sh`, `native.sh`,
  `suite.sh`, `loopmap.py`, `common/`, `selftest/`, README, other
  targets, kernel sources in place). They report a diff. Several
  run at once, and one subagent's change to a shared model changed
  the results of two targets it never looked at.
- **Every real run goes through `cbmc.sh` with a budget file**
  (`CBMC_BUDGET_FILE`, `CBMC_BUDGET`). Subagents have overrun by
  copying the script and by calling `cbmc` directly. `CBMC_DRY=1` is
  free and catches configuration errors; require it after each edit.
- **After any change to `common/` or the scripts**, run
  `sh selftest/run.sh` and `sh suite.sh -m`. New models have turned
  two unrelated targets VACUOUS without anyone touching them.
- **The container restarts without warning** and kills subagents and
  background jobs. Briefs require a `NOTES` file in the scratch
  directory, appended after every run. After a restart, check
  `git status`, read the notes, and relaunch with "you are resuming;
  read NOTES first". Do not assume a silent subagent is alive.
- **Timings under load are 1.5 to 2 times the quiet ones.** Put a
  `timeout` file in a target whose check phase exceeds 150 s quiet.
- **You commit; subagents do not.** No model names in commits or
  files.

## When the checker runs out of time or memory

The README section of that name has the ladder and the measurements.
In brief, read the `PHASE` line and act on where the cost is:

1. Out of memory with `vars=0` right after a short symex: an object
   of symbolic size. Make it constant-size with the data at the end.
2. Symex dominated by library code: use contract models
   (`common/mbufcontract.h`) and prove the library separately.
3. Cost multiplies with a loop bound in the function under test: give
   the loop a contract (`loops` file), unless the loop body allocates
   or the invariant would have to describe data not yet visited; then
   use a small bound and say so.
4. Solver-bound with nothing above applying: split at an interface.
   A different SAT solver bought 1.3 to 1.6 times, no more.

If none applies, that is new ground: work on it yourself, measure, and
write the result into the README before delegating again.

## Reference files

- `references/brief-template.md` — the brief to copy for each
  subagent, with the clauses that prevent known failure modes.
- `references/pitfalls.md` — symptom, cause and resolution for the
  problems met so far, grouped by where they show up. Read it when a
  hand-back looks wrong or a subagent stalls, before designing a new
  workaround.
- `regress/sys/cbmc/README` — target mechanics and recipes.
- `regress/sys/cbmc/FINDINGS` — open findings and observations.
