#!/usr/bin/env python3
"""
reached.py FILE.i COVERAGE.txt ...

Coverage is recorded against the preprocessed .i files (clang's coverage
mapping ignores line markers).  Map every executed .i line back to the
source file and line its gcc line marker names and print "FILE LINE" for
each, the format of cbmc.sh's "reached" file.  COVERAGE.txt is the output
of llvm-cov show for FILE.i.
"""
import re
import sys

out = set()
args = sys.argv[1:]
for ipath, cpath in zip(args[0::2], args[1::2]):
    origin = {}
    cur, line = None, 0
    with open(ipath, errors="replace") as fp:
        for n, ln in enumerate(fp, 1):
            m = re.match(r'# (\d+) "([^"]*)"', ln)
            if m:
                line, cur = int(m.group(1)), m.group(2)
                continue
            origin[n] = (cur, line)
            line += 1
    with open(cpath, errors="replace") as fp:
        for ln in fp:
            m = re.match(r'\s*(\d+)\|\s*([0-9.]+[kMGE]?)\|', ln)
            if not m or m.group(2) in ("0",):
                continue
            n = int(m.group(1))
            if n in origin and origin[n][0]:
                out.add("%s %d" % origin[n])
for r in sorted(out):
    print(r)
