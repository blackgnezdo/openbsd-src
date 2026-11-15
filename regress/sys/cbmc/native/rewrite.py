#!/usr/bin/env python3
"""
Rewrite the LLVM IR of a cbmc target so that it runs natively with the
same function-body semantics as cbmc.sh.  See README.native.

usage: rewrite.py --keep FILE --replace FILE --out DIR
                  --harness H.ll --kernel K1.ll ... --model M1.ll ...

Kernel and harness modules are rewritten in place (into --out):
  - a function that cbmc.sh would strip (not in keep, not defined by the
    harness translation unit, not defined in a header, not one of the
    fixed model names) gets a body that returns bytes from the fuzz
    input and has no other effect, as CBMC does for a bodiless function;
  - a function named on the left of a replace line forwards to the model;
  - every writable global gets registered for the per-input reset.
Model modules (common/stubs_*.c) are left as they are.

Functions that are declared somewhere but defined nowhere get a generated
definition with the same semantics in stubs.ll, unless they are on the
LIBC list (string functions that CBMC also takes from its own library).
Writes stubs.ll, stubbed.txt (what was stripped or generated) and reset
registration (__native_for_each_global) into --out.
"""
import argparse
import os
import re
import sys

# Same fixed list as cbmc.sh's keep (the common models' entry points).
FIXED_KEEP = set("""kmalloc kfree mallocarray malloc calloc free pool_get pool_put
__builtin_bcopy __builtin_memcpy __builtin_memmove memcpy memmove panic
copyin copyout copyinstr m_get m_clget m_free m_freem""".split())

# Undefined functions that bind to the C library (intercepted and checked by
# the sanitizers) instead of getting a nondet stub.  CBMC links its own
# library models for these names.
LIBC = set("""memcpy memmove memset memcmp bcmp memchr bzero strlen strnlen
strcmp strncmp strchr strrchr strcpy strncpy strlcpy strlcat strstr
malloc calloc realloc free abort""".split())

RUNTIME_PREFIXES = ("llvm.", "__asan_", "__ubsan_", "__msan_", "__sanitizer_",
                    "__sancov_", "__native_", "__lsan_")

LINKAGE_WORDS = set("""private internal available_externally linkonce weak common
appending extern_weak linkonce_odr weak_odr external dso_local dso_preemptable
default hidden protected dllimport dllexport unnamed_addr local_unnamed_addr
thread_local ccc fastcc coldcc""".split())
RET_ATTR_WORDS = set("zeroext signext inreg noalias nonnull noundef".split())


def die(msg):
    sys.stderr.write("rewrite.py: %s\n" % msg)
    sys.exit(2)


def take_type(s):
    """Split an LLVM type off the front of s: return (type, rest)."""
    s = s.lstrip()
    if s.startswith("<{") or s[0] in "{[<":
        depth = 0
        for i, ch in enumerate(s):
            if ch in "{[<":
                depth += 1
            elif ch in "}]>":
                depth -= 1
                if depth == 0:
                    return s[:i + 1], s[i + 1:]
        die("unbalanced type: %s" % s[:80])
    m = re.match(r'(%"[^"]*"|%[-\w.$]+|[\w.]+)', s)
    if not m:
        die("cannot parse type: %s" % s[:80])
    t = m.group(1)
    rest = s[m.end():]
    # function pointer types do not occur with opaque pointers; vectors
    # and arrays are handled above
    return t, rest


def split_top(s, sep=","):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


class Func:
    pass


def parse_header(line):
    """Parse a define/declare line into a Func (no body)."""
    f = Func()
    f.line = line
    m = re.match(r'(define|declare)\s+(.*?)@("[^"]+"|[-\w.$]+)\((.*)$', line)
    if not m:
        die("cannot parse function header: %s" % line[:120])
    f.kind = m.group(1)
    pre = m.group(2)
    f.name = m.group(3).strip('"')
    # params: up to the matching ')'
    rest = m.group(4)
    depth, i = 1, 0
    while i < len(rest):
        if rest[i] in "([{<":
            depth += 1
        elif rest[i] in ")]}>":
            depth -= 1
            if depth == 0:
                break
        i += 1
    f.params = rest[:i]
    f.tail = rest[i + 1:]
    # prefix: strip metadata attachments, linkage words and return attributes
    pre = re.sub(r'!\w+ !\d+', ' ', pre)
    toks = pre.split()
    f.linkage = []
    while toks:
        t = toks[0]
        if t in LINKAGE_WORDS or t in RET_ATTR_WORDS:
            f.linkage.append(t)
            toks.pop(0)
        elif re.match(r'(dereferenceable|dereferenceable_or_null|align|range)\b', t):
            toks.pop(0)
            if t == "align":
                toks.pop(0)
        else:
            break
    f.ret = " ".join(toks)
    f.internal = "internal" in f.linkage or "private" in f.linkage
    f.weak = "extern_weak" in f.linkage
    f.attrgroups = re.findall(r'#(\d+)', f.tail)
    m = re.search(r'!dbg !(\d+)', line)
    f.dbg = m.group(1) if m else None
    return f


def param_list(params):
    """[(type, attrs-text, name-or-None)] from a parameter list."""
    out = []
    for p in split_top(params):
        p = p.strip()
        if p == "...":
            out.append(("...", "", None))
            continue
        t, rest = take_type(p)
        m = re.search(r'\s(%[-\w.$"]+)\s*$', rest)
        name = m.group(1) if m else None
        attrs = rest[:m.start()] if m else rest
        out.append((t, attrs.strip(), name))
    return out


def size_expr(t):
    return "ptrtoint (ptr getelementptr (%s, ptr null, i32 1) to i64)" % t


class Module:
    def __init__(self, path, role):
        self.path = path
        self.role = role
        with open(path) as fp:
            self.lines = fp.read().split("\n")
        self.defines = {}      # name -> (Func, start, end)
        self.declares = {}     # name -> Func
        self.globals = []      # (name, type)
        self.gdefs = set()     # non-internal defined globals
        self.gexterns = {}     # name -> (line index, type)
        self.attrs = {}        # id -> text
        self.difile = {}       # md id -> filename
        self.subprog = {}      # md id -> file md id
        L = self.lines
        i = 0
        while i < len(L):
            ln = L[i]
            if ln.startswith("define "):
                f = parse_header(ln)
                j = i
                while L[j] != "}":
                    j += 1
                self.defines[f.name] = (f, i, j)
                i = j + 1
                continue
            if ln.startswith("declare "):
                f = parse_header(ln)
                self.declares[f.name] = f
            elif ln.startswith("attributes #"):
                m = re.match(r'attributes #(\d+) = \{(.*)\}', ln)
                self.attrs[m.group(1)] = m.group(2)
            elif ln.startswith("!"):
                m = re.match(r'!(\d+) = !DIFile\(filename: "([^"]*)"', ln)
                if m:
                    self.difile[m.group(1)] = m.group(2)
                m = re.match(r'!(\d+) = distinct !DISubprogram\(.*?file: !(\d+)', ln)
                if m:
                    self.subprog[m.group(1)] = m.group(2)
            elif ln.startswith("@"):
                m = re.match(r'@("[^"]+"|[-\w.$]+) = (.*?)\b(global|constant) (.*)$', ln)
                if m:
                    words = m.group(2).split()
                    if "external" in words or "extern_weak" in words:
                        t, _ = take_type(m.group(4))
                        self.gexterns[m.group(1)] = (i, t)
                    elif "private" not in words and "internal" not in words:
                        self.gdefs.add(m.group(1))
                if m and m.group(3) == "global":
                    words = m.group(2).split()
                    if ("private" not in words and "external" not in words
                            and "extern_weak" not in words
                            and "thread_local" not in " ".join(words)
                            and not m.group(1).startswith("llvm.")
                            and not m.group(1).startswith("__sancov")):
                        t, _ = take_type(m.group(4))
                        self.globals.append((m.group(1), t))
            i += 1
        self.header = [l for l in L if l.startswith("target ")]

    def file_of(self, f):
        if f.dbg and f.dbg in self.subprog:
            return self.difile.get(self.subprog[f.dbg], "")
        return ""

    def noreturn(self, f):
        return any("noreturn" in self.attrs.get(a, "").split() for a in f.attrgroups)


def stub_body(f, mod, label, fwd=None, fwd_ret_ok=True):
    """Body lines replacing the body of f.  fwd: model to forward to."""
    b = ["entry:"]
    params = param_list(f.params)
    if fwd:
        args = ", ".join("%s %s" % (t, n) for t, a, n in params if t != "...")
        if f.ret == "void":
            b.append("  call void @%s(%s)" % (fwd, args))
            b.append("  ret void")
        else:
            b.append("  %%__native_r = call %s @%s(%s)" % (f.ret, fwd, args))
            b.append("  ret %s %%__native_r" % f.ret)
        return b
    b.append("  call void @__native_stub(ptr @%s)" % label)
    if mod is not None and mod.noreturn(f):
        b.append("  call void @__native_noreturn(ptr @%s)" % label)
        b.append("  unreachable")
        return b
    # an sret result is filled like a return value
    for t, a, n in params:
        m = re.search(r'sret\((.*?)\)', a)
        if m and n:
            b.append("  call void @__native_fill(ptr %s, i64 %s)" % (n, size_expr(m.group(1))))
    if f.ret == "void":
        b.append("  ret void")
    elif f.ret == "i1":
        b.append("  %__native_r = alloca i8")
        b.append("  call void @__native_fill(ptr %__native_r, i64 1)")
        b.append("  %__native_v = load i8, ptr %__native_r")
        b.append("  %__native_w = trunc i8 %__native_v to i1")
        b.append("  ret i1 %__native_w")
    else:
        b.append("  %%__native_r = alloca %s" % f.ret)
        b.append("  call void @__native_fill(ptr %%__native_r, i64 %s)" % size_expr(f.ret))
        b.append("  %%__native_v = load %s, ptr %%__native_r" % f.ret)
        b.append("  ret %s %%__native_v" % f.ret)
    return b


def named_params(params):
    out, k = [], 0
    for t, a, n in param_list(params):
        if t == "...":
            out.append("...")
            continue
        # attributes naming types of the declaring module (byval, sret)
        # cannot be copied into stubs.ll; the stub does not read them
        a = " ".join(w for w in a.split() if w in ("zeroext", "signext", "noundef"))
        out.append("%s %s %%a%d" % (t, a, k))
        k += 1
    return ", ".join(out)


RUNTIME_DECLS = [
    "declare void @__native_fill(ptr, i64)",
    "declare void @__native_stub(ptr)",
    "declare void @__native_noreturn(ptr)",
    "declare void @__native_harness_heap(ptr)",
    "declare void @__native_fp_check(ptr, ptr, i32, ...)",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", required=True)
    ap.add_argument("--replace")
    ap.add_argument("--nobody")
    ap.add_argument("--fptargets")
    ap.add_argument("--out", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--kernel", nargs="*", default=[])
    ap.add_argument("--model", nargs="*", default=[])
    a = ap.parse_args()

    keep = set(open(a.keep).read().split()) | FIXED_KEEP
    nobody = set()
    if a.nobody and os.path.exists(a.nobody):
        nobody = set(open(a.nobody).read().split())
    repl = {}
    if a.replace and os.path.exists(a.replace):
        for ln in open(a.replace).read().split():
            fn, model = ln.split(":")
            repl[fn] = model

    # fptargets: FUNC.function_pointer_call.N/TARGET[,TARGET...]
    fpt = {}
    if a.fptargets and os.path.exists(a.fptargets):
        for ln in open(a.fptargets).read().split():
            site, tl = ln.split("/", 1)
            fn, _, num = site.rpartition(".function_pointer_call.")
            fpt.setdefault(fn, {})[int(num)] = (site, tl.split(","))
    fp_targets = set(t for d in fpt.values() for _, ts in d.values() for t in ts)

    mods = [Module(a.harness, "harness")] + \
        [Module(p, "kernel") for p in a.kernel] + \
        [Module(p, "model") for p in a.model]

    defined = set()
    for m in mods:
        for n, (f, s, e) in m.defines.items():
            if not f.internal:
                defined.add(n)
    for fn, model in repl.items():
        if model not in defined:
            die("replace: model %s is not defined (needs external linkage)" % model)

    gdefined = set()
    for m in mods:
        gdefined |= m.gdefs
    owner = {}
    for idx, m in enumerate(mods):
        if m.role == "model":
            continue
        for g, (i, t) in m.gexterns.items():
            if g in gdefined or g.startswith(RUNTIME_PREFIXES) or g in owner:
                continue
            if g.startswith("__start_") or g.startswith("__stop_"):
                continue
            owner[g] = idx
            if any(l.startswith(t + " = type opaque") for l in m.lines):
                # incomplete type here: the size is unknown, a too small
                # guess shows up as a global-buffer-overflow
                t = "[4096 x i8]"
            m.lines[i] = "@%s = global %s zeroinitializer, align 64" % (g, t)
            m.globals.append((g, t))
    for idx, m in enumerate(mods):
        if m.role != "model":
            continue
        for g in m.gexterns:
            if g not in gdefined and g not in owner:
                die("model needs undefined data symbol %s" % g)

    report = []
    names = {}     # label -> name string constant

    def label_for(n):
        lab = "__native_name.%d" % len(names)
        names[lab] = n
        return lab

    reg_fns = []
    for idx, m in enumerate(mods):
        if m.role == "model":
            continue
        L = m.lines
        edits = []   # (start, end, newlines)
        my_names = {}
        for n, (f, s, e) in m.defines.items():
            fname = m.file_of(f)
            if n in repl:
                body = stub_body(f, m, None, fwd=repl[n])
                why = "replace -> %s" % repl[n]
            elif n in nobody:
                # cbmc.sh: nobody wins over keep, harness and headers
                lab = "__native_name.%d.%d" % (idx, len(my_names))
                my_names[lab] = n
                body = stub_body(f, m, lab)
                why = "body removed (nobody)"
            elif m.role == "harness" or n in keep or fname.endswith(".h"):
                continue
            else:
                lab = "__native_name.%d.%d" % (idx, len(my_names))
                my_names[lab] = n
                body = stub_body(f, m, lab)
                why = "body removed (not in keep)"
            hdr = re.sub(r'\s*!dbg !\d+', '', L[s])
            hdr = re.sub(r'\s*!func_sanitize !\d+', '', hdr)
            # unnamed parameters are numbered; give them names we can use
            if n in repl and any(nm is None for t, at, nm in param_list(f.params) if t != "..."):
                die("cannot forward %s: unnamed parameters" % n)
            # keep the coverage counter of the function entry: the
            # coverage mapping needs the function's name to stay in the
            # profile (llvm-cov: "function name is empty" otherwise)
            # (step 0: the stripped body must not count as executed)
            for ln in L[s + 1:e]:
                mm = re.match(r'\s*call void @llvm\.instrprof\.increment\((.*?)\)', ln)
                if mm:
                    body.insert(1, "  call void @llvm.instrprof.increment.step(%s, i64 0)" % mm.group(1))
                    if not any(l.startswith("declare void @llvm.instrprof.increment.step(") for l in L):
                        L.append("declare void @llvm.instrprof.increment.step(ptr, i64, i32, i32, i64)")
                    break
            edits.append((s, e, [hdr] + body + ["}"]))
            report.append("%s\t%s\t%s" % (os.path.basename(m.path), n, why))
        for s, e, new in sorted(edits, reverse=True):
            L[s:e + 1] = new
        # Objects the harness itself allocates (device data, ioctl
        # buffers, ...) have arbitrary content under CBMC: mark each so that
        # the MSan build fills it from the input instead of reporting it as
        # uninitialised.  (In the ASan build all heap content is input.)
        if m.role == "harness":
            out_l, in_h = [], False
            for ln in L:
                out_l.append(ln)
                if ln.startswith("define "):
                    mm = re.search(r'!dbg !(\d+)', ln)
                    fid = m.subprog.get(mm.group(1)) if mm else None
                    in_h = m.difile.get(fid, "").endswith("harness.c")
                elif ln == "}":
                    in_h = False
                elif in_h:
                    mm = re.match(r'\s*(%[-\w.$]+) = call .*?ptr @(kmalloc|mallocarray|pool_get|__native_allocate)\(', ln)
                    if mm:
                        out_l.append("  call void @__native_harness_heap(ptr %s)" % mm.group(1))
            L[:] = out_l
        # fptargets: cbmc.sh restricts the N-th pointer call in FUNC to
        # the named functions, which CBMC reports when violated.  The same
        # check here, calling the function the pointer holds afterwards.
        if fpt:
            out_l, cur, k = [], None, 0
            for ln in L:
                if ln.startswith("define "):
                    cur = parse_header(ln).name
                    k = 0
                elif ln == "}":
                    cur = None
                elif cur in fpt and cur in m.defines:
                    mm = re.search(r'\bcall\b(.*)$', ln)
                    callee = None
                    if mm and "@llvm." not in ln:
                        c2 = re.search(r'(%[-\w.$]+|@[-\w.$"]+)\(', mm.group(1))
                        if c2 and c2.group(1).startswith("%"):
                            callee = c2.group(1)
                    if callee:
                        k += 1
                        if fpt[cur].get(k):
                            site, ts = fpt[cur][k]
                            lab = "__native_name.%d.%d" % (idx, len(my_names))
                            my_names[lab] = site
                            args = []
                            for j, t in enumerate(ts):
                                out_l.append("  %%__native_fpt%d_%d = load ptr, ptr @__native_fpaddr.%s" % (k, j, t))
                                args.append("ptr %%__native_fpt%d_%d" % (k, j))
                            out_l.append("  call void (ptr, ptr, i32, ...) @__native_fp_check(ptr @%s, ptr %s, i32 %d, %s)"
                                         % (lab, callee, len(ts), ", ".join(args)))
                            report.append("%s\t%s\tfptargets check -> %s" % (os.path.basename(m.path), site, ",".join(ts)))
                            fpt[cur][k] = None
                out_l.append(ln)
            L[:] = out_l
            have_g = set(l.split(" ")[0][1:] for l in L if l.startswith("@__native_fpaddr."))
            for t in fp_targets:
                g = "__native_fpaddr." + t
                if t in m.defines:
                    L.append("@%s = constant ptr @%s" % (g, t))
                elif any(("@__native_fpaddr.%s" % t) in l for l in L) and g not in have_g:
                    L.append("@%s = external constant ptr" % g)
        for lab, n in my_names.items():
            L.append('@%s = private unnamed_addr constant [%d x i8] c"%s\\00"' %
                     (lab, len(n) + 1, n))
        # models a forwarder calls must be declared here
        have = set(m.defines) | set(m.declares)
        for fn, model in repl.items():
            if fn in m.defines and model not in have:
                f = m.defines[fn][0]
                L.append("declare %s @%s(%s)" % (f.ret, model, f.params))
                have.add(model)
        for d in RUNTIME_DECLS:
            nm = re.search(r'@([\w.]+)', d).group(1)
            if nm not in have:
                L.append(d)
        # per-input reset: hand every writable global to a callback
        rf = "__native_globals_%d" % idx
        reg_fns.append(rf)
        L.append("define void @%s(ptr %%cb, ptr %%fill) {" % rf)
        L.append("entry:")
        for g, t in m.globals:
            fn = "%fill" if owner.get(g) == idx else "%cb"
            L.append("  call void %s(ptr @%s, i64 %s)" % (fn, g, size_expr(t)))
            if fn == "%fill":
                report.append("%s\t%s\tundefined data, defined here, pseudo-random content per input"
                              % (os.path.basename(m.path), g))
        L.append("  ret void")
        L.append("}")
        out = os.path.join(a.out, os.path.basename(m.path).replace(".ll", ".rw.ll"))
        with open(out, "w") as fp:
            fp.write("\n".join(L))
        report.append("%s\t%d globals reset per input" %
                      (os.path.basename(m.path), len(m.globals)))

    for fn, d in fpt.items():
        for k, v in d.items():
            if v is not None:
                report.append("-\t%s\tfptargets call site not found (function stripped or not defined)" % v[0])

    # functions declared but defined nowhere
    S = [mods[0].header[0], mods[0].header[1]] if len(mods[0].header) >= 2 else mods[0].header
    S = list(S)
    S += RUNTIME_DECLS
    done = set()
    for m in mods:
        for n, f in m.declares.items():
            if n in defined or n in done or n.startswith(RUNTIME_PREFIXES):
                continue
            if n in LIBC:
                continue
            done.add(n)
            if "%" in f.ret:
                die("cannot stub %s: returns named type %s" % (n, f.ret))
            g = Func()
            g.__dict__.update(f.__dict__)
            g.params = named_params(f.params)
            if n in repl:
                if repl[n] not in done:
                    S.append("declare %s @%s(%s)" % (f.ret, repl[n], f.params))
                    done.add(repl[n])
                body = stub_body(g, None, None, fwd=repl[n])
                why = "undefined, replace -> %s" % repl[n]
            else:
                lab = label_for(n)
                body = stub_body(g, m if m.noreturn(f) else None, lab)
                why = "undefined, generated stub" + (" (noreturn)" if m.noreturn(f) else "")
            attrs = " ".join(w for w in f.linkage if w in RET_ATTR_WORDS)
            S.append("define %s %s @%s(%s) {" % (attrs, f.ret, n, g.params))
            S += body
            S.append("}")
            report.append("stubs.ll\t%s\t%s" % (n, why))
    for lab, n in names.items():
        S.append('@%s = private unnamed_addr constant [%d x i8] c"%s\\00"' %
                 (lab, len(n) + 1, n))
    # one entry point for the runtime
    for rf in reg_fns:
        S.append("declare void @%s(ptr, ptr)" % rf)
    S.append("define void @__native_for_each_global(ptr %cb, ptr %fill) {")
    S.append("entry:")
    for rf in reg_fns:
        S.append("  call void @%s(ptr %%cb, ptr %%fill)" % rf)
    S.append("  ret void")
    S.append("}")
    # noreturn attribute groups referenced by copied declares are not kept
    with open(os.path.join(a.out, "stubs.ll"), "w") as fp:
        fp.write("\n".join(S) + "\n")
    with open(os.path.join(a.out, "stubbed.txt"), "w") as fp:
        fp.write("\n".join(sorted(report)) + "\n")


if __name__ == "__main__":
    main()
