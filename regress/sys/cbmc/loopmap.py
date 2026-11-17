#!/usr/bin/env python3
# Fill in the "symbol_map" of the loop contracts in a <target>/loops file.
#
# usage: loopmap.py <loops.json> <symbol-table.txt> <out.json>
#
# goto-instrument wants every local or parameter used in a contract
# clause as "name,FUNCTION::1::name" (locals) or "name,FUNCTION::name"
# (parameters).  An entry without "symbol_map" gets one here: every
# identifier of its clauses that is a local or parameter of the function
# in the symbol table (goto-instrument --show-symbol-table) is mapped,
# the outermost scope first.  An entry that has a "symbol_map" is kept.
import json
import re
import sys

loops, symtab, out = sys.argv[1:4]
syms = re.findall(r'^Symbol\.*: (\S+)$', open(symtab).read(), re.M)
doc = json.load(open(loops))
for fn in doc.get('functions', []):
    for name, entries in fn.items():
        local = {}
        for s in syms:
            m = re.fullmatch(re.escape(name) + r'::((?:\d+::)*)(\w+)', s)
            if m and (m.group(2) not in local or
                      len(s) < len(local[m.group(2)])):
                local[m.group(2)] = s
        for e in entries:
            if 'symbol_map' in e:
                continue
            text = ' '.join(str(e.get(k, ''))
                            for k in ('invariants', 'decreases', 'assigns'))
            ids = sorted(set(re.findall(r'[A-Za-z_]\w*', text)) & set(local))
            if ids:
                e['symbol_map'] = ';'.join('%s,%s' % (i, local[i])
                                           for i in ids)
json.dump(doc, open(out, 'w'), indent=1)
