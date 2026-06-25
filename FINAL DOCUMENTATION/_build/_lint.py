# -*- coding: utf-8 -*-
import re, io
doc = io.open("FINAL DOCUMENTATION/LuminaFPM_Documentation.tex", encoding="utf-8").read()
i = doc.find("\\begin{document}")
body = doc[i:] if i >= 0 else doc

# 1) inline math $ balance
dollars = len(re.findall(r"(?<!\\)\$", body))
print("inline $ count (even?):", dollars, "OK" if dollars % 2 == 0 else "ODD!!")

# 2) environment matching (stack)
stack, errs = [], []
for m in re.finditer(r"\\(begin|end)\{([^}]+)\}", body):
    k, e = m.group(1), m.group(2)
    if k == "begin":
        stack.append(e)
    else:
        if not stack:
            errs.append("extra end " + e)
        elif stack[-1] != e:
            errs.append("mismatch begin %s / end %s" % (stack[-1], e)); stack.pop()
        else:
            stack.pop()
print("unclosed envs:", stack[:8] or "none")
print("env mismatches:", errs[:8] or "none")

# 3) raw mid-line % (silent comment risk) — exclude escaped \%
raw = []
for ln, l in enumerate(body.splitlines(), 1):
    if l.lstrip().startswith("%"):
        continue
    for mm in re.finditer(r"%", l):
        if mm.start() > 0 and l[mm.start()-1] == "\\":
            continue
        raw.append((ln, l[max(0, mm.start()-22):mm.start()+8]))
print("raw mid-line % :", len(raw))
for r in raw[:10]:
    print("   ", r[0], repr(r[1].encode("ascii", "replace").decode()))

# 4) environment counts
for env in ["tikzpicture", "longtable", "lstlisting", "figure", "tabular", "itemize", "enumerate", "thebibliography", "minipage", "center", "scope"]:
    b = body.count("\\begin{%s}" % env)
    e = body.count("\\end{%s}" % env)
    flag = "" if b == e else "  <-- MISMATCH"
    print("  %-15s begin=%d end=%d%s" % (env, b, e, flag))

# 5) brace balance (rough)
nopen = body.count("{"); nclose = body.count("}")
print("braces { } :", nopen, nclose, "OK" if nopen == nclose else "IMBALANCE %d" % (nopen - nclose))
