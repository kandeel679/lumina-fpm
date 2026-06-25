# -*- coding: utf-8 -*-
import re, io
doc = io.open("FINAL DOCUMENTATION/LuminaFPM_Documentation.tex", encoding="utf-8").read()
i = doc.find("\\begin{document}")
body = doc[i:]

# blank out lstlisting blocks and inline math so we only check prose/tables
masked = re.sub(r"\\begin\{lstlisting\}.*?\\end\{lstlisting\}", " ", body, flags=re.S)
masked = re.sub(r"(?<!\\)\$.*?(?<!\\)\$", " ", masked, flags=re.S)   # inline math
masked = re.sub(r"\\verb\|[^|]*\|", " ", masked)
masked = re.sub(r"\\path\{[^}]*\}", " ", masked)
masked = re.sub(r"\\url\{[^}]*\}", " ", masked)

def ctx(s, p):
    return repr(s[max(0, p-28):p+12].encode("ascii", "replace").decode())

# unescaped underscore (not \_) in prose/tables
us = [(m.start()) for m in re.finditer(r"(?<!\\)_", masked)]
print("unescaped _ (prose/tables, excl. math/listings):", len(us))
for p in us[:12]:
    print("    ", ctx(masked, p))

# unescaped & not in a tabular/longtable/tikz alignment row is hard to judge;
# report raw & that are NOT \& (table cells legitimately use &, so this is informational)
amp = [m.start() for m in re.finditer(r"(?<!\\)&", masked)]
print("raw & total (mostly legitimate table separators):", len(amp))

# stray # not \#
hsh = [m.start() for m in re.finditer(r"(?<!\\)#", masked)]
print("unescaped # :", len(hsh))
for p in hsh[:8]: print("    ", ctx(masked, p))

# \caption with raw _ etc already covered. report ^ and ~ raw (outside math)
crt = [m.start() for m in re.finditer(r"(?<!\\)\^", masked)]
til = [m.start() for m in re.finditer(r"(?<!\\)~", masked)]
print("raw ^ :", len(crt), "| raw ~ (nbsp, usually fine) :", len(til))
for p in crt[:6]: print("   ^ ", ctx(masked, p))
