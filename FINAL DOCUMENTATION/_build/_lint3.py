# -*- coding: utf-8 -*-
import re, io
doc = io.open("FINAL DOCUMENTATION/LuminaFPM_Documentation.tex", encoding="utf-8").read()
body = doc[doc.find("\\begin{document}"):]
m = body
for env in ["longtable", "tabular", "tabularx", "tikzpicture", "align", "array", "matrix"]:
    m = re.sub(r"\\begin\{" + env + r"\}.*?\\end\{" + env + r"\}", " ", m, flags=re.S)
stray = [mm.start() for mm in re.finditer(r"(?<!\\)&", m)]
print("stray & outside tables/tikz/math:", len(stray))
for p in stray[:15]:
    print("   ", repr(m[max(0, p-42):p+10].encode("ascii", "replace").decode()))
