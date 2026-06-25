# -*- coding: utf-8 -*-
import json, re, sys, io
BASE = "FINAL DOCUMENTATION"
OUT_JSON = "C:/Users/Lenovo/AppData/Local/Temp/claude/D----------------------------------------LUMINA-lumina-fpm/27845133-5593-4c4b-9220-a17411fb24ea/tasks/wlyiz3me1.output"

def rd(p):
    return io.open(p, encoding="utf-8").read()

# ---- inline parts from workflow ----
data = json.loads(rd(OUT_JSON))
inline = {p["label"]: p["tex"] for p in data["result"]["parts"]}

# ---- figures dict ----
figsrc = rd(BASE + "/_figures.tex")
FIG = {}
for m in re.finditer(r'%%BEGINFIG:(fig:[\w:-]+?)%%\s*(.*?)\s*%%ENDFIG%%', figsrc, re.S):
    FIG[m.group(1)] = m.group(2).strip()

def strip_fences(t):
    t = re.sub(r'```+\s*latex', '', t)
    t = t.replace('```', '')
    return t

def cut_to_latex(t):
    # remove leading chatter before the first \chapter or \section
    m = re.search(r'\\(chapter|section)\{', t)
    return t[m.start():] if m else t

# Patterns that only appear in agent meta-commentary appended AFTER the LaTeX body
# (markdown bullets; backtick-wrapped LaTeX/labels; grounding/notes sentences).
_TRAIL = [
    r'(?m)^[ \t]*[-*][ \t]\S',
    r'`\\uiplaceholder', r'`\\end\{figure\}', r'`\\chapter', r'`\\section', r'`fig:',
    r'figure markers', r'All figure markers', r'Labels are chapter-prefixed',
    r'Every fact is grounded', r'are grounded in `', r'(?:names|fields) are grounded in',
    r'The chapter starts at', r'is written and (?:saved|grounded)', r'Output file',
]
def trailing_strip(t):
    half = len(t) // 2
    cands = []
    for pat in _TRAIL:
        for mm in re.finditer(pat, t):
            if mm.start() > half:
                cands.append(mm.start())
    if not cands:
        return t
    cut = min(cands)
    # back up to the start of the enclosing paragraph/line
    nl = t.rfind('\n\n', 0, cut)
    if nl <= half:
        nl = t.rfind('\n', 0, cut)
    return (t[:nl] if nl > half else t[:cut]).rstrip()

def inject_figs(t):
    def repl(m):
        lab = m.group(1)
        if lab in FIG:
            return FIG[lab]
        return ("\\uiplaceholder{Figure}{Diagram placeholder.}{%s}{%s}" % (lab.replace('fig:',''), lab))
    return re.sub(r'%%FIG:\s*(fig:[\w:-]+?)\s*%%', repl, t)

def clean_body(t):
    return inject_figs(trailing_strip(cut_to_latex(strip_fences(t)))).strip()

# ---- chapter bodies ----
ch1  = clean_body(rd(BASE + "/ch1_introduction.tex"))
ch2  = clean_body(rd(BASE + "/ch2_literature_review.tex"))
ch3a = clean_body(rd(BASE + "/ch3_partA.tex"))
ch3b = clean_body(inline["ch3b"])
ch4a = clean_body(inline["ch4a"])
ch4b = clean_body(inline["ch4b"])
ch5  = clean_body(rd(BASE + "/chapter5.tex"))

# ---- front matter pieces from 'front' part ----
front = strip_fences(inline["front"])
def seg(name, nxt):
    a = front.find("%%PART:%s%%" % name)
    if a < 0: return ""
    a += len("%%PART:%s%%" % name)
    b = front.find("%%PART:%s%%" % nxt) if nxt else len(front)
    return front[a:b].strip()
abstract = seg("ABSTRACT", "ACRONYMS")
acronyms = seg("ACRONYMS", "REFERENCES")
refs     = seg("REFERENCES", None)

# ---- assemble ----
preamble = rd(BASE + "/_preamble.tex").rstrip()
frontmatter = rd(BASE + "/_frontmatter.tex").rstrip()

ABSTRACT_BLOCK = ("\\chapter*{Abstract}\n\\addcontentsline{toc}{chapter}{Abstract}\n%s\n\\clearpage\n" % abstract)

ACRONYM_BLOCK = (
"\\chapter*{List of Acronyms and Abbreviations}\n"
"\\addcontentsline{toc}{chapter}{List of Acronyms and Abbreviations}\n"
"\\begin{center}\n\\begin{longtable}{|L{2.8cm}|L{11.6cm}|}\n\\hline\n"
+ acronyms + "\n\\end{longtable}\n\\end{center}\n\\clearpage\n"
)

TOC_BLOCK = (
"\\tableofcontents\n\\clearpage\n"
"\\listoffigures\n\\addcontentsline{toc}{chapter}{List of Figures}\n\\clearpage\n"
"\\listoftables\n\\addcontentsline{toc}{chapter}{List of Tables}\n\\clearpage\n"
)

REFS_BLOCK = "\\cleardoublepage\n\\addcontentsline{toc}{chapter}{References}\n" + refs

doc = "\n".join([
    preamble,
    "",
    "\\begin{document}",
    frontmatter,
    ABSTRACT_BLOCK,
    TOC_BLOCK,
    ACRONYM_BLOCK,
    "\\cleardoublepage",
    "\\pagenumbering{arabic}",
    "\\pagestyle{fancy}",
    "",
    ch1, "", ch2, "", ch3a, "", ch3b, "", ch4a, "", ch4b, "", ch5, "",
    REFS_BLOCK,
    "",
    "\\end{document}",
    "",
])

io.open(BASE + "/LuminaFPM_Documentation.tex", "w", encoding="utf-8").write(doc)

# ---- sanity scan ----
def n(s): return doc.count(s)
labels = re.findall(r'\\label\{([^}]+)\}', doc)
dups = sorted(set(l for l in labels if labels.count(l) > 1))
begins = len(re.findall(r'\\begin\{', doc)); ends = len(re.findall(r'\\end\{', doc))
report = []
report.append("WROTE %s/LuminaFPM_Documentation.tex" % BASE)
report.append("chars=%d  words~%d  lines=%d" % (len(doc), len(doc.split()), doc.count(chr(10))+1))
report.append("\\chapter=%d  \\section=%d  \\subsection=%d  longtable=%d  tikzpicture=%d  figure=%d  table refs=%d"
              % (n("\\chapter{"), n("\\section{"), n("\\subsection{"), n("\\begin{longtable}"),
                 n("\\begin{tikzpicture}"), len(re.findall(r'\\begin\{figure\}', doc)), len(re.findall(r'Table~\\ref', doc))))
report.append("\\begin count=%d  \\end count=%d  (should match)" % (begins, ends))
report.append("residual markers: %%FIG=%d  %%PART=%d  ```=%d  fences-latex=%d"
              % (len(re.findall(r'%%FIG:', doc)), len(re.findall(r'%%PART:', doc)), doc.count("```"), doc.count("latex\n")))
report.append("duplicate labels: %s" % (dups if dups else "none"))
report.append("FFFD: %d" % doc.count("�"))
# undefined \ref targets (figs/tables/secs referenced but not labeled)
refd = set(re.findall(r'\\ref\{([^}]+)\}', doc)) | set(re.findall(r'\\Cref\{([^}]+)\}', doc))
lset = set(labels)
missing = sorted(r for r in refd if r not in lset)
report.append("refs with NO matching label: %s" % (missing if missing else "none"))
print("\n".join(report))
