# LuminaFPM — Final Documentation (LaTeX)

**Deliverable:** [`LuminaFPM_Documentation.tex`](LuminaFPM_Documentation.tex) — a single, self‑contained,
compilable LaTeX document (~31,000 words, 5 chapters, 21 tables, 10 TikZ diagrams). It is the full Term‑2
technical documentation for LuminaFPM, structured to the AASTMT B.Sc. final‑year‑project format.

## How to compile

The document compiles with **pdfLaTeX or XeLaTeX** out of the box — it requires **no external image files**
(all figures are either TikZ‑generated or framed placeholders). Run the engine **twice** so the table of
contents, list of figures/tables, and cross‑references resolve:

```bash
pdflatex LuminaFPM_Documentation.tex
pdflatex LuminaFPM_Documentation.tex
```

Or simply upload `LuminaFPM_Documentation.tex` to **Overleaf** (it compiles as‑is). Required packages are all
standard TeX Live: `geometry, titlesec, fancyhdr, booktabs, longtable, tabularx, array, colortbl, multirow,
amsmath, amssymb, enumitem, listings, graphicx, setspace, ragged2e, caption, tikz, hyperref, lmodern`.

## Figures

- **TikZ diagrams** (generated, no image needed): processing pipeline, layered architecture, lab topology,
  context diagram, DFD, ER diagram, anomaly‑detection control flow, end‑to‑end sequence diagram, and the
  two conclusion figures.
- **Placeholders** (a framed box with a caption) for the UML diagrams (use‑case, misuse, class) and the UI
  screenshots (dashboard, audit, topology, risk, reports, benchmark). To use real images: drop the file
  into `figures/` and replace the corresponding `\uiplaceholder{...}` call with
  `\includegraphics[width=0.9\linewidth]{figures/<name>.png}` inside a `figure` environment (a cover logo
  is also optional — place `figures/logo.png` and it appears automatically on the title page).

## Title page

Team and supervisor (Dr. Mohamed Elhamahmy) are filled in from the Term‑1 submission. **Verify the
registration numbers** on the title page / declaration before final submission.

## Regenerating

`_build/` holds the generation scaffolding: the preamble (`_preamble.tex`), front matter
(`_frontmatter.tex`), the figure library (`_figures.tex`), the per‑chapter LaTeX bodies, the assembler
(`_assemble.py`), and the lint scripts. Re‑running `python _build/_assemble.py` (paths relative to the
project root) re‑stitches the single `.tex` from the parts.
