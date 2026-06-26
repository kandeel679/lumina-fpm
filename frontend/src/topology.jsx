import React from "react";
import CytoscapeComponent from "react-cytoscapejs";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { useLFPM } from "./context/LFPMContext";

/* ─────────────────────────────────────────────────────────────────
 * Topology — operational lane diagram on Cytoscape.js
 *
 * Recreates the original vendor-grouped LANE layout (external threat column ▸
 * FortiGate lanes ▸ Palo Alto lanes; each lane = firewall header on top, its
 * zones stacked below, monitored assets inside zones, a device-metrics footer)
 * but on a real graph engine, so it is now:
 *   · draggable (whole lane or an individual zone/asset), wheel-zoom, drag-pan
 *   · persistent — node positions save to localStorage and restore on reload
 *   · a custom "lanes" auto-layout (dagre kept as an optional alternate arrange)
 *
 * Compound nesting models the lane: fwlane ▸ {header, zone ▸ asset, footer}.
 * The firmware-CVE badge is re-sourced from the LIVE CTI firmware_version device
 * axis (LFPM.firmwareCves), not the retired dark-web feed. Every node/edge tap
 * opens the SAME inspector payloads as before (firewall / zone / host / external
 * / path), so the inspector contract is unchanged.
 * ───────────────────────────────────────────────────────────────── */

const { useState, useRef, useMemo, useEffect, useCallback } = React;

try { cytoscape.use(dagre); } catch { /* already registered (HMR re-import) */ }

const LS_KEY = "lumina.topology.positions.v3";
const PRESET_LAYOUT = { name: "preset" };

/* Lane geometry (Cytoscape positions are node CENTERS). */
const L = {
  EXT_X: 110, EXT_H: 74, EXT_GAP: 26, EXT_TOP: 40, EXT_W: 190,
  LANE_X0: 320, LANE_W: 210, LANE_GAP: 60, VENDOR_GAP: 116,
  TOP: 40, HEAD_H: 104, ZONE_HEAD: 30, ASSET_H: 28, ZONE_PAD: 12, ZONE_GAP: 16, FOOT_H: 40,
  SEC_Y: -34,
};
const VENDOR_RANK = { fortinet: 0, "palo-alto": 1 };
const VENDOR_LABEL = { fortinet: "FORTINET", "palo-alto": "PALO ALTO NETWORKS" };

/* ── Theme palette: Cytoscape renders to canvas, so CSS vars must be resolved to
 *    concrete colors. Re-resolved whenever the theme attribute changes. ── */
function resolvePalette() {
  const g = (name, fb) => {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fb;
  };
  return {
    bg0: g("--bg-0", "#0c0d11"), bg1: g("--bg-1", "#0e0f13"), bg2: g("--bg-2", "#16181f"),
    bd1: g("--bd-1", "#23262f"), bd2: g("--bd-2", "#2c2f3a"),
    fg0: g("--fg-0", "#e8e9ee"), fg1: g("--fg-1", "#cdd0d8"), fg2: g("--fg-2", "#aeb2bd"), fg3: g("--fg-3", "#7c818f"),
    accent: g("--accent", "#6ea8fe"),
    critical: g("--sev-critical", "#ff5b6e"), high: g("--sev-high", "#ff9f45"),
    medium: g("--sev-medium", "#ffd24a"), safe: g("--sev-safe", "#3fd08f"),
    palo: g("--vendor-paloalto", "#f5a623"), forti: g("--vendor-fortinet", "#e8443b"),
    unknown: g("--vendor-unknown", "#8a8f9c"),
  };
}

const riskColor = (P, s) => (s >= 80 ? P.critical : s >= 60 ? P.high : s >= 40 ? P.medium : P.safe);
const sevColor = (P, sev) =>
  sev === "critical" ? P.critical : sev === "high" ? P.high : sev === "medium" ? P.medium : P.fg3;
const vendorColor = (P, vId) => (vId === "palo-alto" ? P.palo : vId === "fortinet" ? P.forti : P.unknown);

/* ── localStorage layout persistence (childless nodes only; compounds auto-wrap) ── */
function loadPositions() {
  try { return JSON.parse(localStorage.getItem(LS_KEY)) || {}; } catch { return {}; }
}
function savePositions(cy) {
  if (!cy) return;
  const pos = {};
  cy.nodes().forEach(n => { if (n.isChildless()) pos[n.id()] = { ...n.position() }; });
  try { localStorage.setItem(LS_KEY, JSON.stringify(pos)); } catch { /* quota */ }
}
function clearPositions() { try { localStorage.removeItem(LS_KEY); } catch { /* noop */ } }

const clip = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + "…" : (s || ""));
const vlabel = (vId) => VENDOR_LABEL[vId] || (vId || "other").toUpperCase();
const vrank = (vId) => (VENDOR_RANK[vId] ?? 9);

/* ── Build the Cytoscape elements (compound lanes) from the live LFPM dataset ──
 * fwlane ▸ {fwhead, zone ▸ {asset|empty}, fwfoot}. Node ids are firewall-qualified
 * so a zone/asset present on multiple devices does not collide. */
function buildElements(LFPM, fwCveByDevice) {
  const els = [];
  const fwIds = new Set(LFPM.firewalls.map(f => f.id));
  const fmt = LFPM.fmt || {};
  const riskLabel = typeof fmt.riskLabel === "function" ? fmt.riskLabel : () => "";

  // Section header for the external column
  els.push({ data: { id: "sec:external", type: "section", group: "external", label: "EXTERNAL · THREAT VECTORS" } });

  // Vendor section headers
  const vendorCounts = {};
  LFPM.firewalls.forEach(fw => { vendorCounts[fw.vendorId] = (vendorCounts[fw.vendorId] || 0) + 1; });
  Object.keys(vendorCounts).sort((a, b) => vrank(a) - vrank(b)).forEach(vId => {
    const c = vendorCounts[vId];
    els.push({ data: { id: `sec:${vId}`, type: "section", group: vId, label: `${vlabel(vId)} · ${c} FIREWALL${c === 1 ? "" : "S"}` } });
  });

  // Firewalls → lanes
  LFPM.firewalls.forEach(fw => {
    const cve = fwCveByDevice[fw.id];
    const cveSev = cve ? (cve.critical ? "critical" : cve.worstSeverity) : null;
    els.push({ data: { id: `lane:${fw.id}`, type: "fwlane", vendorId: fw.vendorId, cveSev, fw } });

    const headLabel = [
      fw.display,
      `${fw.model}`,
      `${fw.firmware}`,
      `${fw.ip} · ${fw.zone}`,
      `risk ${fw.riskScore}${riskLabel(fw.riskScore) ? " · " + riskLabel(fw.riskScore) : ""}`
        + (cve ? `   ⚠ ${cve.count} CVE${cve.count === 1 ? "" : "s"}${cve.critical ? ` · ${cve.critical} crit` : ""}` : ""),
    ].join("\n");
    els.push({ data: { id: `fw:${fw.id}`, type: "firewall", parent: `lane:${fw.id}`, vendorId: fw.vendorId, cveSev, label: headLabel, fw } });

    // Footer metrics
    els.push({
      data: {
        id: `meta:${fw.id}`, type: "fwmeta", parent: `lane:${fw.id}`, fw,
        label: `rules ${fw.ruleCount ?? "—"}     ${fw.throughput || ""}`.trim(),
      },
    });

    // Zones for this firewall (zorder preserves natural/policy order, e.g. trust→dmz→db)
    LFPM.zones.filter(z => z.fwId === fw.id).forEach((z, zorder) => {
      const zRisk = Math.max(0, ...LFPM.policies
        .filter(p => p.firewallId === fw.id
          && (String(p.srcZone).toLowerCase() === z.name.toLowerCase()
            || String(p.dstZone).toLowerCase() === z.name.toLowerCase()))
        .map(p => p.riskScore));
      const zid = `zone:${fw.id}:${z.id}`;
      els.push({
        data: {
          id: zid, type: "zone", parent: `lane:${fw.id}`, zRisk, zorder,
          label: `${z.name}${z.subnet ? `   ${clip(z.subnet, 16)}` : ""}`,
          zone: { ...z, fwId: fw.id, fwDisplay: fw.display },
        },
      });
      const zAssets = LFPM.assets.filter(a => a.zoneId === z.id);
      if (zAssets.length === 0) {
        els.push({ data: { id: `empty:${zid}`, type: "empty", parent: zid, label: "no monitored assets" } });
      } else {
        zAssets.forEach(a => {
          els.push({
            data: {
              id: `asset:${fw.id}:${z.id}:${a.id}`, type: "asset", parent: zid, assetKind: a.kind,
              label: `${clip(a.name, 15)}   ${a.ip}`, asset: a,
            },
          });
        });
      }
    });
  });

  // External threat indicators (live CTI) + their correlation (threat) edges
  LFPM.externalNodes.forEach(n => {
    els.push({
      data: { id: `ext:${n.id}`, type: "external", threat: n.threat, ext: n,
        label: `${clip(n.name, 20)}\n${n.kind}` },
    });
    (n.targetFwIds || []).forEach(fwId => {
      if (!fwIds.has(String(fwId))) return;
      const edge = { id: `${n.id}->${fwId}`, sourceId: n.id, targetFwId: String(fwId), severity: n.threat, kind: "threat" };
      els.push({
        data: { id: `edge:${n.id}->${fwId}`, source: `ext:${n.id}`, target: `fw:${fwId}`, severity: n.threat, kind: "threat", edge },
      });
    });
  });

  return els;
}

/* ── Custom "lanes" layout: external column on the left, then vendor-grouped
 *    firewall lanes (header ▸ zones ▸ footer), reproducing the original SVG. ── */
function laneLayout(cy) {
  cy.batch(() => {
    // External column
    const exts = cy.nodes('[type="external"]');
    exts.forEach((n, i) => n.position({ x: L.EXT_X, y: L.EXT_TOP + L.EXT_H / 2 + i * (L.EXT_H + L.EXT_GAP) }));
    const extSec = cy.getElementById("sec:external");
    if (extSec.nonempty()) extSec.position({ x: L.EXT_X, y: L.SEC_Y });

    // Lanes, ordered by vendor then device id
    const lanes = cy.nodes('[type="fwlane"]').sort((a, b) => {
      const dv = vrank(a.data("vendorId")) - vrank(b.data("vendorId"));
      return dv !== 0 ? dv : Number(a.data("fw").id) - Number(b.data("fw").id);
    });

    let leftX = L.LANE_X0;
    let prevVendor = null;
    const groupSpan = {}; // vendorId -> {minX, maxX}
    lanes.forEach(lane => {
      const vId = lane.data("vendorId");
      if (prevVendor !== null && prevVendor !== vId) leftX += L.VENDOR_GAP;
      prevVendor = vId;
      const cx = leftX + L.LANE_W / 2;

      // header
      const head = cy.getElementById(`fw:${lane.data("fw").id}`);
      head.position({ x: cx, y: L.TOP + L.HEAD_H / 2 });
      let y = L.TOP + L.HEAD_H + L.ZONE_GAP;

      // zones (direct child zone nodes of this lane)
      lane.children('[type="zone"]').sort((a, b) => (a.data("zorder") ?? 0) - (b.data("zorder") ?? 0)).forEach(zone => {
        const leaves = zone.children();
        const n = Math.max(1, leaves.length);
        leaves.forEach((leaf, i) => leaf.position({ x: cx, y: y + L.ZONE_HEAD + L.ASSET_H / 2 + i * L.ASSET_H }));
        y += L.ZONE_HEAD + n * L.ASSET_H + L.ZONE_PAD + L.ZONE_GAP;
      });

      // footer
      const foot = cy.getElementById(`meta:${lane.data("fw").id}`);
      if (foot.nonempty()) foot.position({ x: cx, y: y + L.FOOT_H / 2 });

      const span = groupSpan[vId] || { minX: leftX, maxX: leftX + L.LANE_W };
      span.minX = Math.min(span.minX, leftX);
      span.maxX = Math.max(span.maxX, leftX + L.LANE_W);
      groupSpan[vId] = span;

      leftX += L.LANE_W + L.LANE_GAP;
    });

    // Vendor section headers centred over their group
    Object.entries(groupSpan).forEach(([vId, span]) => {
      const sec = cy.getElementById(`sec:${vId}`);
      if (sec.nonempty()) sec.position({ x: (span.minX + span.maxX) / 2, y: L.SEC_Y });
    });
  });
}

/* ── Cytoscape stylesheet (resolved colors) ── */
function buildStylesheet(P) {
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "font-family": "var(--f-mono), ui-monospace, monospace",
        "font-size": 10.5, color: P.fg1, "text-wrap": "wrap",
        "text-valign": "center", "text-halign": "center",
        "border-width": 1, "border-color": P.bd2, "background-color": P.bg2,
        shape: "round-rectangle", "transition-property": "opacity", "transition-duration": "120ms",
      },
    },
    // Lane background (compound)
    {
      selector: 'node[type="fwlane"]',
      style: {
        label: "", "background-color": P.bg1, "background-opacity": 0.45,
        "border-width": 1, "border-color": P.bd1, padding: "10px", shape: "round-rectangle",
      },
    },
    // Firewall header
    {
      selector: 'node[type="firewall"]',
      style: {
        "text-valign": "center", "text-halign": "center", "text-wrap": "wrap", "text-max-width": 188,
        "font-size": 11, "font-weight": 600, color: P.fg0,
        width: L.LANE_W - 18, height: L.HEAD_H - 12,
        "background-color": P.bg2,
        "border-width": 2, "border-color": (ele) => vendorColor(P, ele.data("vendorId")),
      },
    },
    { selector: 'node[type="firewall"][cveSev]', style: { "border-color": (ele) => sevColor(P, ele.data("cveSev")), "border-width": 2.5 } },
    // Zone (compound)
    {
      selector: 'node[type="zone"]',
      style: {
        "text-valign": "top", "text-halign": "center", "text-margin-y": 4,
        "font-size": 10, "font-weight": 600, color: P.fg2, "text-max-width": 190,
        "min-width": L.LANE_W - 18, "background-color": P.bg2, "background-opacity": 0.7,
        "border-width": 1.5, "border-color": (ele) => riskColor(P, ele.data("zRisk") || 0), padding: "8px",
      },
    },
    // Asset leaf
    {
      selector: 'node[type="asset"]',
      style: {
        "font-size": 9.5, color: P.fg2, "text-max-width": L.LANE_W - 44,
        width: L.LANE_W - 40, height: L.ASSET_H - 6,
        "background-color": P.bg0, "border-color": P.bd1,
      },
    },
    { selector: 'node[type="asset"][assetKind="db"]', style: { "border-color": P.accent } },
    // Empty-zone placeholder
    {
      selector: 'node[type="empty"]',
      style: {
        "font-size": 9.5, color: P.fg3, "background-opacity": 0, "border-width": 0,
        width: L.LANE_W - 40, height: L.ASSET_H - 6,
      },
    },
    // Footer metrics
    {
      selector: 'node[type="fwmeta"]',
      style: {
        "font-size": 9.5, color: P.fg3, "text-transform": "uppercase",
        width: L.LANE_W - 18, height: L.FOOT_H - 14,
        "background-opacity": 0, "border-width": 0,
      },
    },
    // Section headers
    {
      selector: 'node[type="section"]',
      style: {
        "font-size": 11, "font-weight": 600, color: P.fg3, "text-transform": "uppercase",
        "background-opacity": 0, "border-width": 0, width: "label", height: 14,
        "text-valign": "center", "text-halign": "center", events: "no",
      },
    },
    // External threat indicator
    {
      selector: 'node[type="external"]',
      style: {
        "font-size": 11, color: P.fg0, "text-max-width": L.EXT_W - 20,
        width: L.EXT_W, height: L.EXT_H, padding: "6px", "background-color": P.bg2,
        "border-width": 1.5, "border-color": (ele) => sevColor(P, ele.data("threat")),
      },
    },
    // Threat edges
    {
      selector: 'edge[kind="threat"]',
      style: {
        "curve-style": "bezier", width: 1.6,
        "line-color": (ele) => sevColor(P, ele.data("severity")),
        "target-arrow-color": (ele) => sevColor(P, ele.data("severity")),
        "target-arrow-shape": "triangle", "arrow-scale": 1,
        opacity: 0.85, "transition-property": "opacity", "transition-duration": "120ms",
      },
    },
    { selector: 'edge[kind="threat"][severity="critical"]', style: { width: 2.4 } },
    { selector: 'edge[kind="threat"][severity="high"]', style: { width: 1.9 } },
    // Selection / focus
    { selector: ".emph", style: { opacity: 1, "z-index": 20 } },
    { selector: 'node[type="firewall"].emph', style: { "border-color": P.accent } },
    { selector: 'node[type="zone"].emph', style: { "border-width": 2 } },
    { selector: "edge.emph", style: { opacity: 1, width: 2.8 } },
    { selector: ".dim", style: { opacity: 0.12 } },
    { selector: "edge.dim", style: { opacity: 0.05 } },
    { selector: ".nolabel", style: { "text-opacity": 0 } },
  ];
}

/* ── Main page ── */
function Topology({ openInspector, intent }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const topoRef = useRef(null);
  const [cyi, setCyi] = useState(null);
  const [palette, setPalette] = useState(() => resolvePalette());
  const [selected, setSelected] = useState(null); // { cyId, kind, label }
  const [sevFilter, setSevFilter] = useState("all"); // all | high | crit
  const [layer, setLayer] = useState({ threats: true, labels: true });

  useEffect(() => {
    const obs = new MutationObserver(() => setPalette(resolvePalette()));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "data-theme", "style"] });
    return () => obs.disconnect();
  }, []);

  const fwCveByDevice = useMemo(() => {
    const out = {};
    (LFPM.firmwareCves || []).forEach(fc => { out[fc.deviceId] = fc; });
    return out;
  }, [LFPM.firmwareCves]);

  const elements = useMemo(
    () => buildElements(LFPM, fwCveByDevice),
    [LFPM.firewalls, LFPM.zones, LFPM.assets, LFPM.externalNodes, LFPM.policies, fwCveByDevice]
  );
  const stylesheet = useMemo(() => buildStylesheet(palette), [palette]);

  const lookups = useMemo(() => ({
    extById: new Map(LFPM.externalNodes.map(n => [n.id, n])),
    fwById: new Map(LFPM.firewalls.map(f => [f.id, f])),
  }), [LFPM.externalNodes, LFPM.firewalls]);

  /* Layout: restore saved positions if the full childless set is present, else lanes. */
  const runLayout = useCallback((cy, { mode = "auto" } = {}) => {
    if (!cy || cy.nodes().empty()) return;
    cy.resize();
    if (mode === "dagre") {
      cy.layout({ name: "dagre", rankDir: "LR", nodeSep: 16, rankSep: 90, padding: 24, animate: false, fit: false }).run();
      savePositions(cy);
    } else {
      const saved = loadPositions();
      const leaves = cy.nodes().filter(n => n.isChildless());
      const ids = leaves.map(n => n.id());
      const haveAll = mode !== "lanes" && ids.length > 0 && ids.every(id => saved[id]);
      if (haveAll) {
        cy.batch(() => leaves.forEach(n => { if (saved[n.id()]) n.position(saved[n.id()]); }));
      } else {
        laneLayout(cy);
        savePositions(cy);
      }
    }
    cy.fit(undefined, 40);
  }, []);

  useEffect(() => {
    if (!cyi) return;
    runLayout(cyi);
    const t = setTimeout(() => { cyi.resize(); cyi.fit(undefined, 40); }, 80);
    return () => clearTimeout(t);
  }, [cyi, elements, runLayout]);

  useEffect(() => {
    if (!cyi || !topoRef.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => cyi.resize());
    ro.observe(topoRef.current);
    return () => ro.disconnect();
  }, [cyi]);

  /* Tap handlers — preserve the exact inspector payloads. */
  useEffect(() => {
    if (!cyi) return;
    const onNode = (evt) => {
      const d = evt.target.data();
      let payload = null, kind = null, label = "", cyId = evt.target.id();
      if (d.type === "firewall" || d.type === "fwlane" || d.type === "fwmeta") {
        payload = { kind: "firewall", data: d.fw }; kind = "firewall"; label = d.fw.display;
        cyId = `fw:${d.fw.id}`;
      } else if (d.type === "zone") { payload = { kind: "zone", data: d.zone }; kind = "zone"; label = d.zone.name; }
      else if (d.type === "asset") { payload = { kind: "host", data: d.asset }; kind = "host"; label = d.asset.name; }
      else if (d.type === "external") { payload = { kind: "external", data: d.ext }; kind = "external"; label = d.ext.name; }
      else return; // section / empty — not interactive
      setSelected({ cyId, kind, label });
      if (payload) openInspector?.(payload);
    };
    const onEdge = (evt) => {
      const e = evt.target.data("edge");
      if (!e) return;
      const ext = lookups.extById.get(e.sourceId);
      const fw = lookups.fwById.get(e.targetFwId);
      setSelected({ cyId: evt.target.id(), kind: "path", label: `${ext?.name || e.sourceId} → ${fw?.display || e.targetFwId}` });
      openInspector?.({ kind: "path", data: { edge: e, ext, fw } });
    };
    const onBg = (evt) => { if (evt.target === cyi) setSelected(null); };
    const onDragfree = () => savePositions(cyi);
    cyi.on("tap", "node", onNode);
    cyi.on("tap", "edge", onEdge);
    cyi.on("tap", onBg);
    cyi.on("dragfree", "node", onDragfree);
    return () => {
      cyi.removeListener("tap", "node", onNode);
      cyi.removeListener("tap", "edge", onEdge);
      cyi.removeListener("tap", onBg);
      cyi.removeListener("dragfree", "node", onDragfree);
    };
  }, [cyi, openInspector, lookups]);

  /* Focus / dim on selection — highlight the whole lane + its threat paths. */
  useEffect(() => {
    if (!cyi) return;
    cyi.batch(() => {
      cyi.elements().removeClass("dim").removeClass("emph");
      if (!selected) return;
      const ele = cyi.getElementById(selected.cyId);
      if (!ele || ele.empty()) return;
      let rel;
      if (ele.isEdge()) {
        const ends = ele.connectedNodes();
        rel = ele.union(ends).union(ends.ancestors()).union(ends.ancestors().descendants()).union(ends.descendants());
      } else {
        const fam = ele.union(ele.ancestors()).union(ele.descendants());
        const lane = fam.union(ele.ancestors().descendants());
        const edges = lane.connectedEdges();
        const ext = edges.connectedNodes();
        rel = lane.union(edges).union(ext).union(ext.ancestors()).union(ext.descendants());
      }
      cyi.elements().addClass("dim");
      rel.removeClass("dim").addClass("emph");
    });
  }, [cyi, selected, elements]);

  /* Severity filter + layer toggles. */
  useEffect(() => {
    if (!cyi) return;
    cyi.batch(() => {
      cyi.edges().forEach(e => {
        if (e.data("kind") !== "threat") { e.style("display", "element"); return; }
        const sev = e.data("severity");
        let vis = layer.threats;
        if (vis && sevFilter === "crit") vis = sev === "critical";
        if (vis && sevFilter === "high") vis = sev === "critical" || sev === "high";
        e.style("display", vis ? "element" : "none");
      });
      if (layer.labels) cyi.elements().removeClass("nolabel");
      else cyi.elements().addClass("nolabel");
    });
  }, [cyi, sevFilter, layer, elements]);

  /* Deep-link intent: #topology?device=<id> → select + inspect + center. */
  useEffect(() => {
    if (!cyi || !intent?.device) return;
    const node = cyi.getElementById(`fw:${intent.device}`);
    if (!node || node.empty()) return;
    const fw = lookups.fwById.get(String(intent.device));
    setSelected({ cyId: node.id(), kind: "firewall", label: fw ? fw.display : intent.device });
    if (fw) openInspector?.({ kind: "firewall", data: fw });
    cyi.animate({ center: { eles: node }, zoom: Math.max(cyi.zoom(), 0.85) }, { duration: 300 });
  }, [cyi, intent, lookups, openInspector]);

  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") setSelected(null); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  const onLanes = useCallback(() => {
    if (!cyi) return;
    runLayout(cyi, { mode: "lanes" });
    window.toast?.("Lanes layout", { kind: "info", sub: "positions saved" });
  }, [cyi, runLayout]);
  const onDagre = useCallback(() => {
    if (!cyi) return;
    runLayout(cyi, { mode: "dagre" });
    window.toast?.("Auto-arranged", { kind: "info", sub: "dagre layout · positions saved" });
  }, [cyi, runLayout]);
  const onResetLayout = useCallback(() => {
    clearPositions();
    if (cyi) runLayout(cyi, { mode: "lanes" });
    setSelected(null);
    window.toast?.("Layout reset", { kind: "info", sub: "saved positions cleared" });
  }, [cyi, runLayout]);
  const onFit = useCallback(() => { cyi?.fit(undefined, 40); }, [cyi]);

  const onExport = useCallback(() => {
    if (!cyi) { window.toast?.("Export failed", { kind: "err", sub: "canvas not ready" }); return; }
    try {
      const png = cyi.png({ full: true, scale: 2, bg: palette.bg0 });
      const fname = `topology-${new Date().toISOString().slice(0, 10)}.png`;
      const a = document.createElement("a");
      a.href = png; a.download = fname;
      document.body.appendChild(a); a.click(); a.remove();
      window.toast?.("Topology exported", { kind: "ok", sub: `${fname} · ${LFPM.firewalls.length} fw · ${LFPM.zones.length} zones` });
    } catch (err) {
      window.toast?.("Export failed", { kind: "err", sub: String(err).slice(0, 80) });
    }
  }, [cyi, palette, LFPM.firewalls.length, LFPM.zones.length]);

  const vulnDevices = (LFPM.firmwareCves || []).length;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Network Topology</h1>
          <p className="page-sub">
            {LFPM.firewalls.length} firewalls · {LFPM.zones.length} zones · {LFPM.assets.length} monitored assets · {LFPM.externalNodes.length} active threat vector{LFPM.externalNodes.length === 1 ? "" : "s"}
            {vulnDevices ? ` · ${vulnDevices} device${vulnDevices === 1 ? "" : "s"} with vulnerable firmware` : ""}
          </p>
        </div>
        <div className="row gap-2" style={{ marginLeft: "auto" }}>
          <div className="seg">
            <button className={sevFilter === "all" ? "active" : ""} onClick={() => setSevFilter("all")}>all paths</button>
            <button className={sevFilter === "high" ? "active" : ""} onClick={() => setSevFilter("high")}>≥ high</button>
            <button className={sevFilter === "crit" ? "active" : ""} onClick={() => setSevFilter("crit")}>critical</button>
          </div>
          <button className="btn" onClick={onLanes}>{I?.Columns ? <I.Columns size={13} /> : null} lanes</button>
          <button className="btn" onClick={onDagre}>{I?.Shuffle ? <I.Shuffle size={13} /> : null} dagre</button>
          <button className="btn" onClick={onFit}>{I?.Maximize ? <I.Maximize size={13} /> : null} fit</button>
          <button className="btn" onClick={onResetLayout}>{I?.RotateCcw ? <I.RotateCcw size={13} /> : null} reset</button>
          <button className="btn" onClick={onExport}>{I?.Download ? <I.Download size={13} /> : null} export</button>
        </div>
      </div>

      <div className="topo" ref={topoRef} style={{ flex: 1, minHeight: 0, position: "relative" }}>
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet}
          layout={PRESET_LAYOUT}
          cy={(cy) => { if (cy && cy !== cyi) setCyi(cy); }}
          style={{ width: "100%", height: "100%" }}
          wheelSensitivity={0.2}
          minZoom={0.15}
          maxZoom={2.5}
          boxSelectionEnabled={false}
        />

        <div className="topo-layers">
          <div className="head" style={{ marginBottom: 4 }}>layers</div>
          <Toggle label="threat paths" on={layer.threats} onChange={() => setLayer(l => ({ ...l, threats: !l.threats }))} />
          <Toggle label="labels" on={layer.labels} onChange={() => setLayer(l => ({ ...l, labels: !l.labels }))} />
          <div className="head" style={{ marginTop: 6, opacity: 0.7, fontSize: 9.5 }}>drag nodes · scroll to zoom</div>
        </div>

        <div className="topo-legend">
          <div className="head">legend</div>
          <div className="sub">threat paths</div>
          <div className="row"><span className="swatch-line" style={{ background: "var(--sev-critical)" }} /> critical</div>
          <div className="row"><span className="swatch-line" style={{ background: "var(--sev-high)" }} /> high</div>
          <div className="sub">firewalls</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--vendor-fortinet)" }} /> fortigate</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--vendor-paloalto)" }} /> palo alto</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--sev-high)" }} /> vulnerable firmware</div>
          <div className="sub">zones · risk</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--sev-safe)" }} /> healthy</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--sev-medium)" }} /> medium</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--sev-high)" }} /> high</div>
          <div className="row"><span className="swatch-dot" style={{ background: "var(--sev-critical)" }} /> critical</div>
        </div>

        {selected && (
          <div className="topo-pill">
            <span className="kind">{selected.kind}</span>
            <span className="id">{selected.label}</span>
            <span className="clear" onClick={() => setSelected(null)}>
              {I?.Close ? <I.Close size={11} /> : "×"} clear (esc)
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function Toggle({ label, on, onChange }) {
  return (
    <div className="toggle-row" onClick={onChange}>
      <span style={{
        width: 22, height: 12, borderRadius: 6,
        background: on ? "var(--accent-bg)" : "var(--bg-3)",
        border: `1px solid ${on ? "var(--accent-bd)" : "var(--bd-2)"}`,
        position: "relative", transition: "all 140ms", flexShrink: 0,
      }}>
        <span style={{
          position: "absolute", top: 1, left: on ? 11 : 1,
          width: 8, height: 8, borderRadius: 4,
          background: on ? "var(--accent)" : "var(--fg-3)",
          transition: "left 140ms",
        }} />
      </span>
      <span className="label">{label}</span>
    </div>
  );
}

export { Topology };
