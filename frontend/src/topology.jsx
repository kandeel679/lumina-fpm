import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
/* ─────────────────────────────────────────────────────────────────
 * Topology — operational network diagram
 *
 * Single SVG canvas, hand-laid grid.
 *
 *   Left rail  ·  external & threat sources (4 nodes)
 *   Right side ·  5 firewall lanes (vendor stripe + header + zones + assets)
 *
 * - Threat edges fan into each firewall's "ingress strip" so multiple
 *   paths don't overlap at the same point.
 * - Grouped edges by default (1 edge per source → target firewall).
 * - Focus mode: clicking a node dims the rest; only related edges and
 *   their endpoints stay opaque. Subtle dash flow on selected risky paths.
 * - Static otherwise; no decorative motion.
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateT, useRef: useRefT, useMemo: useMemoT, useCallback: useCallbackT } = React;

/* ── Geometry ─────────────────────────────────────────────────── */
const TOPO = {
  W: 1280,
  H: 600,
  bandY: 28,
  bandLineY: 42,
  vendorBandY: 70,
  externalX: 18,
  externalW: 210,
  externalH: 76,
  externalGap: 16,
  externalStartY: 90,
  lanesStart: 252,
  laneW: 188,
  laneGap: 20,
  laneVendorGap: 32,    // extra gap between PA and FT groups
  fwY: 90,
  fwH: 110,
  laneContentTop: 212,
  laneBottom: 562,
  laneFooterH: 56,      // metrics strip at lane bottom
  zoneHeaderH: 32,
  zoneGap: 8,
  zonePadding: 8,
  assetH: 28,
  ingressFan: 38,
};

/* Compute x positions per firewall with a wider gap between vendor groups */
function computeLanePositions(firewalls) {
  const xs = {};
  let x = TOPO.lanesStart;
  let prevVendor = null;
  firewalls.forEach(fw => {
    if (prevVendor && prevVendor !== fw.vendorId) {
      x += TOPO.laneVendorGap - TOPO.laneGap;
    }
    xs[fw.id] = x;
    x += TOPO.laneW + TOPO.laneGap;
    prevVendor = fw.vendorId;
  });
  return xs;
}

/* ── Asset icons (12×12) ──────────────────────────────────────── */
function AssetIcon({ kind, color = 'currentColor' }) {
  const s = { fill: 'none', stroke: color, strokeWidth: 1.2, strokeLinecap: 'round', strokeLinejoin: 'round' };
  switch (kind) {
    case 'web':
      return (
        <g style={s}>
          <circle cx="6" cy="6" r="4.5" />
          <path d="M1.5 6 H10.5" />
          <path d="M6 1.5 Q9 6 6 10.5 M6 1.5 Q3 6 6 10.5" />
        </g>
      );
    case 'app':
      return (
        <g style={s}>
          <rect x="1.5" y="2" width="9" height="3.5" rx="0.7" />
          <rect x="1.5" y="6.5" width="9" height="3.5" rx="0.7" />
          <circle cx="3.4" cy="3.75" r="0.55" fill={color} stroke="none" />
          <circle cx="3.4" cy="8.25" r="0.55" fill={color} stroke="none" />
          <path d="M8 3.75 H9.4 M8 8.25 H9.4" strokeWidth="0.9" />
        </g>
      );
    case 'db':
      return (
        <g style={s}>
          <ellipse cx="6" cy="2.4" rx="4" ry="1.4" />
          <path d="M2 2.4 V9.6 Q2 11 6 11 Q10 11 10 9.6 V2.4" />
          <path d="M2 5.6 Q2 7 6 7 Q10 7 10 5.6" />
        </g>
      );
    case 'mail':
      return (
        <g style={s}>
          <rect x="1.2" y="2.6" width="9.6" height="6.8" rx="0.6" />
          <polyline points="1.6,3.2 6,7 10.4,3.2" />
        </g>
      );
    case 'host':
      return (
        <g style={s}>
          <rect x="1.2" y="1.6" width="9.6" height="6.6" rx="0.6" />
          <path d="M4.2 11 H7.8" />
          <path d="M6 8.2 V11" />
        </g>
      );
    case 'vlan':
      return (
        <g style={s}>
          <rect x="1.5" y="2" width="9" height="8" rx="0.7" />
          <path d="M3.5 4.5 H8.5 M3.5 6 H8.5 M3.5 7.5 H6" />
        </g>
      );
    default:
      return (
        <g style={s}>
          <circle cx="6" cy="6" r="3.5" />
          <circle cx="6" cy="6" r="1" fill={color} stroke="none" />
        </g>
      );
  }
}

/* Map data.assets.kind to a display group */
const KIND_TO_ICON = {
  web: 'web', app: 'app', db: 'db', mail: 'mail', host: 'host',
};
function getAssetIconKind(asset) {
  if (asset.kind === 'host' && /vlan|office/i.test(asset.name)) return 'vlan';
  return KIND_TO_ICON[asset.kind] || 'host';
}

/* ── External / threat icons (14×14) ─────────────────────────── */
function ExternalIcon({ kind, color = 'currentColor' }) {
  const s = { fill: 'none', stroke: color, strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' };
  switch (kind) {
    case 'internet':
      return (
        <g style={s}>
          <circle cx="7" cy="7" r="5.5" />
          <path d="M1.5 7 H12.5" />
          <path d="M7 1.5 Q10.6 7 7 12.5 M7 1.5 Q3.4 7 7 12.5" />
        </g>
      );
    case 'suspicious':
      return (
        <g style={s}>
          <path d="M7 1.5 L12.5 12 H1.5 Z" />
          <path d="M7 5.5 V8.5" strokeWidth="1.6" />
          <circle cx="7" cy="10.6" r="0.55" fill={color} stroke="none" />
        </g>
      );
    case 'c2':
      return (
        <g style={s}>
          <circle cx="7" cy="7" r="5.5" />
          <path d="M7 1 V4 M7 10 V13 M1 7 H4 M10 7 H13" />
          <circle cx="7" cy="7" r="1.2" fill={color} stroke="none" />
        </g>
      );
    case 'threat':
      return (
        <g style={s}>
          <circle cx="7" cy="7" r="5.5" />
          <circle cx="7" cy="7" r="2.8" />
          <path d="M7 7 L11 3" strokeWidth="1.6" />
        </g>
      );
    default:
      return (
        <g style={s}>
          <circle cx="7" cy="7" r="5.5" />
        </g>
      );
  }
}

/* ── Section header band ──────────────────────────────────────── */
function SectionBand({ lanePositions, firewalls }) {
  const { externalX, externalW, bandY, bandLineY, vendorBandY, laneW } = TOPO;
  const lblStyle = {
    fontFamily: 'var(--f-mono)',
    fontSize: 11,
    fill: 'var(--fg-3)',
    letterSpacing: '2px',
    textTransform: 'uppercase',
  };

  /* Compute span for each vendor group */
  const vendors = Array.from(new Set(firewalls.map(f => f.vendorId).filter(Boolean)));
  const groups = vendors.map(vId => {
    const fws = firewalls.filter(f => f.vendorId === vId);
    if (!fws.length) return null;
    const start = lanePositions[fws[0].id];
    const end = lanePositions[fws[fws.length - 1].id] + laneW;
    const color = vId === 'palo-alto' ? 'var(--vendor-paloalto)'
      : vId === 'fortinet' ? 'var(--vendor-fortinet)'
      : vId === 'cisco' ? 'var(--vendor-cisco)' : 'var(--vendor-unknown)';
    const label = vId === 'palo-alto' ? 'palo alto networks'
      : vId === 'fortinet' ? 'fortinet' : vId === 'cisco' ? 'cisco' : vId;
    return { vId, start, end, color, label, count: fws.length };
  }).filter(Boolean);

  return (
    <g>
      {/* Left section label */}
      <text x={externalX} y={bandY} style={lblStyle}>external · threat vectors</text>
      <line x1={externalX} y1={bandLineY} x2={externalX + externalW} y2={bandLineY} stroke="var(--bd-2)" />

      {/* Vendor section labels — each group gets a vendor-colored line + label */}
      {groups.map(g => (
        <g key={g.vId}>
          <line
            x1={g.start - 4} y1={bandLineY}
            x2={g.end + 4}   y2={bandLineY}
            stroke={g.color}
            strokeOpacity="0.45"
            strokeWidth="1"
          />
          <text x={g.start - 4} y={bandY} style={{ ...lblStyle, fill: g.color, opacity: 0.85 }}>
            {g.label} · {g.count} firewall{g.count === 1 ? '' : 's'}
          </text>
          <text
            x={g.end + 4} y={bandY}
            textAnchor="end"
            style={{ fontFamily:'var(--f-mono)', fontSize: 10, fill:'var(--fg-muted)' }}
          >
            firewall · zone · asset
          </text>
        </g>
      ))}
    </g>
  );
}

/* ── Compute geometry per lane (zone & asset positions) ──────── */
function layoutLane(fw, x, allZones, allAssets) {
  const zones = allZones.filter(z => z.fwId === fw.id);
  let y = TOPO.laneContentTop;
  const laidZones = zones.map(z => {
    const zAssets = allAssets.filter(a => a.zoneId === z.id);
    const blockH = TOPO.zoneHeaderH + TOPO.zonePadding + Math.max(1, zAssets.length) * TOPO.assetH + TOPO.zonePadding;
    const positioned = {
      ...z,
      y,
      blockH,
      assets: zAssets.map((a, ai) => ({
        ...a,
        y: y + TOPO.zoneHeaderH + TOPO.zonePadding + ai * TOPO.assetH,
      })),
    };
    y += blockH + TOPO.zoneGap;
    return positioned;
  });
  return { fw, x, zones: laidZones };
}

/* ── Compute focus set for a selection or hover ──────────────── */
function computeFocus(target, edges, allZones, allAssets) {
  if (!target) return null;
  const focusNodes = new Set([target.id]);
  const focusEdges = new Set();
  const animEdges = new Set();

  const addFwSubtree = (fwId) => {
    focusNodes.add(fwId);
    allZones.filter(z => z.fwId === fwId).forEach(z => {
      focusNodes.add(z.id);
      allAssets.filter(a => a.zoneId === z.id).forEach(a => focusNodes.add(a.id));
    });
  };

  if (target.kind === 'firewall') {
    addFwSubtree(target.id);
    edges.forEach(e => {
      if (e.targetFwId === target.id) {
        focusEdges.add(e.id);
        focusNodes.add(e.sourceId);
        if (e.severity === 'critical' || e.severity === 'high') animEdges.add(e.id);
      }
    });
  } else if (target.kind === 'external') {
    edges.forEach(e => {
      if (e.sourceId === target.id) {
        focusEdges.add(e.id);
        addFwSubtree(e.targetFwId);
        if (e.severity === 'critical' || e.severity === 'high') animEdges.add(e.id);
      }
    });
  } else if (target.kind === 'asset' || target.kind === 'zone') {
    const asset = target.kind === 'asset' ? allAssets.find(a => a.id === target.id) : null;
    const zone  = target.kind === 'zone'  ? allZones.find(z => z.id === target.id) : allZones.find(z => z.id === asset?.zoneId);
    if (zone) {
      focusNodes.add(zone.id);
      allAssets.filter(a => a.zoneId === zone.id).forEach(a => focusNodes.add(a.id));
      focusNodes.add(zone.fwId);
      edges.forEach(e => {
        if (e.targetFwId === zone.fwId) {
          focusEdges.add(e.id);
          focusNodes.add(e.sourceId);
          if (e.severity === 'critical' || e.severity === 'high') animEdges.add(e.id);
        }
      });
    }
  }
  return { focusNodes, focusEdges, animEdges };
}

/* ── Main page ────────────────────────────────────────────────── */
function Topology({ openInspector, intent, goTo }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const topoRef = useRefT(null);
  const svgRef = useRefT(null);
  const [tip, setTip] = useStateT(null);
  const [hover, setHover] = useStateT(null);     // { id, kind }  — active when no selection
  const [selected, setSelected] = useStateT(null); // { id, kind, label } — sticky
  const [layer, setLayer] = useStateT({
    threats: true,
    structure: true,
    labels: true,
  });
  const [sevFilter, setSevFilter] = useStateT('all'); // all | high | crit

  /* Apply deep-link intent: #topology?device=fw-004
   * Selects the firewall on the canvas + opens the inspector. */
  React.useEffect(() => {
    if (!intent?.device) return;
    const fw = LFPM.firewalls.find(f => f.id === intent.device);
    if (!fw) return;
    setSelected({ id: fw.id, kind: 'firewall', label: fw.display });
    openInspector?.({ kind:'firewall', data: fw });
  }, [intent]);

  /* Lanes & geometry */
  const lanePositions = useMemoT(
    () => computeLanePositions(LFPM.firewalls),
    [LFPM.firewalls]
  );
  const lanes = useMemoT(() => {
    return LFPM.firewalls.map(fw =>
      layoutLane(fw, lanePositions[fw.id], LFPM.zones, LFPM.assets)
    );
  }, [lanePositions, LFPM.firewalls, LFPM.zones, LFPM.assets]);

  /* External nodes */
  const externals = useMemoT(() =>
    LFPM.externalNodes.map((n, i) => ({
      ...n,
      x: TOPO.externalX,
      y: TOPO.externalStartY + i * (TOPO.externalH + TOPO.externalGap),
    })),
  [LFPM.externalNodes]);

  /* CVEs & cumulative metrics per firewall lane */
  const laneMeta = useMemoT(() => {
    const out = {};
    lanes.forEach(lane => {
      const cves = LFPM.threats.filter(t => t.firewallIds.includes(lane.fw.id));
      const kev  = cves.filter(c => c.kev).length;
      const rules = LFPM.policies.filter(p => p.firewallId === lane.fw.id).length;
      const anomalies = LFPM.policies.filter(p => p.firewallId === lane.fw.id && p.status !== 'clean').length;
      out[lane.fw.id] = { cves: cves.length, kev, rules, anomalies };
    });
    return out;
  }, [lanes, LFPM.threats, LFPM.policies]);

  /* Build edges (one per external → fw). Targets are the real devices the engine
   * correlated the malicious indicator to (CTI threat_exposure), not a mock map. */
  const edges = useMemoT(() => {
    const out = [];
    externals.forEach(ext => {
      (ext.targetFwIds || []).forEach(fwId => {
        out.push({
          id: `${ext.id}->${fwId}`,
          sourceId: ext.id,
          targetFwId: fwId,
          severity: ext.threat,
          kind: 'threat',
        });
      });
    });
    return out;
  }, [externals]);

  /* Per-firewall ingress slot assignment (so multiple edges to same fw fan out) */
  const ingressMap = useMemoT(() => {
    const byFw = {};
    edges.forEach(e => { (byFw[e.targetFwId] ||= []).push(e); });
    const map = {};
    Object.entries(byFw).forEach(([fwId, list]) => {
      list.forEach((e, i) => {
        const n = list.length;
        const center = (n - 1) / 2;
        const offset = (i - center) * (TOPO.ingressFan / Math.max(n, 1));
        map[e.id] = offset;
      });
    });
    return map;
  }, [edges]);

  /* Focus calculation */
  const activeTarget = selected || hover;
  const focus = useMemoT(
    () => computeFocus(activeTarget, edges, LFPM.zones, LFPM.assets),
    [activeTarget, edges, LFPM.zones, LFPM.assets]
  );

  /* Visibility filters for edges */
  const isEdgeVisible = (e) => {
    if (e.kind === 'threat' && !layer.threats) return false;
    if (e.kind === 'structure' && !layer.structure) return false;
    if (sevFilter === 'crit' && e.severity !== 'critical') return false;
    if (sevFilter === 'high' && !['critical', 'high'].includes(e.severity)) return false;
    return true;
  };

  /* Hover handling — only when nothing is selected */
  const handleEnter = useCallbackT((id, kind, evt, tipData) => {
    if (!selected) setHover({ id, kind });
    if (!tipData) return;
    const targetRect = evt.currentTarget.getBoundingClientRect();
    const containerRect = topoRef.current.getBoundingClientRect();
    const TIP_W = 220;
    let x = targetRect.left + targetRect.width / 2 - containerRect.left;
    const y = targetRect.top - containerRect.top - 8;
    x = Math.max(TIP_W / 2 + 8, Math.min(containerRect.width - TIP_W / 2 - 8, x));
    setTip({ x, y, ...tipData });
  }, [selected]);
  const handleLeave = useCallbackT(() => {
    if (!selected) setHover(null);
    setTip(null);
  }, [selected]);

  /* Selection */
  const handleSelect = useCallbackT((id, kind, label, inspectPayload) => {
    setSelected({ id, kind, label });
    setHover(null);
    setTip(null);
    if (inspectPayload) openInspector(inspectPayload);
  }, [openInspector]);

  const clearSelection = useCallbackT(() => setSelected(null), []);

  /* Esc clears selection */
  React.useEffect(() => {
    const k = (e) => { if (e.key === 'Escape') clearSelection(); };
    window.addEventListener('keydown', k);
    return () => window.removeEventListener('keydown', k);
  }, [clearSelection]);

  /* Helpers for dim/emph classnames */
  const nodeCls = (id) => {
    if (!focus) return '';
    return focus.focusNodes.has(id) ? 'topo-emph' : 'topo-dim';
  };
  const edgeCls = (e) => {
    if (!focus) return '';
    return focus.focusEdges.has(e.id) ? 'topo-emph' : 'topo-dim';
  };
  const edgeAnim = (e) => focus?.animEdges?.has(e.id) && selected;  // animate only when explicitly selected

  /* ── Render ─────────────────────────────────────────────────── */
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Network Topology</h1>
          <p className="page-sub">
            {LFPM.firewalls.length} firewalls · {LFPM.zones.length} zones · {LFPM.assets.length} monitored assets · {LFPM.externalNodes.length} active threat vector{LFPM.externalNodes.length === 1 ? '' : 's'}
          </p>
        </div>
        <div className="row gap-2" style={{ marginLeft: 'auto' }}>
          <div className="seg">
            <button className={sevFilter === 'all'  ? 'active' : ''} onClick={() => setSevFilter('all')}>all paths</button>
            <button className={sevFilter === 'high' ? 'active' : ''} onClick={() => setSevFilter('high')}>≥ high</button>
            <button className={sevFilter === 'crit' ? 'active' : ''} onClick={() => setSevFilter('crit')}>critical</button>
          </div>
          <button
            className="btn"
            onClick={() => { clearSelection(); window.toast('View reset', { kind:'info', sub:'all paths and nodes visible' }); }}
          ><I.Maximize size={13} /> reset</button>
          <button
            className="btn"
            onClick={() => {
              const svg = svgRef.current;
              if (!svg) {
                window.toast('Export failed', { kind:'err', sub:'topology canvas not ready' });
                return;
              }
              const xml = new XMLSerializer().serializeToString(svg);
              const fname = `topology-${new Date().toISOString().slice(0, 10)}.svg`;
              const blob = new Blob(
                [`<?xml version="1.0" encoding="UTF-8"?>\n${xml}`],
                { type: 'image/svg+xml;charset=utf-8' },
              );
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url; a.download = fname;
              document.body.appendChild(a); a.click(); a.remove();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
              window.toast('Topology exported', {
                kind:'ok',
                sub: `${fname} · ${lanes.length} fw · ${LFPM.zones.length} zones`,
              });
            }}
          ><I.Download size={13} /> export</button>
        </div>
      </div>

      <div className="topo" ref={topoRef} style={{ flex: 1, minHeight: 0 }}>
        <div className="topo-grid" />

        {/* ── Bottom-left layers card ── */}
        <div className="topo-layers">
          <div className="head" style={{ marginBottom: 4 }}>layers</div>
          <Toggle label="threat paths" on={layer.threats}   onChange={() => setLayer(l => ({ ...l, threats:   !l.threats }))} />
          <Toggle label="internet trunk" on={layer.structure} onChange={() => setLayer(l => ({ ...l, structure: !l.structure }))} />
          <Toggle label="labels"       on={layer.labels}    onChange={() => setLayer(l => ({ ...l, labels:    !l.labels }))} />
        </div>

        {/* ── Bottom-right legend card ── */}
        <div className="topo-legend">
          <div className="head">legend</div>
          <div className="sub">edges</div>
          <div className="row"><span className="swatch-line" style={{ background:'var(--sev-critical)' }} /> critical threat</div>
          <div className="row"><span className="swatch-line" style={{ background:'var(--sev-high)' }} /> high threat</div>
          <div className="row" style={{ alignItems:'center' }}>
            <svg width="18" height="2"><line x1="0" y1="1" x2="18" y2="1" stroke="var(--topo-accent-50)" strokeWidth="1" strokeDasharray="3 3" /></svg>
            <span>internet trunk</span>
          </div>
          <div className="sub">zones · risk</div>
          <div className="row"><span className="swatch-dot" style={{ background:'var(--sev-safe)' }} /> healthy</div>
          <div className="row"><span className="swatch-dot" style={{ background:'var(--sev-medium)' }} /> medium</div>
          <div className="row"><span className="swatch-dot" style={{ background:'var(--sev-high)' }} /> high</div>
          <div className="row"><span className="swatch-dot" style={{ background:'var(--sev-critical)' }} /> critical</div>
        </div>

        {/* ── Selection pill (top-right when something is selected) ── */}
        {selected && (
          <div className="topo-pill">
            <span className="kind">{selected.kind}</span>
            <span className="id">{selected.label}</span>
            <span className="clear" onClick={clearSelection}>
              <I.Close size={11} /> clear (esc)
            </span>
          </div>
        )}

        {/* ── SVG canvas ── */}
        <svg
          ref={svgRef}
          className="topo-svg"
          viewBox={`0 0 ${TOPO.W} ${TOPO.H}`}
          preserveAspectRatio="xMidYMid meet"
          onClick={(e) => { if (e.target === e.currentTarget) clearSelection(); }}
        >
          <defs>
            <marker id="mk-low"  viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="var(--topo-accent-55)" />
            </marker>
            <marker id="mk-high" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="var(--sev-high)" />
            </marker>
            <marker id="mk-crit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="var(--sev-critical)" />
            </marker>
            <linearGradient id="lane-bg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--topo-lane-0)" />
              <stop offset="100%" stopColor="var(--topo-lane-1)" />
            </linearGradient>
          </defs>

          {/* Section labels */}
          {layer.labels && <SectionBand lanePositions={lanePositions} firewalls={LFPM.firewalls} />}

          {/* ─── Edges ─── */}
          {edges.filter(isEdgeVisible).map(e => {
            const ext = externals.find(n => n.id === e.sourceId);
            const lane = lanes.find(l => l.fw.id === e.targetFwId);
            if (!ext || !lane) return null;

            const x1 = ext.x + TOPO.externalW;
            const y1 = ext.y + TOPO.externalH / 2;
            const ingressX = lane.x + TOPO.laneW / 2 + (ingressMap[e.id] || 0);
            const x2 = ingressX;
            const y2 = TOPO.fwY - 4;

            const midX = (x1 + x2) / 2;
            const d = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;

            const col = e.severity === 'critical' ? 'var(--sev-critical)'
                     : e.severity === 'high'      ? 'var(--sev-high)'
                     : 'var(--topo-accent-50)';

            const marker = e.severity === 'critical' ? 'url(#mk-crit)'
                         : e.severity === 'high'     ? 'url(#mk-high)'
                         : 'url(#mk-low)';

            const isStruct = e.kind === 'structure';
            return (
              <path
                key={e.id}
                className={`${edgeCls(e)} ${edgeAnim(e) ? 'topo-flow' : ''}`}
                d={d}
                fill="none"
                stroke={col}
                strokeWidth={isStruct ? 1 : 1.5}
                strokeDasharray={isStruct ? '4 4' : 'none'}
                strokeLinecap="round"
                markerEnd={marker}
                opacity={isStruct ? 0.45 : (focus ? (focus.focusEdges.has(e.id) ? 0.95 : 0.65) : 0.85)}
                style={{ cursor: isStruct ? 'default' : 'pointer' }}
                onClick={(evt) => {
                  if (isStruct) return;
                  evt.stopPropagation();
                  const ext = externals.find(n => n.id === e.sourceId);
                  const fw  = LFPM.firewalls.find(f => f.id === e.targetFwId);
                  handleSelect(
                    e.id, 'path',
                    `${ext?.name || e.sourceId} → ${fw?.display || e.targetFwId}`,
                    { kind:'path', data: { edge: e, ext, fw } }
                  );
                }}
              />
            );
          })}

          {/* ─── External / threat nodes ─── */}
          {externals.map(n => {
            const accent =
              n.threat === 'critical' ? 'var(--sev-critical)'
              : n.threat === 'high'   ? 'var(--sev-high)'
              : 'var(--fg-3)';
            const isSelected = selected?.id === n.id;
            const outboundCount = edges.filter(e => e.sourceId === n.id).length;
            const tipData = {
              kind: 'external',
              data: {
                head: n.name,
                badge: n.kind,
                rows: [
                  { k:'ip', v: n.ip },
                  { k:'threat', v: n.threat === 'none' ? '—' : n.threat },
                  { k:'paths', v: `${outboundCount} firewall${outboundCount === 1 ? '' : 's'}` },
                ],
                desc: n.description,
                hint: 'click to focus all paths from this source',
              },
            };
            return (
              <g
                key={n.id}
                className={nodeCls(n.id)}
                transform={`translate(${n.x}, ${n.y})`}
                style={{ cursor: 'pointer' }}
                onMouseEnter={(e) => handleEnter(n.id, 'external', e, tipData)}
                onMouseLeave={handleLeave}
                onClick={(e) => {
                  e.stopPropagation();
                  handleSelect(n.id, 'external', n.name, { kind:'external', data: n });
                }}
              >
                <rect
                  width={TOPO.externalW} height={TOPO.externalH} rx="5"
                  fill="var(--bg-1)"
                  stroke={isSelected ? 'var(--accent)' : accent}
                  strokeWidth={isSelected ? 1.6 : 1}
                  strokeOpacity={isSelected ? 1 : 0.7}
                />
                {/* Threat strip on left edge */}
                {n.threat !== 'none' && (
                  <rect x="0" y="0" width="3" height={TOPO.externalH} rx="1.5" fill={accent} />
                )}
                {/* Icon */}
                <g transform={`translate(16, ${TOPO.externalH / 2 - 9})`} style={{ color: accent }}>
                  <ExternalIcon kind={n.kind} color={accent} />
                </g>
                {/* Texts */}
                <text x="44" y="26" fontSize="13.5" fontWeight="600" fill="var(--fg-0)" style={{ fontFamily: 'var(--f-mono)' }}>
                  {n.name.length > 22 ? n.name.slice(0, 22) + '…' : n.name}
                </text>
                <text x="44" y="44" fontSize="11" fill="var(--fg-3)" style={{ fontFamily: 'var(--f-mono)', textTransform:'uppercase', letterSpacing: '0.08em' }}>
                  {n.kind}
                </text>
                <text x="44" y="60" fontSize="12" fill="var(--fg-2)" style={{ fontFamily: 'var(--f-mono)' }}>
                  {n.ip}
                </text>
                {/* Outbound count badge */}
                {outboundCount > 0 && (
                  <g transform={`translate(${TOPO.externalW - 12}, ${TOPO.externalH - 12})`}>
                    <text fontSize="10" fill="var(--fg-muted)" textAnchor="end" style={{ fontFamily: 'var(--f-mono)' }}>
                      → {outboundCount}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* ─── Firewall lanes ─── */}
          {lanes.map(lane => {
            const fw = lane.fw;
            const meta = laneMeta[fw.id];
            const vendorAccent = fw.vendorId === 'palo-alto' ? 'var(--vendor-paloalto)'
              : fw.vendorId === 'fortinet' ? 'var(--vendor-fortinet)'
              : fw.vendorId === 'cisco' ? 'var(--vendor-cisco)' : 'var(--vendor-unknown)';
            const isSel = selected?.id === fw.id;
            const tipData = {
              kind: 'firewall',
              data: {
                head: fw.display,
                badge: fw.vendorId === 'palo-alto' ? 'palo alto' : 'fortinet',
                rows: [
                  { k:'model', v: fw.model },
                  { k:'firmware', v: fw.firmware },
                  { k:'ip', v: fw.ip },
                  { k:'risk', v: `${fw.riskScore} · ${LFPM.fmt.riskLabel(fw.riskScore)}` },
                  { k:'cves', v: `${meta.cves}${meta.kev ? ` · ${meta.kev} kev` : ''}` },
                ],
                hint: 'click to focus this firewall',
              },
            };

            return (
              <g key={fw.id} className={nodeCls(fw.id)}>
                {/* Lane frame */}
                <rect
                  x={lane.x - 8} y={TOPO.fwY - 12}
                  width={TOPO.laneW + 16}
                  height={TOPO.laneBottom - TOPO.fwY + 12}
                  fill="url(#lane-bg)"
                  stroke="var(--bd-1)"
                  strokeWidth="1"
                  rx="7"
                />

                {/* Ingress hint (faint dotted bar above FW header) */}
                <line
                  x1={lane.x + TOPO.laneW / 2 - TOPO.ingressFan / 2 - 4}
                  y1={TOPO.fwY - 6}
                  x2={lane.x + TOPO.laneW / 2 + TOPO.ingressFan / 2 + 4}
                  y2={TOPO.fwY - 6}
                  stroke="var(--bd-2)"
                  strokeWidth="1"
                  strokeDasharray="2 2"
                  opacity="0.5"
                />

                {/* Firewall header */}
                <g
                  transform={`translate(${lane.x}, ${TOPO.fwY})`}
                  style={{ cursor: 'pointer' }}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleSelect(fw.id, 'firewall', fw.display, { kind:'firewall', data: fw });
                  }}
                  onMouseEnter={(e) => handleEnter(fw.id, 'firewall', e, tipData)}
                  onMouseLeave={handleLeave}
                >
                  <rect
                    width={TOPO.laneW} height={TOPO.fwH} rx="5"
                    fill="var(--bg-2)"
                    stroke={isSel ? 'var(--accent)' : 'var(--bd-2)'}
                    strokeWidth={isSel ? 1.6 : 1}
                  />
                  {/* Vendor stripe */}
                  <rect x="0" y="0" width="3" height={TOPO.fwH} rx="1.5" fill={vendorAccent} />

                  {/* Status dot top-right */}
                  <circle
                    cx={TOPO.laneW - 14} cy={16} r="3.5"
                    fill={fw.status === 'online' ? 'var(--sev-safe)' : 'var(--sev-high)'}
                  />

                  {/* Name */}
                  <text x="14" y="24" fontSize="14" fontWeight="600" fill="var(--fg-0)" style={{ fontFamily:'var(--f-mono)' }}>
                    {fw.display}
                  </text>
                  {/* Model */}
                  <text x="14" y="42" fontSize="11.5" fill="var(--fg-2)" style={{ fontFamily:'var(--f-mono)' }}>
                    {fw.model}
                  </text>
                  {/* Firmware */}
                  <text x="14" y="58" fontSize="11" fill="var(--fg-3)" style={{ fontFamily:'var(--f-mono)' }}>
                    {fw.firmware}
                  </text>
                  {/* IP · zone */}
                  <text x="14" y="74" fontSize="11" fill="var(--fg-3)" style={{ fontFamily:'var(--f-mono)' }}>
                    {fw.ip} · {fw.zone}
                  </text>
                  {/* Divider */}
                  <line x1="14" y1="84" x2={TOPO.laneW - 14} y2="84" stroke="var(--bd-1)" />
                  {/* Footer line: risk + cves badges */}
                  <text x="14" y="100" fontSize="12" fill={LFPM.fmt.riskColor(fw.riskScore)} fontWeight="600" style={{ fontFamily: 'var(--f-mono)' }}>
                    risk {fw.riskScore}
                  </text>
                  {meta.cves > 0 && (
                    <text
                      x={TOPO.laneW - 14} y="100"
                      fontSize="12"
                      textAnchor="end"
                      fontWeight="600"
                      fill={meta.kev > 0 ? 'var(--sev-critical)' : 'var(--sev-high)'}
                      style={{ fontFamily: 'var(--f-mono)' }}
                    >
                      {meta.cves} cve{meta.cves === 1 ? '' : 's'}{meta.kev > 0 ? ` · ${meta.kev} kev` : ''}
                    </text>
                  )}
                </g>

                {/* Zones */}
                {lane.zones.map(z => {
                  const zRisk = Math.max(
                    0,
                    ...LFPM.policies
                      .filter(p => p.firewallId === fw.id && (p.srcZone.toLowerCase() === z.name || p.dstZone.toLowerCase() === z.name))
                      .map(p => p.riskScore)
                  );
                  const zColor = zRisk >= 80 ? 'var(--sev-critical)'
                              : zRisk >= 60 ? 'var(--sev-high)'
                              : zRisk >= 40 ? 'var(--sev-medium)'
                              : 'var(--sev-safe)';
                  const zoneSel = selected?.id === z.id;
                  const zoneTip = {
                    kind: 'zone',
                    data: {
                      head: z.name,
                      badge: z.type,
                      rows: [
                        { k:'subnet', v: z.subnet },
                        { k:'firewall', v: fw.display },
                        { k:'assets', v: z.assets.length },
                        { k:'max risk', v: zRisk || '—' },
                      ],
                    },
                  };
                  return (
                    <g key={z.id} className={nodeCls(z.id)}>
                      {/* Zone outline */}
                      <rect
                        x={lane.x + 4} y={z.y}
                        width={TOPO.laneW - 8}
                        height={z.blockH}
                        rx="4"
                        fill="var(--bg-1)"
                        stroke={zoneSel ? 'var(--accent)' : 'var(--bd-1)'}
                        strokeWidth={zoneSel ? 1.4 : 1}
                      />
                      {/* Header bar */}
                      <rect
                        x={lane.x + 4} y={z.y}
                        width={TOPO.laneW - 8}
                        height={TOPO.zoneHeaderH}
                        rx="4"
                        fill="var(--topo-lane-0)"
                      />
                      <g
                        onClick={(e) => { e.stopPropagation(); handleSelect(z.id, 'zone', z.name, { kind:'zone', data: { ...z, fwId: fw.id, fwDisplay: fw.display } }); }}
                        onMouseEnter={(e) => handleEnter(z.id, 'zone', e, zoneTip)}
                        onMouseLeave={handleLeave}
                        style={{ cursor: 'pointer' }}
                      >
                        <rect x={lane.x + 4} y={z.y} width={TOPO.laneW - 8} height={TOPO.zoneHeaderH} fill="transparent" />
                        <circle cx={lane.x + 16} cy={z.y + 16} r="3.5" fill={zColor} />
                        <text x={lane.x + 28} y={z.y + 21} fontSize="12" fontWeight="600" fill="var(--fg-1)" style={{ fontFamily: 'var(--f-mono)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                          {z.name}
                        </text>
                        <text x={lane.x + TOPO.laneW - 14} y={z.y + 21} fontSize="11" fill="var(--fg-3)" textAnchor="end" style={{ fontFamily:'var(--f-mono)' }}>
                          {z.subnet.length > 16 ? z.subnet.slice(0, 16) + '…' : z.subnet}
                        </text>
                      </g>

                      {/* Assets */}
                      {z.assets.length === 0 && (
                        <text
                          x={lane.x + TOPO.laneW / 2}
                          y={z.y + TOPO.zoneHeaderH + 18}
                          fontSize="11"
                          fill="var(--fg-muted)"
                          textAnchor="middle"
                          style={{ fontFamily: 'var(--f-mono)' }}
                        >
                          no monitored assets
                        </text>
                      )}
                      {z.assets.map(a => {
                        const iconKind = getAssetIconKind(a);
                        const aSel = selected?.id === a.id;
                        const assetTip = {
                          kind: 'asset',
                          data: {
                            head: a.name,
                            badge: a.kind,
                            rows: [
                              { k:'ip', v: a.ip },
                              { k:'os', v: a.os },
                              { k:'zone', v: z.name },
                              { k:'firewall', v: fw.display },
                            ],
                          },
                        };
                        return (
                          <g
                            key={a.id}
                            className={nodeCls(a.id)}
                            transform={`translate(${lane.x + 12}, ${a.y})`}
                            style={{ cursor: 'pointer' }}
                            onClick={(e) => { e.stopPropagation(); handleSelect(a.id, 'asset', a.name, { kind:'host', data: a }); }}
                            onMouseEnter={(e) => handleEnter(a.id, 'asset', e, assetTip)}
                            onMouseLeave={handleLeave}
                          >
                            <rect
                              x="-6" y="0"
                              width={TOPO.laneW - 16} height={TOPO.assetH - 2}
                              rx="3"
                              fill={aSel ? 'var(--topo-accent-06)' : 'transparent'}
                              stroke={aSel ? 'var(--accent-bd)' : 'transparent'}
                            />
                            {/* Icon */}
                            <g transform={`translate(2, ${(TOPO.assetH - 2) / 2 - 6})`}>
                              <AssetIcon kind={iconKind} color="var(--fg-2)" />
                            </g>
                            {/* Name */}
                            <text x="22" y={TOPO.assetH / 2 + 3} fontSize="12.5" fill="var(--fg-1)" style={{ fontFamily: 'var(--f-mono)' }}>
                              {a.name.length > 13 ? a.name.slice(0, 13) + '…' : a.name}
                            </text>
                            {/* IP */}
                            <text
                              x={TOPO.laneW - 22} y={TOPO.assetH / 2 + 3}
                              fontSize="11" fill="var(--fg-3)" textAnchor="end"
                              style={{ fontFamily: 'var(--f-mono)' }}
                            >
                              {a.ip.length > 14 ? a.ip.slice(0, 14) + '…' : a.ip}
                            </text>
                          </g>
                        );
                      })}
                    </g>
                  );
                })}

                {/* ── Lane footer (metrics strip at bottom of each lane) ── */}
                <g transform={`translate(${lane.x}, ${TOPO.laneBottom - TOPO.laneFooterH})`}>
                  {/* Top divider */}
                  <line
                    x1="6" y1="0"
                    x2={TOPO.laneW - 6} y2="0"
                    stroke="var(--bd-1)" strokeWidth="1"
                  />
                  {/* Label */}
                  <text x="14" y="16" fontSize="9.5" fill="var(--fg-muted)" style={{ fontFamily:'var(--f-mono)', textTransform:'uppercase', letterSpacing:'0.08em' }}>
                    device · 24h
                  </text>
                  {/* Two metric columns — left=rules, right=throughput */}
                  {[
                    { x: 14,             label: 'rules',     value: meta.rules,         color:'var(--fg-1)',   anchor:'start' },
                    { x: TOPO.laneW - 14,label: 'throughput',value: fw.throughput,      color:'var(--fg-1)',   anchor:'end' },
                  ].map((m, i) => (
                    <g key={i}>
                      <text
                        x={m.x} y={32}
                        textAnchor={m.anchor}
                        fontSize="9.5"
                        fill="var(--fg-3)"
                        style={{ fontFamily:'var(--f-mono)', textTransform:'uppercase', letterSpacing:'0.06em' }}
                      >
                        {m.label}
                      </text>
                      <text
                        x={m.x} y={49}
                        textAnchor={m.anchor}
                        fontSize="12.5"
                        fontWeight="600"
                        fill={m.color}
                        style={{ fontFamily:'var(--f-mono)' }}
                      >
                        {m.value}
                      </text>
                    </g>
                  ))}
                </g>
              </g>
            );
          })}
        </svg>

        {/* ── Hover tooltip ── */}
        {tip && (
          <div className="topo-tip" style={{
            left: tip.x, top: tip.y,
            transform: 'translate(-50%, -100%)',
          }}>
            <div className="head">
              <span>{tip.data.head}</span>
              {tip.data.badge && <span className="badge">{tip.data.badge}</span>}
            </div>
            {tip.data.rows.map((r, i) => (
              <div className="row" key={i}>
                <span className="k">{r.k}</span>
                <span className="v">{r.v}</span>
              </div>
            ))}
            {tip.data.desc && <div className="desc">{tip.data.desc}</div>}
            {tip.data.hint && <div className="hint">{tip.data.hint}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

/* Layer toggle (small, inline) */
function Toggle({ label, on, onChange }) {
  return (
    <div className="toggle-row" onClick={onChange}>
      <span style={{
        width: 22, height: 12, borderRadius: 6,
        background: on ? 'var(--accent-bg)' : 'var(--bg-3)',
        border: `1px solid ${on ? 'var(--accent-bd)' : 'var(--bd-2)'}`,
        position: 'relative', transition: 'all 140ms', flexShrink: 0,
      }}>
        <span style={{
          position: 'absolute', top: 1, left: on ? 11 : 1,
          width: 8, height: 8, borderRadius: 4,
          background: on ? 'var(--accent)' : 'var(--fg-3)',
          transition: 'left 140ms',
        }} />
      </span>
      <span className="label">{label}</span>
    </div>
  );
}

export { Topology };
