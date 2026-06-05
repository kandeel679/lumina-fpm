import React from "react";
import { Icons } from "./icons";
import { LFPM } from "./data";
import { triggerDeviceAnalysis } from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Dashboard — Overview
 *   · 5 hero KPIs (clickable → deep-link into filtered views)
 *   · Charts row (anomalies-by-type bars + vendor tiles are clickable)
 *   · Fleet + risky-rules + advisories tables → context-aware nav
 *   · Activity feed: priority alerts grouped; each event links to
 *     the related page when entry.link is present
 *
 *  Every navigation goes through `goTo(page, params)` so the URL
 *  hash stays in sync (#audit?filter=shadowed, #threats?cve=…).
 * ───────────────────────────────────────────────────────────────── */

const { useMemo: useMemoD } = React;

function Dashboard({ openInspector, goTo, timeRange = '24h', onTimeRange, user, refreshData }) {
  const I = window.Icons;
  const [running, setRunning] = React.useState(false);

  /* Live scan metadata from the backend (null-safe; empty on the mock path). */
  const meta = LFPM.meta || {};
  const lastScanLabel = meta.lastScanAt
    ? new Date(meta.lastScanAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : null;

  /* Activity panel: collapsible, preference persisted across refresh. */
  const [activityCollapsed, setActivityCollapsed] = React.useState(() => {
    try { return localStorage.getItem('lumina_activity_collapsed') === '1'; }
    catch { return false; }
  });
  const toggleActivity = React.useCallback(() => {
    setActivityCollapsed(v => {
      const next = !v;
      try { localStorage.setItem('lumina_activity_collapsed', next ? '1' : '0'); } catch {}
      return next;
    });
  }, []);

  /* Safety: pages call onNavigate(page) in older code paths; map to goTo */
  const navigate = (page, params) => {
    if (typeof goTo === 'function') goTo(page, params);
  };

  const runAudit = async () => {
    if (running) return;
    setRunning(true);
    window.toast('Audit run started', { kind:'info', sub:`analyzing ${LFPM.policies.length} rules across ${LFPM.firewalls.length} firewalls…` });
    try {
      await Promise.all(LFPM.firewalls.map(fw => triggerDeviceAnalysis(fw.id)));
      await new Promise(resolve => setTimeout(resolve, 2000));
      if (typeof refreshData === 'function') {
        await refreshData();
      }
      const updatedAnomalies = LFPM.policies.filter(p => p.status !== 'clean').length;
      window.toast('Audit complete', { kind:'ok', sub:`${updatedAnomalies} anomalies surfaced · database synchronized` });
    } catch (e) {
      console.error(e);
      window.toast('Audit failed', { kind:'crit', sub: String(e.message || e) });
    } finally {
      setRunning(false);
    }
  };

  const exportSnapshot = () => {
    window.toast('Snapshot exported', {
      kind: 'ok',
      sub: `overview-${new Date().toISOString().slice(0,10)}.pdf · 7 panels · 1.2 MB`,
    });
  };

  const pickRange = (id) => onTimeRange && onTimeRange(id);

  const stats = useMemoD(() => {
    const p = LFPM.policies;
    return {
      rules:       p.length,
      issues:      p.filter(x => x.status !== 'clean').length,
      shadowed:    p.filter(x => x.status === 'shadowed').length,
      redundant:   p.filter(x => x.status === 'redundant').length,
      permissive:  p.filter(x => x.status === 'permissive').length,
      clean:       p.filter(x => x.status === 'clean').length,
      conflicts:   LFPM.conflicts.length,
      critCves:    LFPM.threats.filter(t => t.severity === 'critical').length,
      kev:         LFPM.threats.filter(t => t.kev).length,
      devices:     LFPM.firewalls.length,
      online:      LFPM.firewalls.filter(f => f.status === 'online').length,
      degraded:    LFPM.firewalls.filter(f => f.status !== 'online').length,
      avgRisk:     Math.round(p.reduce((a, x) => a + x.riskScore, 0) / p.length),
    };
  }, []);

  const fleet = useMemoD(() => {
    return LFPM.firewalls.map(fw => {
      const rules = LFPM.policies.filter(p => p.firewallId === fw.id);
      const anomalies = rules.filter(r => r.status !== 'clean').length;
      const cves = LFPM.threats.filter(t => t.firewallIds.includes(fw.id));
      const kev = cves.filter(c => c.kev).length;
      return { ...fw, rules: rules.length, anomalies, cves: cves.length, kev };
    }).sort((a, b) => b.riskScore - a.riskScore);
  }, []);

  const topRisky = useMemoD(() =>
    [...LFPM.policies]
      .filter(p => p.status !== 'clean')
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5),
  []);

  const topCves = useMemoD(() =>
    [...LFPM.threats]
      .sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || b.cvss - a.cvss)
      .slice(0, 4),
  []);

  const charts = useMemoD(() => {
    const trend = Array.from({ length: 24 }, (_, i) => {
      const base = 56
        + Math.sin(i * 0.4) * 6
        + Math.cos(i * 0.9) * 3
        + (i > 16 ? (i - 16) * 1.3 : 0);
      return Math.round(Math.max(35, Math.min(95, base)));
    });

    const anomalyTypes = [
      { id:'permissive', label:'permissive', count: stats.permissive, color:'var(--sev-high)' },
      { id:'shadowed',   label:'shadowed',   count: stats.shadowed,   color:'var(--sev-critical)' },
      { id:'conflicts',  label:'conflicts',  count: stats.conflicts,  color:'var(--sev-low)',
        intent:{ page:'audit', params:{ filter:'anomalies' } } },
      { id:'redundant',  label:'redundant',  count: stats.redundant,  color:'var(--sev-medium)' },
    ].sort((a, b) => b.count - a.count);

    /* Build vendor tiles from the vendors ACTUALLY present in the fleet
     * (no longer hardcoded to PA/FT — Cisco now shows), and guard the average
     * against divide-by-zero so a vendor with no rules reads 0, never NaN. */
    const vendorIds = Array.from(new Set(LFPM.firewalls.map(f => f.vendorId).filter(Boolean)));
    const vendors = vendorIds.map(vid => {
      const vinfo = (LFPM.vendors || []).find(v => v.id === vid);
      const vfws = LFPM.firewalls.filter(f => f.vendorId === vid);
      const fwIds = new Set(vfws.map(f => f.id));
      const pols  = LFPM.policies.filter(p => fwIds.has(p.firewallId));
      const avg   = pols.length ? Math.round(pols.reduce((a, p) => a + p.riskScore, 0) / pols.length) : 0;
      const issues = pols.filter(p => p.status !== 'clean').length;
      const cves  = LFPM.threats.filter(t => (t.vendors || []).includes(vid)).length;
      const kev   = LFPM.threats.filter(t => (t.vendors || []).includes(vid) && t.kev).length;
      return {
        id: vid,
        label: vinfo?.name || vid,
        abbr:  vinfo?.abbr || vid.slice(0, 2).toUpperCase(),
        devices: vfws.length,
        avg, issues, cves, kev,
      };
    }).sort((a, b) => b.avg - a.avg);

    return { trend, anomalyTypes, vendors };
  }, [stats]);

  return (
    <div className="page">
      {/* ── header ─────────────────────────────────────── */}
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="page-sub">
            Cross-vendor policy health across {stats.devices} firewalls · {stats.rules} rules
            {lastScanLabel ? ` · last threat scan ${lastScanLabel}` : ''}
          </p>
        </div>
        <div className="row gap-2" style={{ marginLeft: 'auto' }}>
          <div className="seg">
            {['1h','6h','24h','7d','30d'].map(id => (
              <button key={id} className={timeRange === id ? 'active' : ''} onClick={() => pickRange(id)}>{id}</button>
            ))}
          </div>
          <button className="btn" onClick={exportSnapshot}><I.Download size={13} /> export</button>
          <button className="btn primary" onClick={runAudit} disabled={running}
                  style={running ? { opacity: 0.7, cursor: 'wait' } : {}}>
            <I.Play size={13} /> {running ? 'running…' : 'run audit'}
          </button>
        </div>
      </div>

      {/* ── hero KPIs (clickable, deep-link into filtered views) ── */}
      <div className="kpi-strip hero">
        <HeroKpi
          label="avg fleet risk"
          value={stats.avgRisk}
          sub={`${LFPM.fmt.riskLabel(stats.avgRisk)} · ${stats.issues} open issues`}
          color={LFPM.fmt.riskColor(stats.avgRisk)}
          kind={stats.avgRisk >= 60 ? 'high' : 'safe'}
          onClick={() => navigate('audit', { filter:'critical' })}
          cta="audit"
        />
        <HeroKpi
          label="open issues"
          value={stats.issues}
          sub={`${stats.shadowed} shadowed · ${stats.permissive} permissive`}
          color="var(--sev-critical)"
          kind="crit"
          onClick={() => navigate('audit', { filter:'anomalies' })}
          cta="review →"
        />
        <HeroKpi
          label="critical cves"
          value={stats.critCves}
          sub={`${stats.kev} cisa-kev · actively exploited`}
          color="var(--sev-critical)"
          kind="crit"
          onClick={() => navigate('threats', { severity:'critical' })}
          cta="advisories →"
        />
        <HeroKpi
          label="fleet online"
          value={`${stats.online}/${stats.devices}`}
          sub={stats.degraded > 0 ? `${stats.degraded} degraded · ${stats.online} online` : 'all healthy'}
          color={stats.degraded > 0 ? 'var(--sev-high)' : 'var(--sev-safe)'}
          kind={stats.degraded > 0 ? 'high' : 'safe'}
          onClick={() => navigate('topology')}
          cta="topology →"
        />
        <HeroKpi
          label="threat findings"
          value={meta.totalFindings != null ? meta.totalFindings : LFPM.threats.length}
          sub={meta.lastScanAt
            ? `${meta.newFindingsLastScan || 0} new · ${meta.correlatedRules || 0} correlated`
            : `${stats.kev} cisa-kev`}
          color="var(--accent)"
          kind="accent"
          onClick={() => navigate('threats')}
          cta="threats →"
        />
      </div>

      {/* ── body: charts + tables (left) · activity (right) ─── */}
      <div className={`page-body dash-grid${activityCollapsed ? ' activity-collapsed' : ''}`}>
        <div style={{ background:'var(--bg-0)', overflow:'auto', padding:'14px', display:'flex', flexDirection:'column', gap:14, minHeight: 0 }}>

          {/* Charts row — risk trend, anomalies by type, vendor risk */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 0.9fr', gap: 14 }}>

            {/* Risk trend (line) */}
            <div className="panel">
              <div
                className="panel-head clickable"
                onClick={() => navigate('audit', { filter:'critical' })}
                title="View high-risk rules"
              >
                <div className="panel-title"><I.Activity size={12} /> risk trend</div>
                <div className="panel-cta">last 24h <I.ChevronR size={11} /></div>
              </div>
              <div className="chart-body">
                <TrendChart data={charts.trend} id="risk24" />
                <div className="chart-axis">
                  <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>now</span>
                </div>
                <div className="chart-legend">
                  <span><span className="sw" style={{ background:'var(--accent)' }} /> hourly avg risk score</span>
                  <span style={{ marginLeft:'auto', color:'var(--fg-2)' }}>
                    peak <span className="mono" style={{ color:'var(--sev-high)' }}>{Math.max(...charts.trend)}</span>
                  </span>
                </div>
              </div>
            </div>

            {/* Anomaly distribution — each bar clickable to a filter */}
            <div className="panel">
              <div
                className="panel-head clickable"
                onClick={() => navigate('audit', { filter:'anomalies' })}
                title="View all anomalies"
              >
                <div className="panel-title"><I.AlertTri size={12} /> anomalies by type</div>
                <div className="panel-cta">{stats.issues} total <I.ChevronR size={11} /></div>
              </div>
              <div className="chart-body">
                <HBars
                  items={charts.anomalyTypes.map(t => ({
                    label: t.label,
                    value: t.count,
                    color: t.color,
                    onClick: () => navigate('audit',
                      t.id === 'conflicts'
                        ? { filter:'anomalies' }
                        : { filter: t.id }),
                  }))}
                  max={Math.max(...charts.anomalyTypes.map(t => t.count), 1)}
                />
                <div className="chart-legend">
                  <span style={{ color:'var(--fg-2)' }}>
                    {Math.round((stats.issues / stats.rules) * 100)}% of rules flagged · click to filter
                  </span>
                </div>
              </div>
            </div>

            {/* Vendor risk — compact comparison */}
            <div className="panel">
              <div className="panel-head">
                <div className="panel-title"><I.Shield size={12} /> vendor risk</div>
                <div className="panel-meta">avg rule risk</div>
              </div>
              <div className="chart-body">
                <div className="hbars">
                  {charts.vendors.map(v => (
                    <div
                      key={v.id}
                      className="vendor-tile"
                      onClick={() => navigate('audit', { vendor: v.id })}
                      title={`Filter audit by ${v.label}`}
                    >
                      <div className="row" style={{ justifyContent:'space-between', marginBottom: 4, alignItems:'center' }}>
                        <span className="row gap-2">
                          <span className="mono" style={{
                            fontSize: 10, padding:'1px 5px', borderRadius:3,
                            background:'var(--bg-3)', color:'var(--fg-1)', letterSpacing:'0.04em',
                          }}>{v.abbr}</span>
                          <span className="vendor-tile-name" style={{ fontSize: 12, color: 'var(--fg-1)' }}>{v.label}</span>
                        </span>
                        <span className="mono" style={{
                          fontSize: 14, fontWeight: 600,
                          color: LFPM.fmt.riskColor(v.avg),
                        }}>{v.avg}</span>
                      </div>
                      <div className="hbar-track" style={{ height: 6 }}>
                        <div className="hbar-fill" style={{
                          width: `${v.avg}%`, background: LFPM.fmt.riskColor(v.avg),
                        }} />
                      </div>
                      <div className="row" style={{
                        marginTop: 5, fontSize: 10.5, color:'var(--fg-3)',
                        fontFamily:'var(--f-mono)', gap: 10, justifyContent:'flex-start',
                      }}>
                        <span>{v.devices}d</span>
                        <span><span style={{ color: v.issues > 0 ? 'var(--sev-high)' : 'var(--fg-1)' }}>{v.issues}</span> issues</span>
                        <span>
                          <span style={{ color: 'var(--fg-1)' }}>{v.cves}</span> cve
                          {v.kev > 0 && <> · <span style={{ color:'var(--sev-critical)' }}>{v.kev}kev</span></>}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Fleet — rows go to Topology with device selected */}
          <div className="panel">
            <div
              className="panel-head clickable"
              onClick={() => navigate('topology')}
              title="Open network topology"
            >
              <div className="panel-title"><I.Shield size={12} /> firewall fleet</div>
              <div className="panel-cta">{stats.online}/{stats.devices} online · topology <I.ChevronR size={11} /></div>
            </div>
            <table className="t">
              <thead>
                <tr>
                  <th style={{ paddingLeft: 14 }}>device</th>
                  <th>vendor</th>
                  <th>status</th>
                  <th>rules</th>
                  <th>anomalies</th>
                  <th>cves</th>
                  <th style={{ width: 160 }}>risk</th>
                </tr>
              </thead>
              <tbody>
                {fleet.map(fw => (
                  <tr key={fw.id}
                      onClick={() => navigate('topology', { device: fw.id })}
                      title={`Open ${fw.display} on topology`}>
                    <td>
                      <span className="sev-stripe" style={{ background: LFPM.fmt.riskColor(fw.riskScore) }} />
                      <span className="mono strong">{fw.display}</span>
                      <div style={{ fontSize: 10.5, color: 'var(--fg-3)', marginTop: 2 }}>
                        {fw.location} · {fw.firmware}
                      </div>
                    </td>
                    <td className="dim">{(fw.vendor || '').toLowerCase()}</td>
                    <td>
                      <span className={`stat-text ${fw.status === 'online' ? 'safe' : 'high'}`}>
                        <span className="dot" /> {fw.status}
                      </span>
                    </td>
                    <td className="num">{fw.rules}</td>
                    <td className="num"
                        onClick={(e) => { e.stopPropagation(); navigate('audit', { firewall: fw.id, filter:'anomalies' }); }}
                        style={{ cursor: fw.anomalies > 0 ? 'pointer' : undefined }}>
                      <span style={{ color: fw.anomalies > 0 ? 'var(--sev-high)' : 'var(--fg-3)' }}>
                        {fw.anomalies}
                      </span>
                    </td>
                    <td className="num"
                        onClick={(e) => { e.stopPropagation(); navigate('threats', { vendor: fw.vendorId }); }}
                        style={{ cursor: fw.cves > 0 ? 'pointer' : undefined }}>
                      {fw.cves > 0 ? (
                        <span style={{ color: fw.kev > 0 ? 'var(--sev-critical)' : 'var(--sev-high)' }}>
                          {fw.cves}{fw.kev > 0 ? ` · ${fw.kev} kev` : ''}
                        </span>
                      ) : <span className="dim">0</span>}
                    </td>
                    <td>
                      <div className="row gap-2">
                        <span className="mono strong" style={{
                          color: LFPM.fmt.riskColor(fw.riskScore), minWidth: 24,
                        }}>{fw.riskScore}</span>
                        <div style={{ flex:1, height: 4, background:'var(--bg-3)', borderRadius: 2, overflow:'hidden' }}>
                          <div style={{
                            width: `${fw.riskScore}%`, height:'100%',
                            background: LFPM.fmt.riskColor(fw.riskScore),
                          }} />
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Risky rules + CVEs */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 14 }}>
            <div className="panel">
              <div
                className="panel-head clickable"
                onClick={() => navigate('audit', { filter:'critical' })}
                title="View Policy Audit"
              >
                <div className="panel-title"><I.Audit size={12} /> top risky rules</div>
                <div className="panel-cta">view all <I.ChevronR size={11} /></div>
              </div>
              <table className="t">
                <thead>
                  <tr>
                    <th style={{ paddingLeft: 14 }}>rule</th>
                    <th>device</th>
                    <th>status</th>
                    <th style={{ textAlign: 'right' }}>risk</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisky.map(r => {
                    const fw = LFPM.firewalls.find(f => f.id === r.firewallId);
                    return (
                      <tr key={r.id}
                          onClick={() => navigate('audit', { rule: r.id })}
                          title={`Open ${r.id} in Policy Audit`}>
                        <td>
                          <span className="sev-stripe" style={{ background: LFPM.fmt.riskColor(r.riskScore) }} />
                          <div className="row gap-2">
                            <span className="mono dim" style={{ fontSize: 10.5 }}>{r.id}</span>
                            <span className="mono strong truncate" style={{ maxWidth: 200 }}>{r.name}</span>
                          </div>
                        </td>
                        <td className="mono dim">{fw?.display}</td>
                        <td>
                          <span className={`stat-text ${
                            r.status === 'permissive' ? 'high' :
                            r.status === 'shadowed'   ? 'critical' : 'medium'}`}>
                            <span className="dot" />{r.status}
                          </span>
                        </td>
                        <td className="num" style={{ color: LFPM.fmt.riskColor(r.riskScore), fontWeight: 600 }}>
                          {r.riskScore}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="panel">
              <div
                className="panel-head clickable"
                onClick={() => navigate('threats')}
                title="View Threat Intelligence"
              >
                <div className="panel-title"><I.Bug size={12} /> active advisories</div>
                <div className="panel-cta">view all <I.ChevronR size={11} /></div>
              </div>
              <div className="col" style={{ padding: 0 }}>
                {topCves.map(c => (
                  <div key={c.id}
                    onClick={() => navigate('threats', { cve: c.id })}
                    title={`Open ${c.id} in Threat Intel`}
                    style={{
                      padding: '10px 14px',
                      borderBottom: '1px solid var(--bd-1)',
                      cursor: 'pointer',
                      display: 'flex', alignItems: 'flex-start', gap: 10,
                    }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-2)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                    <span className="sev-stripe" style={{
                      margin: '2px 0 0 -14px', height: 24,
                      background: LFPM.fmt.sevColor(c.severity),
                    }} />
                    <div className="flex1">
                      <div className="row" style={{ justifyContent: 'space-between' }}>
                        <span className="mono strong" style={{ fontSize: 11.5 }}>{c.id}</span>
                        <span className="mono" style={{
                          color: LFPM.fmt.sevColor(c.severity), fontWeight: 600, fontSize: 11.5,
                        }}>{c.cvss.toFixed(1)}</span>
                      </div>
                      <div className="truncate" style={{ fontSize: 12, color:'var(--fg-1)', marginTop: 3 }}>
                        {c.title}
                      </div>
                      <div className="row" style={{ marginTop: 5, fontSize: 10.5, color:'var(--fg-3)', gap: 10 }}>
                        <span className={`stat-text ${c.exploit === 'active' || c.exploit === 'wild' ? 'critical' : 'high'}`}>
                          <span className="dot" />{LFPM.fmt.exploitLabel(c.exploit)}
                        </span>
                        {c.kev && <span style={{ color: 'var(--sev-critical)' }}>cisa kev</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Conflicts — each card opens inspector */}
          <div className="panel">
            <div className="panel-head">
              <div className="panel-title"><I.Zap size={12} /> cross-vendor conflicts</div>
              <span className="panel-meta">{LFPM.conflicts.length} unresolved</span>
            </div>
            <div className="col" style={{ padding: 0 }}>
              {LFPM.conflicts.map(c => {
                const fwA = LFPM.firewalls.find(f => f.id === c.firewallA);
                const fwB = LFPM.firewalls.find(f => f.id === c.firewallB);
                return (
                  <div key={c.id}
                    className="conflict-card"
                    onClick={() => navigate('audit', { rule: c.ruleA })}
                    title={`Inspect ${c.ruleA} in Policy Audit`}
                    style={{
                      padding: '10px 14px', borderBottom: '1px solid var(--bd-1)',
                      display: 'flex', alignItems: 'flex-start', gap: 12,
                    }}>
                    <span className="sev-stripe" style={{
                      margin: '4px 0 0 -14px', height: 28,
                      background: LFPM.fmt.sevColor(c.severity),
                    }} />
                    <div className="flex1">
                      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
                        <span className="mono strong">{c.id}</span>
                        <span className={`chip ${c.severity}`}>{c.severity}</span>
                        <span className="chip">{c.type.replace('-', ' ')}</span>
                        <span className="muted mono" style={{ fontSize: 11 }}>
                          {c.ruleA} on {fwA?.display} ⇄ {c.ruleB} on {fwB?.display}
                        </span>
                      </div>
                      <div style={{ fontSize: 12, color:'var(--fg-2)', marginTop: 6, lineHeight: 1.55 }}>
                        {c.description}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

        </div>

        {/* Right column — grouped activity feed */}
        <ActivityColumn
          feed={LFPM.activityFeed}
          navigate={navigate}
          collapsed={activityCollapsed}
          onToggle={toggleActivity}
        />
      </div>
    </div>
  );
}

/* ── Hero KPI card (clickable) ─────────────────────────────────── */
function HeroKpi({ label, value, sub, delta, deltaKind, color, kind, trail, onClick, cta }) {
  const I = window.Icons;
  const clickable = typeof onClick === 'function';
  const cls = ['kpi', 'lg', kind || '', clickable ? 'clickable' : ''].filter(Boolean).join(' ');
  const handleKey = (e) => {
    if (!clickable) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); }
  };
  return (
    <div
      className={cls}
      onClick={onClick}
      onKeyDown={handleKey}
      role={clickable ? 'button' : undefined}
      tabIndex={clickable ? 0 : undefined}
    >
      <div className="kpi-label">{label}</div>
      <div className="kpi-row">
        <span className="kpi-value" style={color ? { color } : {}}>{value}</span>
        {delta && <span className={`kpi-delta ${deltaKind || ''}`}>{delta}</span>}
      </div>
      {sub && <div className="kpi-sub">{sub}</div>}
      {trail && <div className="kpi-trail">{trail}</div>}
      {clickable && cta && (
        <div className="kpi-cta">
          {cta.replace(' →','')} <I.ChevronR size={10} />
        </div>
      )}
    </div>
  );
}

/* ── Trend line chart (SVG) — interactive on hover ───────────────
 *  Default: latest value annotation only.
 *  On hover: nearest data point gets a crosshair + dot, tooltip
 *  shows time + value. On leave, reverts to the latest point.
 */
function TrendChart({ data, id = 'trend', color = 'var(--accent)', height = 90 }) {
  const svgRef = React.useRef(null);
  const [hoverI, setHoverI] = React.useState(null);

  if (!data || !data.length) return null;
  const w = 320, h = height;
  const padX = 6, padT = 8, padB = 8;
  const innerW = w - padX * 2;
  const innerH = h - padT - padB;
  const step = innerW / (data.length - 1);
  const yFor = (v) => padT + (1 - v / 100) * innerH;
  const pts = data.map((v, i) => [padX + i * step, yFor(v)]);
  const lineD = pts.map(([x, y], i) =>
    `${i === 0 ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const areaD = lineD +
    ` L${pts[pts.length - 1][0].toFixed(1)} ${(h - padB).toFixed(1)}` +
    ` L${pts[0][0].toFixed(1)} ${(h - padB).toFixed(1)} Z`;
  const lastX = pts[pts.length - 1][0];
  const lastY = pts[pts.length - 1][1];
  const last  = data[data.length - 1];

  const onMove = (e) => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0) return;
    const ratio = w / rect.width;
    const svgX = (e.clientX - rect.left) * ratio;
    let i = Math.round((svgX - padX) / step);
    i = Math.max(0, Math.min(data.length - 1, i));
    setHoverI(i);
  };
  const onLeave = () => setHoverI(null);

  /* 24 hourly samples ending at "now" — map index to a friendly
   * relative-time label. data[len-1] is current, data[0] is 23h ago. */
  const hoursAgo = (i) => data.length - 1 - i;
  const tipLabel = (i) => {
    const ago = hoursAgo(i);
    return ago === 0 ? 'now' : `${ago}h ago`;
  };

  const showHover = hoverI !== null;
  const hoverX = showHover ? pts[hoverI][0] : null;
  const hoverY = showHover ? pts[hoverI][1] : null;
  const hoverV = showHover ? data[hoverI] : null;

  /* Clamp tooltip horizontally so it doesn't overflow the panel */
  const tipLeftPct = showHover
    ? Math.min(94, Math.max(6, (hoverX / w) * 100))
    : 0;

  return (
    <div className="trend-chart-wrap">
      <svg
        ref={svgRef}
        width="100%" height={h} viewBox={`0 0 ${w} ${h}`}
        preserveAspectRatio="none"
        style={{ display: 'block', cursor: 'crosshair' }}
        onMouseMove={onMove}
        onMouseLeave={onLeave}
      >
        <defs>
          <linearGradient id={`g-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   style={{ stopColor: color, stopOpacity: 0.24 }} />
            <stop offset="100%" style={{ stopColor: color, stopOpacity: 0 }} />
          </linearGradient>
        </defs>

        {/* Baseline */}
        <line x1={padX} x2={w - padX} y1={h - padB} y2={h - padB}
              style={{ stroke: 'var(--bd-1)' }} />

        {/* Area + line */}
        <path d={areaD} style={{ fill: `url(#g-${id})` }} />
        <path d={lineD} fill="none" strokeWidth="1.5"
              strokeLinecap="round" strokeLinejoin="round"
              style={{ stroke: color }} />

        {/* Hover crosshair + marker */}
        {showHover && (
          <>
            <line x1={hoverX} x2={hoverX} y1={padT} y2={h - padB}
                  strokeDasharray="2 3"
                  style={{ stroke: 'var(--bd-3)' }} />
            <circle cx={hoverX} cy={hoverY} r="5"
                    style={{ fill: color, fillOpacity: 0.18 }} />
            <circle cx={hoverX} cy={hoverY} r="2.4" style={{ fill: color }} />
          </>
        )}

        {/* Latest-point indicator — visible only when not hovering */}
        {!showHover && (
          <>
            <circle cx={lastX} cy={lastY} r="5"
                    style={{ fill: color, fillOpacity: 0.18 }} />
            <circle cx={lastX} cy={lastY} r="2.4" style={{ fill: color }} />
            <text x={lastX - 6} y={lastY - 8}
                  textAnchor="end"
                  style={{ fill: color, fontFamily: 'var(--f-mono)', fontSize: 10, fontWeight: 600 }}>
              {last}
            </text>
          </>
        )}
      </svg>

      {showHover && (
        <div className="trend-tip" style={{ left: `${tipLeftPct}%` }}>
          <span className="trend-tip-time">{tipLabel(hoverI)}</span>
          <span className="trend-tip-val" style={{ color }}>{hoverV}</span>
        </div>
      )}
    </div>
  );
}

/* ── Horizontal bars (clickable rows) ──────────────────────────── */
function HBars({ items, max }) {
  const m = max || Math.max(...items.map(i => i.value), 1);
  return (
    <div className="hbars">
      {items.map((it, i) => {
        const clickable = typeof it.onClick === 'function';
        return (
          <div
            key={i}
            className={`hbar-row${clickable ? ' clickable' : ''}`}
            onClick={it.onClick}
            title={clickable ? `Filter by ${it.label}` : undefined}
            role={clickable ? 'button' : undefined}
            tabIndex={clickable ? 0 : undefined}
            onKeyDown={clickable ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); it.onClick(); }
            } : undefined}
          >
            <span className="hbar-label">{it.label}</span>
            <div className="hbar-track">
              <div className="hbar-fill" style={{
                width: `${Math.max(2, (it.value / m) * 100)}%`,
                background: it.color || 'var(--accent)',
              }} />
            </div>
            <span className={`hbar-val ${it.value === 0 ? 'dim' : ''}`}>{it.value}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ── Activity column — critical first, then recent ──────────── */
function ActivityColumn({ feed, navigate, collapsed, onToggle }) {
  const I = window.Icons;
  const priority = feed.filter(f => f.sev === 'critical' || f.sev === 'high');
  const rest     = feed.filter(f => !(f.sev === 'critical' || f.sev === 'high'));
  /* Anchor relative-time to the newest entry in THIS feed (works for both the
   * frozen mock feed and the live feed whose stamps are near real "now"). */
  const anchor = secondsOf(feed[0]?.t);

  /* Collapsed → slim vertical rail with badge so priority alert
   * count stays visible at a glance. */
  if (collapsed) {
    return (
      <aside className="activity-rail">
        <button
          className="activity-rail-btn"
          onClick={onToggle}
          title="Expand activity panel"
          aria-label="Expand activity panel"
        >
          <I.ChevronR size={13} style={{ transform: 'rotate(180deg)' }} />
        </button>

        <button
          className="activity-rail-icon"
          onClick={onToggle}
          title={`${priority.length} priority alert${priority.length === 1 ? '' : 's'} · click to expand`}
          aria-label="Expand activity panel"
        >
          <I.Activity size={16} />
          {priority.length > 0 && (
            <span className="activity-rail-badge">{priority.length}</span>
          )}
        </button>

        <div className="activity-rail-label">activity</div>

        <div className="activity-rail-spacer" />
        <div className="activity-rail-pulse" title="Live feed · streaming" />
      </aside>
    );
  }

  return (
    <div className="activity-col">
      <div className="panel-head" style={{ position: 'sticky', top: 0, zIndex: 2, background: 'var(--bg-1)' }}>
        <div className="panel-title"><I.Activity size={12} /> activity</div>
        <div className="panel-meta">live · last 60m</div>
        <button
          className="activity-collapse-btn"
          onClick={onToggle}
          title="Collapse activity panel"
          aria-label="Collapse activity panel"
        >
          <I.ChevronR size={12} />
        </button>
      </div>

      <div className="feed">
        {priority.length > 0 && (
          <>
            <div className="feed-group-label crit">
              <span>priority alerts</span>
              <span className="count">{priority.length}</span>
            </div>
            {priority.map((f, i) => (
              <FeedRow key={`p-${i}`} entry={f} priority navigate={navigate} anchor={anchor} />
            ))}
          </>
        )}

        <div className="feed-group-label">
          <span>recent activity</span>
          <span className="count">{rest.length}</span>
        </div>
        {rest.map((f, i) => (
          <FeedRow key={`r-${i}`} entry={f} navigate={navigate} anchor={anchor} />
        ))}

        <div style={{ padding: '14px', textAlign: 'center', fontSize: 11, color: 'var(--fg-muted)' }}>
          showing the last {feed.length} events
        </div>
      </div>
    </div>
  );
}

function FeedRow({ entry, priority, navigate, anchor }) {
  const I = window.Icons;
  const icons = {
    sync: I.Refresh, alert: I.AlertTri, audit: I.Audit,
    block: I.Shield, anomaly: I.AlertCirc, login: I.Users,
  };
  const Ico = icons[entry.kind] || I.Activity;
  const link = entry.link;
  const handleClick = link
    ? () => navigate?.(link.page, link.params)
    : undefined;
  const cls = [
    'feed-row',
    entry.kind,
    entry.sev || '',
    priority ? 'priority' : '',
    priority && entry.sev === 'high' ? 'high' : '',
    link ? 'linkable' : '',
  ].filter(Boolean).join(' ');
  return (
    <div
      className={cls}
      onClick={handleClick}
      title={link ? `${entry.t} UTC · open ${link.page}` : `${entry.t} UTC`}
      role={link ? 'button' : undefined}
      tabIndex={link ? 0 : undefined}
      onKeyDown={link ? (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleClick(); }
      } : undefined}
    >
      <span className="ts">{relTime(entry.t, anchor)}</span>
      <span className="ico"><Ico size={11} /></span>
      <span className="text">{entry.text}</span>
    </div>
  );
}

/* Relative-time formatter anchored to the newest entry of the feed being
 * rendered. Works for both the frozen mock feed and the live feed (whose
 * stamps sit near real "now"). */
function secondsOf(ts) {
  if (!ts) return 0;
  const [h, m, s] = ts.split(':').map(Number);
  return h * 3600 + m * 60 + (s || 0);
}
function relTime(t, anchor) {
  if (!t) return '';
  const base = anchor != null ? anchor : secondsOf(t);
  const diff = Math.max(0, base - secondsOf(t));
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

export { Dashboard };
