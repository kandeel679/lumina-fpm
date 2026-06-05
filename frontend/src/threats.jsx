import React from "react";
import { Icons } from "./icons";
import { LFPM } from "./data";
import {
  fetchThreatReports,
  fetchThreatReportDetail,
  triggerThreatScan,
  subscribeThreatScanProgress,
} from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Threat Intelligence — latest scan report + advisories feed
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateTI, useMemo: useMemoTI, useEffect: useEffectTI, useCallback: useCallbackTI } = React;

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function fmtScanTime(iso) {
  if (!iso) return null;
  return new Date(iso).toLocaleString([], {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function findingIsDarkweb(f) {
  return !!(f.source_onion_url || f.source_search_engine);
}

function ThreatIntelligence({ openInspector, intent, goTo, refreshData }) {
  const I = window.Icons;
  const meta = LFPM.meta || {};

  const [tab, setTab] = useStateTI('scan');
  const [sevFilter, setSev]    = useStateTI(new Set());
  const [exFilter, setEx]      = useStateTI(new Set());
  const [vendFilter, setVend]  = useStateTI(new Set());
  const [search, setSearch]    = useStateTI('');
  const [kevOnly, setKevOnly]  = useStateTI(false);
  const [highRelOnly, setHighRelOnly] = useStateTI(false);
  const [resyncing, setResyncing] = useStateTI(false);

  /* Latest scan tab state */
  const [reports, setReports] = useStateTI([]);
  const [selectedReportId, setSelectedReportId] = useStateTI(null);
  const [reportDetail, setReportDetail] = useStateTI(null);
  const [loadingReport, setLoadingReport] = useStateTI(false);
  const [scanning, setScanning] = useStateTI(false);
  const [scanProgress, setScanProgress] = useStateTI(null);

  const setTabAndHash = useCallbackTI((nextTab, extra = {}) => {
    setTab(nextTab);
    if (typeof goTo === 'function') {
      goTo('threats', { tab: nextTab, ...extra });
    }
  }, [goTo]);

  /* Apply deep-link intent */
  React.useEffect(() => {
    if (!intent) return;
    if (intent.tab === 'advisories') setTab('advisories');
    else if (intent.tab === 'scan') setTab('scan');
    if (intent.relevance === 'high') {
      setHighRelOnly(true);
      setTab('advisories');
    }
    if (intent.severity) setSev(new Set([intent.severity]));
    if (intent.exploit)  setEx(new Set([intent.exploit]));
    if (intent.vendor)   setVend(new Set([intent.vendor]));
    if (intent.kev === '1' || intent.kev === 'true') setKevOnly(true);
    if (intent.q)        setSearch(intent.q);
    if (intent.cve) {
      const c = LFPM.threats.find(t => t.id === intent.cve);
      if (c) openInspector({ kind:'cve', data: c });
    }
  }, [intent, openInspector]);

  /* Load report list */
  useEffectTI(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await fetchThreatReports(1);
        if (cancelled) return;
        setReports(data.items || []);
        const latestCompleted = (data.items || []).find(r => r.status === 'completed' || r.status === 'partial');
        if (latestCompleted && !selectedReportId) {
          setSelectedReportId(latestCompleted.id);
        }
      } catch (e) {
        console.warn('Failed to load threat reports', e);
      }
    })();
    return () => { cancelled = true; };
  }, [scanning]); // refresh list after scan

  /* Load selected report detail */
  useEffectTI(() => {
    if (!selectedReportId) {
      setReportDetail(null);
      return;
    }
    let cancelled = false;
    setLoadingReport(true);
    (async () => {
      try {
        const detail = await fetchThreatReportDetail(selectedReportId);
        if (!cancelled) setReportDetail(detail);
      } catch (e) {
        console.warn('Failed to load report detail', e);
        if (!cancelled) setReportDetail(null);
      } finally {
        if (!cancelled) setLoadingReport(false);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedReportId]);

  const runThreatScan = async () => {
    if (scanning) return;
    setScanning(true);
    setScanProgress({ phase: 'Starting scan…', percent: 0 });
    window.toast('Threat scan started', { kind: 'info', sub: 'Tor + clearnet pipeline · ~2 LLM calls' });
    try {
      const created = await triggerThreatScan();
      const reportId = created.report_id;
      setSelectedReportId(reportId);

      const unsub = subscribeThreatScanProgress(reportId, ({ type, data }) => {
        setScanProgress({
          phase: data.phase || type,
          percent: data.percent ?? 0,
          detail: data.detail || '',
          status: data.status || type,
        });
        if (type === 'SUCCESS' || data.status === 'SUCCESS') {
          window.toast('Threat scan complete', { kind: 'ok', sub: 'Report ready · refreshing findings' });
        } else if (type === 'FAILED' || data.status === 'FAILED') {
          window.toast('Threat scan failed', { kind: 'crit', sub: data.detail || data.phase || 'See worker logs' });
        }
      });

      /* Poll until terminal or timeout */
      await new Promise((resolve) => {
        const deadline = Date.now() + 30 * 60 * 1000;
        const tick = setInterval(async () => {
          if (Date.now() > deadline) {
            clearInterval(tick);
            unsub();
            resolve();
            return;
          }
          try {
            const detail = await fetchThreatReportDetail(reportId);
            if (detail.status === 'completed' || detail.status === 'partial' || detail.status === 'failed') {
              clearInterval(tick);
              unsub();
              setReportDetail(detail);
              resolve();
            }
          } catch { /* keep polling */ }
        }, 3000);
      });

      if (typeof refreshData === 'function') await refreshData();
      const list = await fetchThreatReports(1);
      setReports(list.items || []);
    } catch (e) {
      console.error(e);
      window.toast('Scan trigger failed', { kind: 'crit', sub: String(e.message || e) });
    } finally {
      setScanning(false);
      setScanProgress(null);
    }
  };

  const handleResync = async () => {
    if (resyncing) return;
    setResyncing(true);
    window.toast('Resyncing feeds', { kind: 'info', sub: 'nvd · cisa kev · threat findings' });
    try {
      if (typeof refreshData === 'function') await refreshData();
      window.toast('Feeds up to date', { kind: 'ok', sub: `${LFPM.threats.length} advisories · ${meta.newFindingsLastScan || 0} new last scan` });
    } catch (e) {
      window.toast('Resync failed', { kind: 'crit', sub: String(e.message || e) });
    } finally {
      setResyncing(false);
    }
  };

  const toggle = (set, val, setter) => {
    const ns = new Set(set);
    ns.has(val) ? ns.delete(val) : ns.add(val);
    setter(ns);
  };

  const filtered = useMemoTI(() => {
    return [...LFPM.threats].filter(t => {
      if (sevFilter.size  && !sevFilter.has(t.severity)) return false;
      if (exFilter.size   && !exFilter.has(t.exploit))   return false;
      if (vendFilter.size && !t.vendors.some(v => vendFilter.has(v))) return false;
      if (kevOnly && !t.kev) return false;
      if (highRelOnly && t.relevanceBand !== 'high') return false;
      if (search) {
        const q = search.toLowerCase();
        if (!t.id.toLowerCase().includes(q) &&
            !t.title.toLowerCase().includes(q) &&
            !t.description.toLowerCase().includes(q)) return false;
      }
      return true;
    }).sort((a, b) =>
      (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
      (b.cvss - a.cvss)
    );
  }, [sevFilter, exFilter, vendFilter, kevOnly, highRelOnly, search]);

  const stats = useMemoTI(() => ({
    total:    LFPM.threats.length,
    critical: LFPM.threats.filter(t => t.severity === 'critical').length,
    high:     LFPM.threats.filter(t => t.severity === 'high').length,
    kev:      LFPM.threats.filter(t => t.kev).length,
    highRel:  LFPM.threats.filter(t => t.relevanceBand === 'high').length,
    newLast:  meta.newFindingsLastScan || 0,
    exposed:  new Set(LFPM.threats.flatMap(t => t.firewallIds)).size,
    clearnet: LFPM.threats.filter(t => t.isClearnet).length,
    darkweb:  LFPM.threats.filter(t => t.isDarkweb).length,
  }), [meta.newFindingsLastScan]);

  const scanFindings = reportDetail?.findings || [];
  const scanLaneCounts = useMemoTI(() => {
    let clearnet = 0;
    let darkweb = 0;
    scanFindings.forEach(f => {
      if (findingIsDarkweb(f)) darkweb += 1;
      else clearnet += 1;
    });
    return { clearnet, darkweb, total: scanFindings.length };
  }, [scanFindings]);

  const subtitle = reportDetail?.scan_completed_at
    ? `Last scan ${fmtScanTime(reportDetail.scan_completed_at)} · report #${reportDetail.id}`
    : meta.lastScanAt
      ? `Last scan ${fmtScanTime(meta.lastScanAt)} · ${meta.totalFindings ?? stats.total} findings`
      : 'No completed scans · run a threat scan to begin';

  const completedReports = reports.filter(r => r.status === 'completed' || r.status === 'partial');

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-sub">{subtitle}</p>
        </div>
        <div className="row gap-2" style={{ marginLeft:'auto', alignItems:'center' }}>
          <div className="seg">
            <button
              className={tab === 'scan' ? 'active' : ''}
              onClick={() => setTabAndHash('scan')}
            >latest scan</button>
            <button
              className={tab === 'advisories' ? 'active' : ''}
              onClick={() => setTabAndHash('advisories')}
            >advisories</button>
          </div>
          {tab === 'scan' && (
            <button
              className="btn primary"
              onClick={runThreatScan}
              disabled={scanning}
            >
              {scanning
                ? <><span className="li-spinner" /> scanning…</>
                : <><I.Play size={13} /> run threat scan</>}
            </button>
          )}
          {tab === 'advisories' && (
            <button className="btn" onClick={handleResync} disabled={resyncing}>
              <I.Refresh size={13} /> {resyncing ? 'syncing…' : 'resync feeds'}
            </button>
          )}
        </div>
      </div>

      {/* KPI strip — live counts */}
      <div className="kpi-strip">
        <Kpi2 label="total advisories" value={stats.total} />
        <Kpi2 label="critical"          value={stats.critical}  color="var(--sev-critical)" />
        <Kpi2 label="high relevance"    value={stats.highRel}   color="var(--accent)" />
        <Kpi2 label="cisa kev"          value={stats.kev}       color="var(--sev-critical)" />
        <Kpi2 label="new last scan"     value={stats.newLast}   color="var(--sev-high)" />
        <Kpi2 label="clearnet"          value={stats.clearnet} />
        <Kpi2 label="dark web"          value={stats.darkweb}   color="var(--fg-2)" />
        <Kpi2 label="devices exposed"   value={stats.exposed} />
      </div>

      {tab === 'scan' ? (
        <LatestScanPanel
          I={I}
          reportDetail={reportDetail}
          loadingReport={loadingReport}
          completedReports={completedReports}
          selectedReportId={selectedReportId}
          onSelectReport={setSelectedReportId}
          scanLaneCounts={scanLaneCounts}
          scanning={scanning}
          scanProgress={scanProgress}
          openInspector={openInspector}
        />
      ) : (
        <AdvisoriesPanel
          I={I}
          filtered={filtered}
          stats={stats}
          sevFilter={sevFilter}
          exFilter={exFilter}
          vendFilter={vendFilter}
          search={search}
          kevOnly={kevOnly}
          highRelOnly={highRelOnly}
          setSev={setSev}
          setEx={setEx}
          setVend={setVend}
          setSearch={setSearch}
          setKevOnly={setKevOnly}
          setHighRelOnly={setHighRelOnly}
          toggle={toggle}
          openInspector={openInspector}
          goTo={goTo}
        />
      )}
    </div>
  );
}

function LatestScanPanel({
  I, reportDetail, loadingReport, completedReports, selectedReportId,
  onSelectReport, scanLaneCounts, scanning, scanProgress, openInspector,
}) {
  if (loadingReport && !reportDetail) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--fg-3)' }}>
        <span className="li-spinner" /> loading report…
      </div>
    );
  }

  if (!reportDetail && !scanning) {
    return (
      <div style={{
        padding: 48, textAlign: 'center', background: 'var(--bg-1)',
        border: '1px solid var(--bd-1)', borderRadius: 6,
      }}>
        <I.Shield size={32} style={{ color: 'var(--fg-3)', marginBottom: 12 }} />
        <div style={{ fontSize: 15, color: 'var(--fg-1)', marginBottom: 6 }}>No scan reports yet</div>
        <div className="muted" style={{ fontSize: 12.5 }}>Run a threat scan to assess your firewall inventory against Tor + clearnet intel.</div>
      </div>
    );
  }

  const clean = reportDetail?.clean;
  const stats = reportDetail?.stats || {};
  const bySev = stats.by_severity || {};

  return (
    <div className="col" style={{ gap: 1, flex: 1, minHeight: 0 }}>
      {/* Report picker + progress */}
      <div style={{
        padding: '10px 16px', background: 'var(--bg-1)', borderBottom: '1px solid var(--bd-1)',
        display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
      }}>
        {completedReports.length > 0 && (
          <>
            <span className="muted" style={{ fontSize: 11.5 }}>report</span>
            <select
              className="field-input"
              style={{ width: 200, padding: '6px 10px', fontSize: 12 }}
              value={selectedReportId || ''}
              onChange={(e) => onSelectReport(Number(e.target.value))}
            >
              {completedReports.map(r => (
                <option key={r.id} value={r.id}>
                  #{r.id} · {fmtScanTime(r.scan_completed_at || r.scan_started_at)} · {r.status}
                </option>
              ))}
            </select>
          </>
        )}
        {scanning && scanProgress && (
          <div className="row gap-2" style={{ flex: 1, minWidth: 200 }}>
            <div style={{
              flex: 1, height: 4, background: 'var(--bg-3)', borderRadius: 2, overflow: 'hidden',
            }}>
              <div style={{
                width: `${scanProgress.percent || 5}%`, height: '100%',
                background: 'var(--accent)', transition: 'width 0.4s',
              }} />
            </div>
            <span className="mono muted" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
              {scanProgress.phase}
            </span>
          </div>
        )}
        {reportDetail?.llm_model_name && (
          <span className="chip mono" style={{ fontSize: 10, marginLeft: 'auto' }}>
            {reportDetail.llm_model_name}
          </span>
        )}
      </div>

      {/* Clean status hero */}
      {reportDetail && (
        <div style={{
          padding: '20px 24px',
          background: clean ? 'var(--sev-safe-bg)' : 'var(--sev-high-bg)',
          borderBottom: `1px solid ${clean ? 'var(--sev-safe-bd)' : 'var(--sev-high-bd)'}`,
        }}>
          <div className="row gap-3" style={{ alignItems: 'flex-start', marginBottom: 12 }}>
            {clean
              ? <I.CheckCirc size={22} style={{ color: 'var(--sev-safe)', flexShrink: 0 }} />
              : <I.AlertCirc size={22} style={{ color: 'var(--sev-high)', flexShrink: 0 }} />}
            <div>
              <div style={{ fontSize: 16, fontWeight: 600, color: 'var(--fg-0)', marginBottom: 4 }}>
                {clean === true
                  ? 'Firewall posture: clean'
                  : clean === false
                    ? 'Action required — medium+ relevance findings'
                    : 'Assessment pending'}
              </div>
              {reportDetail.coverage_note && (
                <p style={{ fontSize: 12.5, color: 'var(--fg-2)', lineHeight: 1.55, margin: 0, maxWidth: 900 }}>
                  {reportDetail.coverage_note}
                </p>
              )}
            </div>
          </div>

          {/* Metrics row */}
          <div className="row gap-3" style={{ flexWrap: 'wrap', marginBottom: 16 }}>
            <MetricChip label="total findings" value={stats.total_findings ?? scanLaneCounts.total} />
            <MetricChip label="critical" value={bySev.critical || 0} color="var(--sev-critical)" />
            <MetricChip label="high" value={bySev.high || 0} color="var(--sev-high)" />
            <MetricChip label="correlated rules" value={stats.correlated_rules || 0} />
            <MetricChip label="clearnet" value={scanLaneCounts.clearnet} />
            <MetricChip label="dark web" value={scanLaneCounts.darkweb} />
            {reportDetail.scan_duration_seconds != null && (
              <MetricChip label="duration" value={`${reportDetail.scan_duration_seconds}s`} />
            )}
          </div>

          {/* Narrative */}
          {reportDetail.narrative_summary && (
            <div style={{
              background: 'var(--bg-0)', border: '1px solid var(--bd-1)',
              borderRadius: 5, padding: '14px 16px',
            }}>
              <div className="panel-title" style={{ marginBottom: 8, fontSize: 11.5 }}>
                <I.Terminal size={12} /> assessment narrative
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--fg-1)', lineHeight: 1.65, whiteSpace: 'pre-wrap' }}>
                {reportDetail.narrative_summary}
              </div>
            </div>
          )}
        </div>
      )}

      {/* High-relevance findings from this report */}
      {reportDetail?.findings?.length > 0 && (
        <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg-0)' }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--bd-1)', background: 'var(--bg-1)' }}>
            <span className="panel-title"><I.Threat size={12} /> report findings ({reportDetail.findings.length})</span>
          </div>
          <table className="t">
            <thead>
              <tr>
                <th style={{ paddingLeft: 14 }}>finding</th>
                <th>sev</th>
                <th>relevance</th>
                <th>source lane</th>
                <th>devices</th>
              </tr>
            </thead>
            <tbody>
              {[...reportDetail.findings]
                .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9))
                .slice(0, 50)
                .map(f => {
                  const cveId = f.title?.includes('CVE-') ? f.title.split(' ')[0].replace(/[:,]$/, '') : `FND-${f.id}`;
                  const isDw = findingIsDarkweb(f);
                  const mapped = LFPM.threats.find(t => t.id === cveId);
                  return (
                    <tr
                      key={f.id}
                      onClick={() => mapped && openInspector({ kind: 'cve', data: mapped })}
                      style={{ cursor: mapped ? 'pointer' : 'default' }}
                    >
                      <td>
                        <span className="sev-stripe" style={{ background: LFPM.fmt.sevColor(f.severity) }} />
                        <span className="mono strong">{cveId}</span>
                        <div className="dim truncate" style={{ fontSize: 10.5, maxWidth: 320 }}>{f.title}</div>
                      </td>
                      <td>
                        <span className={`stat-text ${f.severity}`}><span className="dot" />{f.severity}</span>
                      </td>
                      <td>
                        {f.relevance_band === 'high' && (
                          <span className="chip accent" style={{ fontSize: 9.5 }}>
                            high{f.relevance_score != null ? ` ${f.relevance_score}` : ''}
                          </span>
                        )}
                        {f.relevance_band === 'medium' && (
                          <span className="chip" style={{ fontSize: 9.5 }}>medium</span>
                        )}
                        {(!f.relevance_band || f.relevance_band === 'low' || f.relevance_band === 'none') && (
                          <span className="dim" style={{ fontSize: 10.5 }}>{f.relevance_band || '—'}</span>
                        )}
                      </td>
                      <td>
                        <span className="chip" style={{ fontSize: 10 }}>
                          {isDw ? 'dark web' : (f.source_marketplace_or_forum || 'clearnet')}
                        </span>
                      </td>
                      <td className="mono dim" style={{ fontSize: 11 }}>
                        {(f.matched_device_ids || []).map(id =>
                          LFPM.firewalls.find(fw => fw.id === String(id))?.display
                        ).filter(Boolean).join(', ') || '—'}
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AdvisoriesPanel({
  I, filtered, stats, sevFilter, exFilter, vendFilter, search,
  kevOnly, highRelOnly, setSev, setEx, setVend, setSearch,
  setKevOnly, setHighRelOnly, toggle, openInspector, goTo,
}) {
  const applyQuickFilter = (kind) => {
    setSev(new Set());
    setEx(new Set());
    setKevOnly(false);
    setHighRelOnly(false);
    if (kind === 'high-relevance') {
      setHighRelOnly(true);
      if (typeof goTo === 'function') goTo('threats', { tab: 'advisories', relevance: 'high' });
    } else if (kind === 'kev') {
      setKevOnly(true);
      if (typeof goTo === 'function') goTo('threats', { tab: 'advisories', kev: '1' });
    } else if (kind === 'critical') {
      setSev(new Set(['critical']));
      if (typeof goTo === 'function') goTo('threats', { tab: 'advisories', severity: 'critical' });
    }
  };

  return (
    <div style={{
      flex: 1, display: 'grid',
      gridTemplateColumns: '1fr 280px',
      gap: 1, background: 'var(--bd-1)', minHeight: 0, overflow: 'hidden',
    }}>
      {/* Left: filters + table */}
      <div style={{ background: 'var(--bg-0)', display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
        <div style={{
          padding: '10px 16px',
          borderBottom: '1px solid var(--bd-1)',
          display: 'flex', alignItems: 'center', gap: 10,
          background: 'var(--bg-1)',
          flexWrap: 'wrap',
          flexShrink: 0,
        }}>
          <div className="input" style={{ width: 260 }}>
            <I.Search size={12} style={{ color:'var(--fg-3)' }} />
            <input placeholder="filter advisories…" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <div className="seg">
            {['critical','high','medium'].map(s => (
              <button key={s} className={sevFilter.has(s) ? 'active' : ''} onClick={() => toggle(sevFilter, s, setSev)}>
                <span className={`stat-text ${s}`}><span className="dot" />{s}</span>
              </button>
            ))}
          </div>
          <div className="seg">
            {['active','wild','poc','none'].map(e => (
              <button key={e} className={exFilter.has(e) ? 'active' : ''} onClick={() => toggle(exFilter, e, setEx)}>
                {e}
              </button>
            ))}
          </div>
          <div className="seg">
            <button className={vendFilter.has('palo-alto') ? 'active' : ''} onClick={() => toggle(vendFilter, 'palo-alto', setVend)}>palo alto</button>
            <button className={vendFilter.has('fortinet') ? 'active' : ''}  onClick={() => toggle(vendFilter, 'fortinet', setVend)}>fortinet</button>
          </div>
          <button
            className={`chip ${kevOnly ? 'critical' : ''}`}
            onClick={() => setKevOnly(k => !k)}
            style={{ cursor:'pointer' }}
          >
            <span className="dot" />cisa kev
          </button>
          <button
            className={`chip ${highRelOnly ? 'accent' : ''}`}
            onClick={() => setHighRelOnly(k => !k)}
            style={{ cursor:'pointer' }}
          >
            <span className="dot" />high relevance
          </button>
          <div className="tb-spacer" />
          <span className="muted mono" style={{ fontSize: 11 }}>{filtered.length} advisories</span>
        </div>

        <div style={{ flex: 1, overflow: 'auto' }}>
          <table className="t">
            <thead>
              <tr>
                <th style={{ paddingLeft: 14 }}>cve</th>
                <th>sev / cvss</th>
                <th>title</th>
                <th>vendor</th>
                <th>affected devices</th>
                <th>exploit</th>
                <th>published</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => (
                <tr key={t.id} onClick={() => openInspector({ kind:'cve', data: t })}>
                  <td>
                    <span className="sev-stripe" style={{ background: LFPM.fmt.sevColor(t.severity) }} />
                    <div className="row gap-2">
                      <span className="mono strong">{t.id}</span>
                      {t.kev && <span className="chip critical" style={{ fontSize: 10 }}>KEV</span>}
                      {t.isNew && <span className="chip accent" style={{ fontSize: 10 }}>new</span>}
                    </div>
                  </td>
                  <td>
                    <span className={`stat-text ${t.severity}`}><span className="dot" />{t.severity}</span>
                    <div className="mono" style={{ fontSize: 10.5, color: LFPM.fmt.sevColor(t.severity), fontWeight: 600 }}>
                      {t.cvss.toFixed(1)}
                    </div>
                  </td>
                  <td className="truncate" style={{ maxWidth: 340 }}>
                    <div className="row gap-2" style={{ alignItems: 'center' }}>
                      <span className="truncate" style={{ color:'var(--fg-1)', maxWidth: 240 }}>{t.title}</span>
                      {t.relevanceBand === 'high' && (
                        <span className="chip accent" style={{ fontSize: 9.5 }}
                              title={t.relevanceReason || 'matches your firewall inventory'}>
                          relevant{t.relevanceScore != null ? ` ${t.relevanceScore}` : ''}
                        </span>
                      )}
                      {t.relevanceBand === 'medium' && (
                        <span className="chip" style={{ fontSize: 9.5 }}
                              title={t.relevanceReason || 'possible relevance to your inventory'}>
                          rel: med
                        </span>
                      )}
                    </div>
                    <div className="dim" style={{ fontSize: 10.5, marginTop: 1 }}>
                      {(t.firmware || []).join(' · ')}
                    </div>
                  </td>
                  <td>
                    <div className="row gap-2">
                      {t.vendors.map(v => (
                        <span key={v} className="chip" style={{ fontSize: 10 }}>{v === 'palo-alto' ? 'PA' : v === 'fortinet' ? 'FT' : 'CS'}</span>
                      ))}
                    </div>
                  </td>
                  <td className="mono dim" style={{ fontSize: 11 }}>
                    {t.firewallIds.map(id => LFPM.firewalls.find(f => f.id === id)?.display).filter(Boolean).join(', ')}
                  </td>
                  <td>
                    <span className={`stat-text ${t.exploit === 'active' || t.exploit === 'wild' ? 'critical' : t.exploit === 'poc' ? 'high' : 'dim'}`}>
                      <span className="dot" />{LFPM.fmt.exploitLabel(t.exploit)}
                    </span>
                  </td>
                  <td className="mono dim">{t.published}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Right column: quick filters + data sources */}
      <div style={{ background: 'var(--bg-1)', overflow: 'auto', display:'flex', flexDirection:'column' }}>
        <div style={{ padding: 14, borderBottom: '1px solid var(--bd-1)' }}>
          <div className="panel-title" style={{ marginBottom: 10 }}>
            <I.Filter size={12} />
            quick filters
          </div>
          <div className="col" style={{ gap: 6 }}>
            <QuickFilterBtn
              I={I}
              label="high relevance"
              count={stats.highRel}
              color="var(--accent)"
              active={highRelOnly}
              onClick={() => applyQuickFilter('high-relevance')}
              sub="inventory-confirmed or version-matched CVEs"
            />
            <QuickFilterBtn
              I={I}
              label="cisa kev"
              count={stats.kev}
              color="var(--sev-critical)"
              active={kevOnly}
              onClick={() => applyQuickFilter('kev')}
              sub="actively exploited in the wild"
            />
            <QuickFilterBtn
              I={I}
              label="critical severity"
              count={stats.critical}
              color="var(--sev-critical)"
              active={sevFilter.has('critical') && sevFilter.size === 1}
              onClick={() => applyQuickFilter('critical')}
              sub="CVSS 9+ or vendor critical"
            />
          </div>
        </div>

        <div style={{ padding: 14, borderBottom: '1px solid var(--bd-1)' }}>
          <div className="panel-title" style={{ marginBottom: 10 }}>
            <I.Server size={12} />
            source lanes
          </div>
          <div className="col" style={{ gap: 6 }}>
            <div style={{ background: 'var(--bg-2)', border: '1px solid var(--bd-1)', borderRadius: 5, padding: '8px 10px' }}>
              <div className="row" style={{ justifyContent:'space-between' }}>
                <span style={{ fontSize: 12, color:'var(--fg-0)' }}>clearnet (NVD + CISA KEV)</span>
                <span className="mono" style={{ fontSize: 11.5, color:'var(--fg-1)' }}>{stats.clearnet}</span>
              </div>
            </div>
            <div style={{ background: 'var(--bg-2)', border: '1px solid var(--bd-1)', borderRadius: 5, padding: '8px 10px' }}>
              <div className="row" style={{ justifyContent:'space-between' }}>
                <span style={{ fontSize: 12, color:'var(--fg-0)' }}>dark web (Tor scrape)</span>
                <span className="mono" style={{ fontSize: 11.5, color:'var(--fg-1)' }}>{stats.darkweb}</span>
              </div>
            </div>
          </div>
        </div>

        <div style={{ padding: 14, fontSize: 11, color: 'var(--fg-3)' }}>
          <div className="row gap-2" style={{ marginBottom: 6 }}>
            <I.AlertCirc size={11} />
            <span>data sources</span>
          </div>
          <ul style={{ margin: 0, paddingLeft: 16, lineHeight: 1.6 }}>
            <li>nvd · pubStartDate · 120d window</li>
            <li>cisa kev catalog · product-scoped</li>
            <li>tor · curated .onion search engines</li>
            <li>llm assessment · ~2 calls/scan</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function QuickFilterBtn({ I, label, count, color, active, onClick, sub }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: active ? 'var(--accent-bg)' : 'var(--bg-2)',
        border: `1px solid ${active ? 'var(--accent-bd)' : 'var(--bd-1)'}`,
        borderRadius: 5, padding: '8px 10px', cursor: 'pointer',
      }}
      onMouseEnter={(e) => { if (!active) e.currentTarget.style.background = 'var(--bg-3)'; }}
      onMouseLeave={(e) => { if (!active) e.currentTarget.style.background = 'var(--bg-2)'; }}
    >
      <div className="row" style={{ justifyContent:'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 12, color:'var(--fg-0)' }}>{label}</span>
        <span className="mono" style={{ fontSize: 11.5, color, fontWeight: 600 }}>{count}</span>
      </div>
      <div style={{ fontSize: 10.5, color: 'var(--fg-3)', lineHeight: 1.4 }}>{sub}</div>
    </div>
  );
}

function MetricChip({ label, value, color = 'var(--fg-0)' }) {
  return (
    <div style={{
      background: 'var(--bg-0)', border: '1px solid var(--bd-1)',
      borderRadius: 4, padding: '6px 12px', minWidth: 90,
    }}>
      <div className="muted" style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
      <div className="mono" style={{ fontSize: 16, fontWeight: 600, color }}>{value}</div>
    </div>
  );
}

function Kpi2({ label, value, color = 'var(--fg-0)' }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-row">
        <span className="kpi-value" style={{ color }}>{value}</span>
      </div>
    </div>
  );
}

export { ThreatIntelligence };
