import React from "react";
import { Icons } from "./icons";
import { LFPM } from "./data";
/* ─────────────────────────────────────────────────────────────────
 * Threat Intelligence — CVE feed + firmware exposure + threat hunter
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateTI, useMemo: useMemoTI } = React;

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function ThreatIntelligence({ openInspector, intent, goTo }) {
  const I = window.Icons;
  const [sevFilter, setSev]    = useStateTI(new Set());
  const [exFilter, setEx]      = useStateTI(new Set());
  const [vendFilter, setVend]  = useStateTI(new Set());
  const [search, setSearch]    = useStateTI('');
  const [kevOnly, setKevOnly]  = useStateTI(false);
  const [hunterQ, setHunterQ]  = useStateTI('');

  /* Apply deep-link intent. Examples:
   *   #threats?severity=critical
   *   #threats?kev=1
   *   #threats?vendor=fortinet
   *   #threats?cve=CVE-2024-3400      (opens inspector)
   */
  React.useEffect(() => {
    if (!intent) return;
    if (intent.severity) setSev(new Set([intent.severity]));
    if (intent.exploit)  setEx(new Set([intent.exploit]));
    if (intent.vendor)   setVend(new Set([intent.vendor]));
    if (intent.kev === '1' || intent.kev === 'true') setKevOnly(true);
    if (intent.q)        setSearch(intent.q);
    if (intent.cve) {
      const c = LFPM.threats.find(t => t.id === intent.cve);
      if (c) openInspector({ kind:'cve', data: c });
    }
  }, [intent]);

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
  }, [sevFilter, exFilter, vendFilter, kevOnly, search]);

  const stats = {
    total:    LFPM.threats.length,
    critical: LFPM.threats.filter(t => t.severity === 'critical').length,
    kev:      LFPM.threats.filter(t => t.kev).length,
    active:   LFPM.threats.filter(t => t.exploit === 'active' || t.exploit === 'wild').length,
    exposed:  new Set(LFPM.threats.flatMap(t => t.firewallIds)).size,
  };

  /* Suggested AI hunts: each is a static example with mocked result count */
  const hunts = [
    {
      q: 'rules that bypass our tor-egress block',
      matches: 1, refs: ['POL-026', 'POL-004'], conf: 'CONF-001',
      summary: 'POL-026 (lan→wan any/any) supersedes POL-004 (block tor egress) for traffic transiting fg-600f-core.',
    },
    {
      q: 'services exposed to internet via permissive paths',
      matches: 4, refs: ['POL-025', 'POL-016', 'POL-006', 'POL-042'],
      summary: '4 firewall rules expose any/any services to or from 0.0.0.0/0 via overly-broad allow rules.',
    },
    {
      q: 'devices still vulnerable to actively-exploited CVEs',
      matches: 4, refs: ['fw-001','fw-002','fw-003','fw-004'],
      summary: '4 devices remain on firmware affected by active-exploitation advisories (CVE-2024-3400, CVE-2024-21762, CVE-2024-0012).',
    },
    {
      q: 'lateral movement paths to crown-jewel sap-erp-01',
      matches: 3, refs: ['POL-028','POL-031','POL-026'],
      summary: '3 paths reach 10.2.0.50 (sap-erp-01): direct sap rule, broad ad-extended, and lan-to-wan-full.',
    },
  ];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-sub">
            CVE feed ingested from NVD · CISA KEV · vendor advisories · last refresh 14:32 UTC
          </p>
        </div>
        <div className="row gap-2" style={{ marginLeft:'auto' }}>
          <span className="muted" style={{ fontSize: 11.5 }}>
            ingestion <span className="stat-text safe"><span className="dot" /> healthy</span>
          </span>
          <button
            className="btn"
            onClick={() => {
              window.toast('Resyncing 5 feeds', { kind: 'info', sub: 'nvd · cisa kev · psirts · mitre att&ck' });
              setTimeout(() => window.toast('Feeds up to date', { kind:'ok', sub:'12 advisories · no new entries' }), 1500);
            }}
          ><I.Refresh size={13} /> resync feeds</button>
        </div>
      </div>

      {/* KPI strip */}
      <div className="kpi-strip">
        <Kpi2 label="total cves"        value={stats.total} />
        <Kpi2 label="critical"          value={stats.critical}  color="var(--sev-critical)" />
        <Kpi2 label="cisa kev"          value={stats.kev}       color="var(--sev-critical)" />
        <Kpi2 label="actively exploited"value={stats.active}    color="var(--sev-high)" />
        <Kpi2 label="devices exposed"   value={stats.exposed} />
        <Kpi2 label="eol firmware"      value={LFPM.firmwareTimeline.filter(f => f.isEol).length} color="var(--sev-medium)" />
        <Kpi2 label="patch debt"        value="14d"             color="var(--sev-high)" />
        <Kpi2 label="oldest advisory"   value="2022-12" />
      </div>

      <div style={{
        flex: 1, display: 'grid',
        gridTemplateColumns: '1fr 320px',
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
              <span className="dot" />cisa kev only
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
                          <span key={v} className="chip" style={{ fontSize: 10 }}>{v === 'palo-alto' ? 'PA' : 'FT'}</span>
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

        {/* Right column: threat hunter + firmware exposure */}
        <div style={{ background: 'var(--bg-1)', overflow: 'auto', display:'flex', flexDirection:'column' }}>
          {/* Threat hunter */}
          <div style={{ padding: 14, borderBottom: '1px solid var(--bd-1)' }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <I.Terminal size={12} />
              ai threat hunter
              <span className="chip accent" style={{ marginLeft: 6, fontSize: 10 }}>beta</span>
            </div>
            <div className="input" style={{ marginBottom: 8 }}>
              <I.Search size={12} style={{ color:'var(--fg-3)' }} />
              <input
                placeholder='ask: "show paths from internet to crown jewels"'
                value={hunterQ}
                onChange={(e) => setHunterQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && hunterQ.trim()) {
                    const q = hunterQ.trim();
                    window.toast('Threat hunter dispatched', { kind:'info', sub: `parsing: "${q.slice(0, 40)}${q.length > 40 ? '…' : ''}"` });
                    setTimeout(() => {
                      window.toast('Hunt complete', {
                        kind:'ok',
                        sub: `3 matches · 1 high-risk path · added to "recent hunts"`,
                      });
                      setHunterQ('');
                    }, 1500);
                  }
                }}
              />
              <span className="kbd">↵</span>
            </div>
            <div className="muted" style={{ fontSize: 10.5, marginBottom: 8, textTransform:'uppercase', letterSpacing:'0.06em' }}>
              recent hunts
            </div>
            <div className="col" style={{ gap: 6 }}>
              {hunts.map((h, i) => (
                <div key={i}
                  onClick={() => window.toast(`Replaying hunt: ${h.q.slice(0, 36)}…`, { kind:'info', sub: h.summary.slice(0, 60) + '…' })}
                  style={{
                    background: 'var(--bg-2)', border: '1px solid var(--bd-1)',
                    borderRadius: 5, padding: '8px 10px',
                    cursor: 'pointer',
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-3)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'var(--bg-2)'}
                >
                  <div className="row" style={{ gap: 6, marginBottom: 4 }}>
                    <I.Code size={11} style={{ color:'var(--accent)' }} />
                    <span style={{ fontSize: 12, color:'var(--fg-0)' }}>{h.q}</span>
                  </div>
                  <div className="row" style={{ gap: 8, fontSize: 10.5, color:'var(--fg-3)', marginBottom: 4 }}>
                    <span className="mono">{h.matches} match{h.matches === 1 ? '' : 'es'}</span>
                    {h.conf && <span className="mono" style={{ color: 'var(--sev-critical)' }}>· {h.conf}</span>}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--fg-2)', lineHeight: 1.5 }}>{h.summary}</div>
                  <div className="row" style={{ gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
                    {h.refs.slice(0, 4).map(r => (
                      <span key={r} className="chip mono" style={{ fontSize: 10 }}>{r}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Firmware exposure */}
          <div style={{ padding: 14, borderBottom: '1px solid var(--bd-1)' }}>
            <div className="panel-title" style={{ marginBottom: 10 }}>
              <I.Server size={12} />
              firmware exposure
            </div>
            <div className="col" style={{ gap: 6 }}>
              {LFPM.firmwareTimeline.map(f => {
                const eolDate = new Date(f.eol);
                const months = Math.round((eolDate - new Date()) / (1000 * 60 * 60 * 24 * 30));
                const eolWarn = months < 6;
                return (
                  <div key={f.firmware} style={{
                    background: 'var(--bg-2)', border: '1px solid var(--bd-1)',
                    borderRadius: 5, padding: '8px 10px',
                  }}>
                    <div className="row" style={{ justifyContent:'space-between' }}>
                      <span className="mono" style={{ fontSize: 11.5, color:'var(--fg-0)' }}>{f.firmware}</span>
                      <span className={`stat-text ${f.cves >= 5 ? 'critical' : 'high'}`}>
                        <span className="dot" />{f.cves} cves
                      </span>
                    </div>
                    <div className="row" style={{ justifyContent:'space-between', marginTop: 4, fontSize: 10.5, color:'var(--fg-3)' }}>
                      <span className="mono">released {f.released}</span>
                      <span className="mono" style={{ color: f.isEol ? 'var(--sev-critical)' : eolWarn ? 'var(--sev-high)' : 'var(--fg-3)' }}>
                        {f.isEol ? 'end-of-life' : `eol ${f.eol}`}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div style={{ padding: 14, fontSize: 11, color: 'var(--fg-3)' }}>
            <div className="row gap-2" style={{ marginBottom: 6 }}>
              <I.AlertCirc size={11} />
              <span>data sources</span>
            </div>
            <ul style={{ margin: 0, paddingLeft: 16, lineHeight: 1.6 }}>
              <li>nvd · feed v2 · 47k advisories</li>
              <li>cisa kev catalog · 1k entries</li>
              <li>palo alto psirt · live api</li>
              <li>fortinet psirt · live api</li>
            </ul>
          </div>
        </div>
      </div>
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
