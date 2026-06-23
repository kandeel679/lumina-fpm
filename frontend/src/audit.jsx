import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
import { triggerDeviceAnalysis } from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Policy Audit — faceted ruleset analyzer
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateA, useMemo: useMemoA } = React;

const VIEWS = [
  { id: 'all',          label: 'all rules',                       count: (LFPM) => LFPM.policies.length },
  { id: 'anomalies',    label: 'flagged',             highlight: true, count: (LFPM) => LFPM.policies.filter(p => p.status !== 'clean').length },
  { id: 'critical',     label: 'critical',                        count: (LFPM) => LFPM.policies.filter(p => p.status === 'critical').length },
  { id: 'high',         label: 'high',                            count: (LFPM) => LFPM.policies.filter(p => p.status === 'high').length },
  { id: 'highrisk',     label: 'risk ≥ 80',                       count: (LFPM) => LFPM.policies.filter(p => p.riskScore >= 80).length },
  { id: 'disabled',     label: 'disabled rules',                  count: (LFPM) => LFPM.policies.filter(p => !p.enabled).length },
];

function PolicyAudit({ openInspector, inspectorOpen, selectedRuleId, intent, goTo, refreshData }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const [running, setRunning] = React.useState(false);
  const [view, setView]       = useStateA('all');
  const [search, setSearch]   = useStateA('');
  const [vendor, setVendor]   = useStateA(new Set()); // set of vendorId
  const [fws, setFws]         = useStateA(new Set()); // set of fwId
  const [statuses, setStat]   = useStateA(new Set()); // set of status
  const [actions, setActions] = useStateA(new Set()); // set of 'allow'/'deny'
  const [minRisk, setMinRisk] = useStateA(0);
  const [sortKey, setSortKey] = useStateA('riskScore');
  const [sortDir, setSortDir] = useStateA('desc');

  /* Apply intent (URL/deep-link) once whenever it changes. ──────────
   * Examples:
   *   #audit?filter=shadowed
   *   #audit?rule=POL-026         (opens inspector)
   *   #audit?firewall=fw-004
   *   #audit?vendor=palo-alto&filter=permissive
   */
  React.useEffect(() => {
    if (!intent) return;
    if (intent.filter && VIEWS.some(v => v.id === intent.filter)) {
      setView(intent.filter);
    }
    if (intent.firewall && LFPM.firewalls.some(f => f.id === intent.firewall)) {
      setFws(new Set([intent.firewall]));
    }
    if (intent.vendor && (intent.vendor === 'palo-alto' || intent.vendor === 'fortinet')) {
      setVendor(new Set([intent.vendor]));
    }
    if (intent.status) setStat(new Set([intent.status]));
    if (intent.q) setSearch(intent.q);
    if (intent.minRisk) setMinRisk(+intent.minRisk || 0);
    if (intent.rule) {
      const r = LFPM.policies.find(p => p.id === intent.rule);
      if (r) openInspector({ kind:'rule', data: r });
    }
  }, [intent, LFPM.policies, LFPM.firewalls]);

  const toggle = (set, val, setter) => {
    const ns = new Set(set);
    ns.has(val) ? ns.delete(val) : ns.add(val);
    setter(ns);
  };

  const filtered = useMemoA(() => {
    let data = [...LFPM.policies];

    /* saved view */
    if (view === 'anomalies')  data = data.filter(p => p.status !== 'clean');
    if (view === 'critical')   data = data.filter(p => p.status === 'critical');
    if (view === 'high')       data = data.filter(p => p.status === 'high');
    if (view === 'highrisk')   data = data.filter(p => p.riskScore >= 80);
    if (view === 'disabled')   data = data.filter(p => !p.enabled);

    if (vendor.size > 0)   data = data.filter(p => vendor.has(LFPM.firewalls.find(f => f.id === p.firewallId)?.vendorId));
    if (fws.size > 0)      data = data.filter(p => fws.has(p.firewallId));
    if (statuses.size > 0) data = data.filter(p => statuses.has(p.status));
    if (actions.size > 0)  data = data.filter(p => actions.has(p.action));
    if (minRisk > 0)       data = data.filter(p => p.riskScore >= minRisk);

    if (search) {
      const q = search.toLowerCase();
      data = data.filter(p =>
        p.id.toLowerCase().includes(q) ||
        p.name.toLowerCase().includes(q) ||
        p.srcIp.toLowerCase().includes(q) ||
        p.dstIp.toLowerCase().includes(q) ||
        p.service.toLowerCase().includes(q) ||
        p.srcZone.toLowerCase().includes(q) ||
        p.dstZone.toLowerCase().includes(q)
      );
    }

    data.sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return data;
  }, [view, search, vendor, fws, statuses, actions, minRisk, sortKey, sortDir, LFPM.policies, LFPM.firewalls]);

  const counts = useMemoA(() => {
    const all = LFPM.policies;
    return {
      critical:   all.filter(p => p.status === 'critical').length,
      high:       all.filter(p => p.status === 'high').length,
      medium:     all.filter(p => p.status === 'medium').length,
      low:        all.filter(p => p.status === 'low').length,
      clean:      all.filter(p => p.status === 'clean').length,
      flagged:    all.filter(p => p.status !== 'clean').length,
      allow:      all.filter(p => p.action === 'allow').length,
      deny:       all.filter(p => p.action === 'deny').length,
      pa:         all.filter(p => LFPM.firewalls.find(f => f.id === p.firewallId)?.vendorId === 'palo-alto').length,
      ft:         all.filter(p => LFPM.firewalls.find(f => f.id === p.firewallId)?.vendorId === 'fortinet').length,
    };
  }, [LFPM.policies, LFPM.firewalls]);

  const sort = (k) => {
    if (sortKey === k) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(k); setSortDir('desc'); }
  };

  const SortHeader = ({ k, children, align }) => (
    <th onClick={() => sort(k)} className="sortable" style={{ textAlign: align || 'left' }}>
      <span className="row gap-2" style={{ justifyContent: align === 'right' ? 'flex-end' : 'flex-start' }}>
        {children}
        {sortKey === k && <I.Chevron size={10} style={{ transform: sortDir === 'asc' ? 'rotate(180deg)' : '' }} />}
      </span>
    </th>
  );

  const activeFilters = [
    ...[...statuses].map(s => ({ key:'status:'+s, label:s, clear: () => toggle(statuses, s, setStat) })),
    ...[...vendor].map(v => ({ key:'vendor:'+v, label: v === 'palo-alto' ? 'palo alto' : 'fortinet', clear: () => toggle(vendor, v, setVendor) })),
    ...[...fws].map(f => ({ key:'fw:'+f, label: LFPM.firewalls.find(x => x.id === f)?.display || f, clear: () => toggle(fws, f, setFws) })),
    ...[...actions].map(a => ({ key:'action:'+a, label:a, clear: () => toggle(actions, a, setActions) })),
    ...(minRisk > 0 ? [{ key:'risk', label:`risk ≥ ${minRisk}`, clear: () => setMinRisk(0) }] : []),
    ...(search ? [{ key:'q', label:`"${search}"`, clear: () => setSearch('') }] : []),
  ];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Policy Audit</h1>
          <p className="page-sub">
            {filtered.length} of {LFPM.policies.length} rules · {counts.flagged} flagged · {LFPM.policies.reduce((a, p) => a + (p.anomalyCount || 0), 0)} findings
          </p>
        </div>
        <div className="row gap-2" style={{ marginLeft: 'auto' }}>
          <button
            className="btn"
            onClick={() => {
              const esc = (v) => {
                const s = String(v ?? '');
                return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
              };
              const header = ['id','name','device','vendor','src_zone','dst_zone','src','dst','service','action','status','priority','risk_score','enabled'];
              const rows = filtered.map(p => {
                const fw = LFPM.firewalls.find(f => f.id === p.firewallId);
                return [p.id, p.name, fw?.display || '—', fw?.vendor || '—', p.srcZone, p.dstZone, p.srcIp, p.dstIp, p.service, p.action, p.status, p.priority, p.riskScore, p.enabled ? 'yes' : 'no'].map(esc).join(',');
              });
              const fname = `policy-audit-${new Date().toISOString().slice(0,10)}.csv`;
              const blob = new Blob([header.join(',') + '\n' + rows.join('\n')], { type: 'text/csv;charset=utf-8' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url; a.download = fname;
              document.body.appendChild(a); a.click(); a.remove();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
              window.toast(`Exported ${filtered.length} rule${filtered.length === 1 ? '' : 's'} as CSV`, { kind:'ok', sub: fname });
            }}
          ><I.Download size={13} /> export csv</button>
          <button
            className="btn primary"
            disabled={running}
            style={running ? { opacity: 0.7, cursor: 'wait' } : {}}
            onClick={async () => {
              if (running) return;
              setRunning(true);
              window.toast('Audit run started', { kind:'info', sub:`analyzing ${LFPM.policies.length} rules across ${LFPM.firewalls.length} firewalls…` });
              try {
                const results = await Promise.allSettled(
                  LFPM.firewalls.map(fw => triggerDeviceAnalysis(fw.id))
                );
                const ok = results.filter(r => r.status === 'fulfilled').length;
                const failed = results.length - ok;
                if (typeof refreshData === 'function') {
                  await refreshData();
                }
                const updatedAnomalies = LFPM.policies.filter(p => p.status !== 'clean').length;
                if (ok === 0) {
                  window.toast('Audit failed', { kind:'crit', sub:`0/${results.length} devices analyzed — backend unreachable` });
                } else {
                  window.toast('Audit complete', {
                    kind: failed > 0 ? 'warn' : 'ok',
                    sub: `${ok}/${results.length} devices analyzed · ${updatedAnomalies} anomalies open${failed > 0 ? ` · ${failed} failed` : ''}`,
                  });
                }
              } catch (e) {
                console.error(e);
                window.toast('Audit failed', { kind:'crit', sub: String(e.message || e) });
              } finally {
                setRunning(false);
              }
            }}
          ><I.Play size={13} /> {running ? 'running…' : 'run audit'}</button>
        </div>
      </div>

      <div style={{ flex: 1, display:'grid', gridTemplateColumns:'232px 1fr', minHeight: 0, overflow: 'hidden' }}>
        {/* Filter sidebar */}
        <aside className="filter-side">
          <div className="group">
            <div className="group-title">saved views</div>
            <div className="col" style={{ gap: 2 }}>
              {VIEWS.map(v => (
                <button
                  key={v.id}
                  onClick={() => setView(v.id)}
                  style={{
                    display:'flex', justifyContent:'space-between', alignItems:'center',
                    padding:'5px 8px', fontSize:12,
                    background: view === v.id ? 'var(--bg-3)' : 'transparent',
                    color: view === v.id ? 'var(--fg-0)' : 'var(--fg-2)',
                    borderRadius: 3,
                    fontWeight: view === v.id ? 500 : 400,
                  }}
                >
                  <span className="row gap-2">
                    {v.highlight && <span style={{ width: 4, height: 4, borderRadius: 2, background: 'var(--sev-high)' }} />}
                    {v.label}
                  </span>
                  <span className="muted mono" style={{ fontSize: 10.5 }}>{v.count(LFPM)}</span>
                </button>
              ))}
            </div>
          </div>

          <FilterGroup title="severity">
            {[
              { v:'critical', count: counts.critical },
              { v:'high',     count: counts.high },
              { v:'medium',   count: counts.medium },
              { v:'low',      count: counts.low },
              { v:'clean',    count: counts.clean },
            ].map(s => (
              <FilterCheck key={s.v} on={statuses.has(s.v)} onChange={() => toggle(statuses, s.v, setStat)} count={s.count}>
                <span className={`stat-text ${s.v === 'clean' ? 'safe' : s.v}`}>
                  <span className="dot" />
                  {s.v}
                </span>
              </FilterCheck>
            ))}
          </FilterGroup>

          <FilterGroup title="vendor">
            <FilterCheck on={vendor.has('palo-alto')} onChange={() => toggle(vendor, 'palo-alto', setVendor)} count={counts.pa}>palo alto networks</FilterCheck>
            <FilterCheck on={vendor.has('fortinet')}  onChange={() => toggle(vendor, 'fortinet', setVendor)}  count={counts.ft}>fortinet</FilterCheck>
          </FilterGroup>

          <FilterGroup title="firewall">
            {LFPM.firewalls.map(fw => {
              const c = LFPM.policies.filter(p => p.firewallId === fw.id).length;
              return (
                <FilterCheck key={fw.id} on={fws.has(fw.id)} onChange={() => toggle(fws, fw.id, setFws)} count={c}>
                  <span className="mono" style={{ fontSize: 11.5 }}>{fw.display}</span>
                </FilterCheck>
              );
            })}
          </FilterGroup>

          <FilterGroup title="action">
            <FilterCheck on={actions.has('allow')} onChange={() => toggle(actions, 'allow', setActions)} count={counts.allow}>
              <span className="verb allow">allow</span>
            </FilterCheck>
            <FilterCheck on={actions.has('deny')}  onChange={() => toggle(actions, 'deny', setActions)} count={counts.deny}>
              <span className="verb deny">deny</span>
            </FilterCheck>
          </FilterGroup>

          <FilterGroup title="minimum risk">
            <div className="row" style={{ alignItems: 'center', gap: 8 }}>
              <input
                type="range" min="0" max="100" step="5"
                value={minRisk}
                onChange={(e) => setMinRisk(+e.target.value)}
                style={{ flex: 1, accentColor: 'var(--accent)' }}
              />
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--fg-0)', minWidth: 28, textAlign: 'right' }}>
                {minRisk}
              </span>
            </div>
            <div className="row" style={{ justifyContent: 'space-between', fontSize: 10.5, color: 'var(--fg-muted)', marginTop: 4 }}>
              <span>0</span><span>safe</span><span>50</span><span>critical</span><span>100</span>
            </div>
          </FilterGroup>
        </aside>

        {/* Main table area */}
        <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden', background: 'var(--bg-0)' }}>
          {/* Toolbar */}
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid var(--bd-1)',
            display: 'flex', alignItems: 'center', gap: 10,
            background: 'var(--bg-1)',
            flexShrink: 0,
          }}>
            <div className="input" style={{ width: 280 }}>
              <I.Search size={12} style={{ color: 'var(--fg-3)' }} />
              <input
                placeholder="filter rules… (try POL-026 or any/any)"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <span className="kbd">/</span>
            </div>

            <div className="row gap-2" style={{ flex: 1, flexWrap: 'wrap' }}>
              {activeFilters.map(f => (
                <span key={f.key} className="chip" style={{ gap: 6, cursor: 'pointer' }} onClick={f.clear}>
                  {f.label}
                  <I.Close size={10} />
                </span>
              ))}
              {activeFilters.length > 0 && (
                <button
                  className="sb-link" style={{ fontSize: 11, background: 'none', border: 0 }}
                  onClick={() => { setStat(new Set()); setVendor(new Set()); setFws(new Set()); setActions(new Set()); setMinRisk(0); setSearch(''); }}
                >clear all</button>
              )}
            </div>

            <span className="muted mono" style={{ fontSize: 11 }}>{filtered.length} row{filtered.length === 1 ? '' : 's'}</span>
          </div>

          {/* Table */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            <table className="t">
              <thead>
                <tr>
                  <SortHeader k="id">id</SortHeader>
                  <SortHeader k="name">rule</SortHeader>
                  <SortHeader k="firewallId">device</SortHeader>
                  <th>src</th>
                  <th>dst</th>
                  <SortHeader k="service">service</SortHeader>
                  <SortHeader k="action">act</SortHeader>
                  <SortHeader k="status">status</SortHeader>
                  <SortHeader k="priority" align="right">prio</SortHeader>
                  <SortHeader k="riskScore" align="right">risk</SortHeader>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr><td colSpan={10}>
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--fg-3)' }}>
                      <div style={{ fontSize: 13, marginBottom: 4 }}>no rules match the current filters</div>
                      <div style={{ fontSize: 11.5, color: 'var(--fg-muted)' }}>try clearing a filter or broadening the search</div>
                    </div>
                  </td></tr>
                )}
                {filtered.map(rule => {
                  const fw = LFPM.firewalls.find(f => f.id === rule.firewallId);
                  return (
                    <tr
                      key={rule.id}
                      className={selectedRuleId === rule.id ? 'selected' : ''}
                      onClick={() => openInspector({ kind:'rule', data: rule })}
                    >
                      <td>
                        <span className="sev-stripe" style={{ background: LFPM.fmt.riskColor(rule.riskScore) }} />
                        <span className="mono" style={{ color: 'var(--fg-2)' }}>{rule.id}</span>
                      </td>
                      <td className="truncate" style={{ maxWidth: 200 }}>
                        <div className="row gap-2">
                          <span className="mono strong">{rule.name}</span>
                          {!rule.enabled && <span className="chip" style={{ fontSize: 10 }}>off</span>}
                        </div>
                        <div className="mono dim" style={{ fontSize: 10.5, marginTop: 1 }}>
                          {rule.srcZone} → {rule.dstZone}
                        </div>
                      </td>
                      <td className="mono dim">{fw?.display || '—'}</td>
                      <td className="mono dim" style={{ fontSize: 11 }}>{rule.srcIp}</td>
                      <td className="mono dim truncate" style={{ fontSize: 11, maxWidth: 150 }}>{rule.dstIp}</td>
                      <td className="mono dim" style={{ fontSize: 11 }}>{rule.service}</td>
                      <td><span className={`verb ${rule.action}`}>{rule.action}</span></td>
                      <td>
                        <span className={`stat-text ${rule.status === 'clean' ? 'safe' : rule.status}`}
                              title={(rule.anomalyTypes || []).join(', ')}>
                          <span className="dot" />
                          {rule.status === 'clean' ? 'clean' : `${rule.status} · ${rule.anomalyCount}`}
                        </span>
                      </td>
                      <td className="num dim">{rule.priority}</td>
                      <td className="num" style={{ color: LFPM.fmt.riskColor(rule.riskScore), fontWeight: 600 }}>
                        {rule.riskScore}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Footer status */}
          <div style={{
            padding: '6px 16px', borderTop: '1px solid var(--bd-1)',
            background: 'var(--bg-1)', display: 'flex', alignItems: 'center', gap: 14,
            fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--f-mono)', flexShrink: 0,
          }}>
            <span><span style={{ color:'var(--fg-1)' }}>{filtered.length}</span> rows</span>
            <span><span style={{ color:'var(--sev-critical)' }}>{filtered.filter(r => r.riskScore >= 80).length}</span> critical</span>
            <span><span style={{ color:'var(--sev-high)' }}>{filtered.filter(r => r.riskScore >= 60 && r.riskScore < 80).length}</span> high</span>
            <span><span style={{ color:'var(--sev-safe)' }}>{filtered.filter(r => r.status === 'clean').length}</span> clean</span>
            <div className="tb-spacer" />
            <span>sort {sortKey} · {sortDir}</span>
            <span>j/k to navigate</span>
            <span>enter to inspect</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterGroup({ title, children }) {
  return (
    <div className="group">
      <div className="group-title">{title}</div>
      <div className="col" style={{ gap: 2 }}>
        {children}
      </div>
    </div>
  );
}
function FilterCheck({ on, onChange, count, children }) {
  return (
    <div className="filter-row" onClick={onChange}>
      <span className="label">
        <span className={`checkbox ${on ? 'on' : ''}`} />
        {children}
      </span>
      {count !== undefined && <span className="count">{count}</span>}
    </div>
  );
}

export { PolicyAudit };
