import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
import { updateAnomalyStatus } from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Inspector — right-side detail pane for rule / firewall / cve / host
 * Triggered from any table row or from the command palette
 * ───────────────────────────────────────────────────────────────── */

const { useEffect: useEffectI, useState: useStateI } = React;

/* Navigate via the app's hash router (app.jsx listens to hashchange). */
function navTo(page, params) {
  const qs = params && Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
  window.location.hash = `#${page}${qs}`;
}

function KV({ k, v, mono = false }) {
  return (
    <>
      <span className="k">{k}</span>
      <span className="v" style={{ fontFamily: mono ? 'var(--f-mono)' : 'inherit' }}>{v ?? '—'}</span>
    </>
  );
}

/* ── Anomaly finding (with analyst lifecycle) ───────────────────── */
const DETECTION_LABEL = {
  config_only: 'config', conditional: 'conditional', simulated: 'simulated',
  benchmark_simulated: 'simulated', cti: 'threat-intel', future_enhanced: 'future',
};

function SeverityChip({ sev }) {
  const s = (sev || 'low').toLowerCase();
  const cls = ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'low';
  return <span className={`chip ${cls}`}>{s}</span>;
}

function AnomalyCard({ anomaly }) {
  const [busy, setBusy] = React.useState(false);
  const [status, setStatus] = React.useState(anomaly.status || 'open');
  const mode = DETECTION_LABEL[anomaly.detection_mode] || anomaly.detection_mode || 'config';
  const resolved = status !== 'open';

  const act = async (next, needReason) => {
    let reason = null;
    if (needReason) {
      reason = window.prompt(`Reason to mark this finding "${next.replace(/_/g, ' ')}":`);
      if (reason == null || !reason.trim()) return; // cancelled
    }
    setBusy(true);
    try {
      await updateAnomalyStatus(anomaly.anomaly_id, next, reason);
      setStatus(next);
      window.toast(`Finding ${next.replace(/_/g, ' ')}`, {
        kind: 'ok', sub: `${(anomaly.anomaly_type || '').replace(/_/g, ' ')} · #${anomaly.anomaly_id}`,
      });
    } catch (e) {
      window.toast('Update failed', { kind: 'crit', sub: String(e.message || e) });
    } finally { setBusy(false); }
  };

  return (
    <div style={{
      background: 'var(--bg-2)', border: '1px solid var(--bd-1)', borderRadius: 5,
      padding: '9px 11px', opacity: resolved ? 0.65 : 1,
    }}>
      <div className="row" style={{ justifyContent: 'space-between', gap: 6, alignItems: 'center' }}>
        <span className="mono strong" style={{ fontSize: 12, color: 'var(--fg-0)' }}>
          {(anomaly.anomaly_type || '').replace(/_/g, ' ')}
        </span>
        <span className="row gap-2" style={{ alignItems: 'center' }}>
          <SeverityChip sev={anomaly.severity_level} />
          <span className="chip" style={{ fontSize: 10 }}>{mode}</span>
        </span>
      </div>
      {anomaly.description && (
        <p style={{ margin: '6px 0 0', fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.5 }}>{anomaly.description}</p>
      )}
      <div className="row gap-3" style={{ marginTop: 6, fontSize: 10.5, color: 'var(--fg-3)', flexWrap: 'wrap' }}>
        <span>#{anomaly.anomaly_id}</span>
        {anomaly.confidence != null && <span>confidence {Math.round(anomaly.confidence * 100)}%</span>}
        {resolved && <span className="stat-text safe"><span className="dot" />{status.replace(/_/g, ' ')}</span>}
      </div>
      {anomaly.recommendation && (
        <p style={{ margin: '6px 0 0', fontSize: 11, color: 'var(--fg-3)', lineHeight: 1.5 }}>
          <span style={{ color: 'var(--accent)' }}>→ </span>{anomaly.recommendation}
        </p>
      )}
      {anomaly.evidence && Object.keys(anomaly.evidence).length > 0 && (
        <details style={{ marginTop: 6 }}>
          <summary style={{ fontSize: 10.5, color: 'var(--fg-3)', cursor: 'pointer' }}>evidence</summary>
          <pre style={{
            margin: '4px 0 0', fontSize: 10.5, color: 'var(--fg-2)', background: 'var(--bg-1)',
            padding: '6px 8px', borderRadius: 4, overflow: 'auto', maxHeight: 160,
          }}>{JSON.stringify(anomaly.evidence, null, 2)}</pre>
        </details>
      )}
      {!resolved && (
        <div className="row gap-2" style={{ marginTop: 8, flexWrap: 'wrap' }}>
          <button className="btn" disabled={busy} onClick={() => act('resolved', false)}>resolve</button>
          <button className="btn ghost" disabled={busy} onClick={() => act('false_positive', true)}>false positive</button>
          <button className="btn ghost" disabled={busy} onClick={() => act('accepted_risk', true)}>accept risk</button>
        </div>
      )}
    </div>
  );
}

/* ── Rule detail ────────────────────────────────────────────────── */
function RuleDetail({ rule }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const fw = LFPM.firewalls.find(f => f.id === rule.firewallId);
  const relatedRule = rule.shadowedBy ? LFPM.policies.find(p => p.id === rule.shadowedBy) : null;
  const tier = rule.riskTier || LFPM.fmt.riskLabel(rule.riskScore);
  const factors = rule.riskFactors || {};
  const anomalies = rule.anomalies || [];

  return (
    <>
      <div className="inspector-section">
        <h4>identity</h4>
        <div className="kvgrid">
          <KV k="rule id"   v={rule.id}              mono />
          <KV k="name"      v={rule.name}            mono />
          <KV k="firewall"  v={fw?.display || '—'}   mono />
          <KV k="vendor"    v={fw?.vendor || '—'} />
          <KV k="priority"  v={`#${rule.priority}`}  mono />
          <KV k="action"    v={<span className={`verb ${rule.action}`}>{rule.action}</span>} />
          <KV k="enabled"   v={rule.enabled
            ? <span className="stat-text safe"><span className="dot" /> enabled</span>
            : <span className="stat-text dim"><span className="dot" /> disabled</span>} />
        </div>
      </div>

      <div className="inspector-section">
        <h4>match</h4>
        <div className="kvgrid">
          <KV k="src zone"  v={rule.srcZone} mono />
          <KV k="dst zone"  v={rule.dstZone} mono />
          <KV k="source"    v={rule.srcIp}  mono />
          <KV k="dest"      v={rule.dstIp}  mono />
          <KV k="service"   v={rule.service} mono />
        </div>
      </div>

      <div className="inspector-section">
        <h4>risk</h4>
        <div className="row gap-3" style={{ alignItems: 'center', marginBottom: 8 }}>
          <div style={{
            fontFamily: 'var(--f-mono)', fontSize: 24,
            color: LFPM.fmt.riskColor(rule.riskScore),
            fontWeight: 600, minWidth: 38,
          }}>{rule.riskScore}</div>
          <div className="flex1">
            <div style={{ height: 4, background: 'var(--bg-3)', borderRadius: 2, overflow:'hidden' }}>
              <div style={{
                width: `${rule.riskScore}%`,
                height: '100%',
                background: LFPM.fmt.riskColor(rule.riskScore),
              }} />
            </div>
            <div className="row" style={{ justifyContent: 'space-between', fontSize: 10.5, marginTop: 4, color: 'var(--fg-3)' }}>
              <span>0</span><span>{tier}</span><span>100</span>
            </div>
          </div>
          <span className={`chip ${rule.status === 'clean' ? 'safe' : rule.status}`}>{tier}</span>
        </div>
        {Object.keys(factors).length > 0 && (
          <div className="col" style={{ gap: 3, marginTop: 4 }}>
            {Object.entries(factors)
              .filter(([, v]) => typeof v === 'number')
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => (
                <div key={k} className="row" style={{ justifyContent: 'space-between', fontSize: 11 }}>
                  <span className="muted">{k.replace(/_/g, ' ')}</span>
                  <span className="mono" style={{ color: 'var(--fg-1)' }}>+{v}</span>
                </div>
              ))}
          </div>
        )}
      </div>

      {relatedRule && (
        <div className="inspector-section">
          <h4>related rule</h4>
          <div style={{
            background: 'var(--bg-2)', border: '1px solid var(--bd-1)',
            padding: '8px 10px', borderRadius: 4, fontSize: 12,
          }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span className="mono" style={{ color: 'var(--fg-0)' }}>{relatedRule.id}</span>
              <span className="muted mono">priority #{relatedRule.priority}</span>
            </div>
            <div style={{ color: 'var(--fg-2)', marginTop: 4 }}>{relatedRule.name}</div>
            <div className="row" style={{ marginTop: 6, fontSize: 11 }}>
              <span className="muted">match</span>
              <span className="mono">{relatedRule.srcZone} → {relatedRule.dstZone}</span>
              <span className="mono muted">{relatedRule.service}</span>
            </div>
          </div>
        </div>
      )}

      <div className="inspector-section">
        <h4><I.AlertTri size={11} /> findings ({anomalies.length})</h4>
        {anomalies.length === 0
          ? <div className="muted" style={{ fontSize: 12 }}>
              No anomalies — rule conforms to least-privilege and is not shadowed.
            </div>
          : <div className="col" style={{ gap: 8 }}>
              {anomalies.map(a => <AnomalyCard key={a.anomaly_id} anomaly={a} />)}
            </div>}
      </div>

      <div className="inspector-section">
        <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          <button
            className="btn"
            onClick={() => navTo('audit', { firewall: rule.firewallId })}
          >view in firewall</button>
          <button
            className="btn ghost"
            onClick={() => {
              navigator.clipboard?.writeText?.(rule.id)
                .then(() => window.toast(`Copied ${rule.id}`, { kind:'ok' }))
                .catch(() => window.toast(`Couldn't access clipboard`, { kind:'err' }));
            }}
          >copy id</button>
        </div>
      </div>
    </>
  );
}

/* ── Firewall detail ─────────────────────────────────────────────── */
function FirewallDetail({ fw }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const rules = LFPM.policies.filter(p => p.firewallId === fw.id);
  const cves = LFPM.threats.filter(t => t.firewallIds.includes(fw.id));
  const cleanRules = rules.filter(r => r.status === 'clean').length;
  const anomalies = rules.length - cleanRules;
  return (
    <>
      <div className="inspector-section">
        <h4>identity</h4>
        <div className="kvgrid">
          <KV k="hostname"  v={fw.name} mono />
          <KV k="model"     v={fw.model} mono />
          <KV k="vendor"    v={fw.vendor} />
          <KV k="firmware"  v={fw.firmware} mono />
          <KV k="ip"        v={fw.ip} mono />
          <KV k="serial"    v={fw.serial} mono />
          <KV k="zone"      v={fw.zone} mono />
          <KV k="location"  v={fw.location} />
        </div>
      </div>

      <div className="inspector-section">
        <h4>health</h4>
        <div className="kvgrid">
          <KV k="status" v={
            <span className={`stat-text ${fw.status === 'online' ? 'safe' : 'high'}`}>
              <span className="dot" /> {fw.status}
            </span>
          } />
          <KV k="uptime"      v={fw.uptime} mono />
          <KV k="throughput"  v={fw.throughput} mono />
          <KV k="last sync"   v="14:32:08 UTC · 4m ago" mono />
        </div>
      </div>

      <div className="inspector-section">
        <h4>ruleset</h4>
        <div className="kvgrid">
          <KV k="rules"      v={rules.length} mono />
          <KV k="anomalies"  v={
            <span style={{ color: anomalies ? 'var(--sev-high)' : 'var(--fg-1)' }}>{anomalies}</span>
          } mono />
          <KV k="clean"      v={<span style={{ color: 'var(--sev-safe)' }}>{cleanRules}</span>} mono />
          <KV k="risk score" v={
            <span style={{ color: LFPM.fmt.riskColor(fw.riskScore), fontWeight: 600 }}>{fw.riskScore}</span>
          } mono />
        </div>
      </div>

      <div className="inspector-section">
        <h4>open cves ({cves.length})</h4>
        {cves.length === 0
          ? <div className="muted" style={{ fontSize: 12 }}>no advisories link to this device.</div>
          : (
            <div className="col" style={{ gap: 6 }}>
              {cves.slice(0, 5).map(c => (
                <div key={c.id} style={{
                  background:'var(--bg-2)', border:'1px solid var(--bd-1)',
                  padding:'6px 9px', borderRadius:4,
                }}>
                  <div className="row" style={{ justifyContent:'space-between', gap: 6 }}>
                    <span className="mono" style={{ fontSize: 11.5, color: 'var(--fg-0)' }}>{c.id}</span>
                    <span className={`chip ${c.severity}`}>{c.severity} · {c.cvss}</span>
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--fg-2)', marginTop: 3 }}>{c.title}</div>
                </div>
              ))}
            </div>
          )}
      </div>
    </>
  );
}

/* ── CVE detail ─────────────────────────────────────────────────── */
function CveDetail({ cve }) {
  const { data: LFPM } = useLFPM();
  const affected = cve.firewallIds.map(id => LFPM.firewalls.find(f => f.id === id)).filter(Boolean);
  return (
    <>
      <div className="inspector-section">
        <h4>summary</h4>
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--fg-1)', lineHeight: 1.55 }}>{cve.description}</p>
      </div>
      <div className="inspector-section">
        <h4>metadata</h4>
        <div className="kvgrid">
          <KV k="severity"  v={<span className={`chip ${cve.severity}`}>{cve.severity}</span>} />
          <KV k="cvss"      v={cve.cvss.toFixed(1)} mono />
          <KV k="exploit"   v={
            <span className={`stat-text ${cve.exploit === 'active' || cve.exploit === 'wild' ? 'critical' : cve.exploit === 'poc' ? 'high' : 'dim'}`}>
              <span className="dot" /> {LFPM.fmt.exploitLabel(cve.exploit)}
            </span>
          } />
          <KV k="kev"       v={cve.kev ? <span className="chip critical">CISA KEV</span> : <span className="muted">not listed</span>} />
          <KV k="published" v={cve.published} mono />
          <KV k="patched"   v={cve.patched} mono />
        </div>
      </div>
      <div className="inspector-section">
        <h4>affected firmware</h4>
        <div className="row" style={{ flexWrap:'wrap', gap: 6 }}>
          {cve.firmware.map(f => <span key={f} className="chip">{f}</span>)}
        </div>
      </div>
      <div className="inspector-section">
        <h4>impacted devices ({affected.length})</h4>
        <div className="col" style={{ gap: 4 }}>
          {affected.map(fw => (
            <div key={fw.id} className="row" style={{
              padding:'6px 9px', background:'var(--bg-2)', border:'1px solid var(--bd-1)', borderRadius:4,
              justifyContent:'space-between',
            }}>
              <span className="mono" style={{ fontSize: 12, color: 'var(--fg-0)' }}>{fw.display}</span>
              <span className="mono muted" style={{ fontSize: 11.5 }}>{fw.firmware}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ── Host detail ────────────────────────────────────────────────── */
function HostDetail({ host }) {
  const { data: LFPM } = useLFPM();
  const zone = LFPM.zones.find(z => z.id === host.zoneId);
  const fw = zone ? LFPM.firewalls.find(f => f.id === zone.fwId) : null;
  return (
    <>
      <div className="inspector-section">
        <h4>identity</h4>
        <div className="kvgrid">
          <KV k="hostname"  v={host.name} mono />
          <KV k="kind"      v={host.kind} />
          <KV k="ip"        v={host.ip} mono />
          <KV k="os"        v={host.os} />
          <KV k="zone"      v={zone?.name} mono />
          <KV k="firewall"  v={fw?.display} mono />
        </div>
      </div>
      <div className="inspector-section">
        <h4>recent activity</h4>
        <div className="col" style={{ gap: 4, fontSize: 12 }}>
          {[
            { t:'14:32', txt:'outbound · tcp/443 → 52.114.7.10 · 11.2 MB' },
            { t:'14:30', txt:'authentication · openssh · success' },
            { t:'14:28', txt:'inbound  · tcp/22  ← 10.10.0.50  ·  78 KB' },
            { t:'14:25', txt:'rule hit · POL-008 · 1 flow' },
          ].map((r,i) => (
            <div key={i} className="row" style={{ gap: 8 }}>
              <span className="mono" style={{ width: 36, color: 'var(--fg-muted)' }}>{r.t}</span>
              <span style={{ color: 'var(--fg-2)' }}>{r.txt}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ── Zone detail ────────────────────────────────────────────────── */
function ZoneDetail({ zone }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const fwId = zone.fwId;
  const fw = LFPM.firewalls.find(f => f.id === fwId);
  const zoneName = zone.name.toLowerCase();
  const related = LFPM.policies.filter(p =>
    p.firewallId === fwId &&
    (p.srcZone.toLowerCase() === zoneName || p.dstZone.toLowerCase() === zoneName)
  );
  const anomalies = related.filter(r => r.status !== 'clean');
  const maxRisk = related.length ? Math.max(...related.map(r => r.riskScore)) : 0;
  const assets = LFPM.assets.filter(a => a.zoneId === zone.id);

  const advice = maxRisk >= 80
    ? `Reduce ${anomalies.length} anomalous rule${anomalies.length === 1 ? '' : 's'} reaching this zone. Highest risk: ${maxRisk}.`
    : anomalies.length
      ? `Review ${anomalies.length} anomalous rule${anomalies.length === 1 ? '' : 's'} that traverse this zone.`
      : `No anomalies. Continue monitoring traffic at this boundary.`;

  return (
    <>
      <div className="inspector-section">
        <h4>identity</h4>
        <div className="kvgrid">
          <KV k="zone"     v={zone.name} mono />
          <KV k="type"     v={zone.type} mono />
          <KV k="subnet"   v={zone.subnet} mono />
          <KV k="firewall" v={fw?.display} mono />
          <KV k="vendor"   v={fw?.vendor} />
        </div>
      </div>

      <div className="inspector-section">
        <h4>posture</h4>
        <div className="kvgrid">
          <KV k="assets"     v={assets.length} mono />
          <KV k="rules"      v={related.length} mono />
          <KV k="anomalies"  v={
            <span style={{ color: anomalies.length ? 'var(--sev-high)' : 'var(--fg-1)' }}>{anomalies.length}</span>
          } mono />
          <KV k="max risk"   v={
            <span style={{ color: LFPM.fmt.riskColor(maxRisk), fontWeight: 600 }}>{maxRisk}</span>
          } mono />
        </div>
      </div>

      {assets.length > 0 && (
        <div className="inspector-section">
          <h4>monitored assets ({assets.length})</h4>
          <div className="col" style={{ gap: 6 }}>
            {assets.map(a => (
              <div key={a.id} className="row" style={{
                padding:'6px 9px', background:'var(--bg-2)', border:'1px solid var(--bd-1)', borderRadius:4,
                justifyContent:'space-between', gap: 8,
              }}>
                <span className="mono" style={{ color:'var(--fg-0)' }}>{a.name}</span>
                <span className="mono muted" style={{ fontSize: 11.5 }}>{a.ip}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {related.length > 0 && (
        <div className="inspector-section">
          <h4>rules traversing this zone ({related.length})</h4>
          <div className="col" style={{ gap: 4, maxHeight: 220, overflow:'auto' }}>
            {[...related].sort((a,b) => b.riskScore - a.riskScore).slice(0, 8).map(p => (
              <div key={p.id} style={{
                padding:'6px 9px', background:'var(--bg-2)', border:'1px solid var(--bd-1)', borderRadius:4,
              }}>
                <div className="row" style={{ justifyContent:'space-between', gap: 6 }}>
                  <span className="mono" style={{ color:'var(--fg-0)' }}>{p.id}</span>
                  <span className={`stat-text ${p.status === 'clean' ? 'safe' : p.status}`}>
                    <span className="dot" />{p.status}
                  </span>
                </div>
                <div className="row" style={{ marginTop: 4, fontSize: 11 }}>
                  <span className="mono" style={{ color:'var(--fg-2)' }}>{p.name}</span>
                  <span style={{ marginLeft:'auto', color: LFPM.fmt.riskColor(p.riskScore), fontWeight: 600, fontFamily:'var(--f-mono)' }}>
                    {p.riskScore}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="inspector-section">
        <h4><I.Code size={11} /> analyzer notes</h4>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.55 }}>{advice}</p>
        <div className="row" style={{ marginTop: 10, gap: 6 }}>
          <button
            className="btn"
            onClick={() => navTo('audit', { firewall: fwId, q: zone.name })}
          >view in audit</button>
          <button
            className="btn ghost"
            onClick={() => {
              navigator.clipboard?.writeText?.(zone.subnet)
                .then(() => window.toast(`Copied ${zone.subnet}`, { kind:'ok' }))
                .catch(() => {});
            }}
          >copy subnet</button>
        </div>
      </div>
    </>
  );
}

/* ── External / threat node detail ──────────────────────────────── */
function ExternalDetail({ node }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const targetMap = {
    'ext-internet':  ['fw-001','fw-002','fw-003','fw-004','fw-005'],
    'ext-susp':      ['fw-001','fw-002'],
    'ext-c2':        ['fw-004','fw-001'],
    'ext-tor':       ['fw-001'],
  };
  const affected = (targetMap[node.id] || [])
    .map(id => LFPM.firewalls.find(f => f.id === id))
    .filter(Boolean);
  const isMalicious = node.threat === 'critical' || node.threat === 'high';
  const recommendation = node.kind === 'c2'
    ? `Block ${node.ip} at all perimeter firewalls. Hunt for endpoints beaconing to this IP.`
    : node.kind === 'suspicious'
      ? `Quarantine traffic from ${node.ip}. Capture flow logs at impacted firewalls.`
      : node.kind === 'threat'
        ? `Confirm Tor egress policy. Review allow rules whose src or dst overlaps ${node.ip}.`
        : `Reference perimeter. No action required.`;

  return (
    <>
      <div className="inspector-section">
        <h4>identity</h4>
        <div className="kvgrid">
          <KV k="name"   v={node.name} mono />
          <KV k="kind"   v={node.kind} />
          <KV k="ip"     v={node.ip} mono />
          <KV k="threat" v={
            node.threat === 'none'
              ? <span className="muted">reference</span>
              : <span className={`stat-text ${node.threat}`}><span className="dot" />{node.threat}</span>
          } />
        </div>
      </div>

      {node.description && (
        <div className="inspector-section">
          <h4>description</h4>
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--fg-1)', lineHeight: 1.55 }}>{node.description}</p>
        </div>
      )}

      <div className="inspector-section">
        <h4>reachable firewalls ({affected.length})</h4>
        <div className="col" style={{ gap: 4 }}>
          {affected.map(fw => (
            <div key={fw.id} className="row" style={{
              padding:'6px 9px', background:'var(--bg-2)', border:'1px solid var(--bd-1)', borderRadius:4,
              justifyContent:'space-between',
            }}>
              <span className="mono" style={{ color:'var(--fg-0)' }}>{fw.display}</span>
              <span className="mono muted" style={{ fontSize: 11.5 }}>{fw.ip}</span>
            </div>
          ))}
        </div>
      </div>

      {isMalicious && (
        <div className="inspector-section">
          <h4><I.AlertTri size={11} /> recommendation</h4>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.55 }}>{recommendation}</p>
          <div className="row" style={{ marginTop: 10, gap: 6 }}>
            <button
              className="btn primary"
              onClick={() => {
                navTo('audit', { q: node.ip });
                window.toast(`Filtering audit by ${node.ip}`, {
                  kind:'ok', sub:`source/dest match · ${affected.length} firewalls in scope`,
                });
              }}
            >block at perimeter</button>
            <button
              className="btn"
              onClick={() => {
                navTo('threats', { q: node.ip });
                window.toast('Threat hunt', { kind:'info', sub:`searching advisories for ${node.ip}` });
              }}
            >hunt traffic</button>
          </div>
        </div>
      )}
    </>
  );
}

/* ── Threat path (edge) detail ──────────────────────────────────── */
function PathDetail({ edge, ext, fw }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const isThreat = edge.kind === 'threat';
  const severity = edge.severity || 'low';
  const relevantRules = LFPM.policies.filter(p =>
    p.firewallId === fw.id &&
    (p.srcZone.toUpperCase() === 'UNTRUST' || p.srcZone.toUpperCase() === 'WAN' || p.srcIp === 'any')
  );
  const exposedRules = relevantRules.filter(p => p.action === 'allow' && p.status !== 'clean');

  const recommendation = severity === 'critical'
    ? `Immediate review required. ${exposedRules.length} permissive ingress rule${exposedRules.length === 1 ? '' : 's'} could expose ${fw.display} to this source.`
    : severity === 'high'
      ? `Review ingress rules at ${fw.display}. Tighten any any/any to source ${ext?.ip || ''}.`
      : `Informational path. No action required.`;

  return (
    <>
      <div className="inspector-section">
        <h4>path</h4>
        <div className="kvgrid">
          <KV k="source"   v={ext?.name || edge.sourceId} mono />
          <KV k="target"   v={fw?.display} mono />
          <KV k="kind"     v={edge.kind} />
          <KV k="severity" v={
            <span className={`stat-text ${severity === 'critical' || severity === 'high' || severity === 'medium' ? severity : 'safe'}`}>
              <span className="dot" />{severity}
            </span>
          } />
        </div>
      </div>

      {ext && (
        <div className="inspector-section">
          <h4>about the source</h4>
          <div className="kvgrid">
            <KV k="ip"     v={ext.ip} mono />
            <KV k="kind"   v={ext.kind} />
          </div>
          {ext.description && (
            <p style={{ margin:'8px 0 0', fontSize: 12, color:'var(--fg-2)', lineHeight: 1.5 }}>
              {ext.description}
            </p>
          )}
        </div>
      )}

      {fw && (
        <div className="inspector-section">
          <h4>at the target</h4>
          <div className="kvgrid">
            <KV k="firewall"     v={fw.display} mono />
            <KV k="firmware"     v={fw.firmware} mono />
            <KV k="risk"         v={
              <span style={{ color: LFPM.fmt.riskColor(fw.riskScore), fontWeight: 600 }}>{fw.riskScore}</span>
            } mono />
            <KV k="ingress rules" v={relevantRules.length} mono />
          </div>
        </div>
      )}

      {isThreat && (
        <div className="inspector-section">
          <h4><I.AlertTri size={11} /> analyzer notes</h4>
          <p style={{ margin: 0, fontSize: 12, color:'var(--fg-2)', lineHeight: 1.55 }}>{recommendation}</p>
          <div className="row" style={{ marginTop: 10, gap: 6 }}>
            <button
              className="btn primary"
              onClick={() => {
                const rid = exposedRules[0]?.id || relevantRules[0]?.id;
                if (rid) navTo('audit', { rule: rid });
                window.toast('Path mitigation', {
                  kind:'ok', sub: rid ? `opened ${rid} in audit` : 'no ingress rules to review',
                });
              }}
            >mitigate path</button>
            <button
              className="btn"
              onClick={() => navTo('audit', { firewall: fw.id, filter: 'permissive' })}
            >review rules</button>
          </div>
        </div>
      )}
    </>
  );
}

/* ── Main Inspector wrapper ─────────────────────────────────────── */
function Inspector({ open, onClose }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  useEffectI(() => {
    if (!open) return;
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [open, onClose]);

  const meta = (() => {
    if (!open) return { crumb:'', title:'', sub:[] };
    if (open.kind === 'rule')     return { crumb:'rule', title: open.data.name, sub: [open.data.id, LFPM.firewalls.find(f => f.id === open.data.firewallId)?.display] };
    if (open.kind === 'firewall') return { crumb:'firewall', title: open.data.display, sub: [open.data.ip, open.data.firmware] };
    if (open.kind === 'cve')      return { crumb:'advisory', title: open.data.id, sub: [open.data.title] };
    if (open.kind === 'host')     return { crumb:'host', title: open.data.name, sub: [open.data.ip, open.data.os] };
    if (open.kind === 'zone')     return { crumb:'zone', title: open.data.name, sub: [open.data.subnet, open.data.fwDisplay] };
    if (open.kind === 'external') return { crumb:'threat indicator', title: open.data.name, sub: [open.data.ip, open.data.kind] };
    if (open.kind === 'path')     return {
      crumb:'threat path',
      title: `${open.data.ext?.name || '—'} → ${open.data.fw?.display || '—'}`,
      sub: [open.data.edge?.severity || '—', open.data.edge?.kind || '—'],
    };
    return { crumb:'', title:'', sub:[] };
  })();

  return (
    <aside className={`inspector ${open ? 'open' : ''}`}>
      <div className="inspector-head">
        <div className="meta">
          <div className="crumb">{meta.crumb}</div>
          <div className="title">{meta.title}</div>
          <div className="sub">{meta.sub.filter(Boolean).map((s,i) => <span key={i}>{s}</span>)}</div>
        </div>
        <button className="tb-iconbtn" onClick={onClose} title="Close (esc)">
          <I.Close size={15} />
        </button>
      </div>
      <div className="inspector-body">
        {open?.kind === 'rule'     && <RuleDetail rule={open.data} />}
        {open?.kind === 'firewall' && <FirewallDetail fw={open.data} />}
        {open?.kind === 'cve'      && <CveDetail cve={open.data} />}
        {open?.kind === 'host'     && <HostDetail host={open.data} />}
        {open?.kind === 'zone'     && <ZoneDetail zone={open.data} />}
        {open?.kind === 'external' && <ExternalDetail node={open.data} />}
        {open?.kind === 'path'     && <PathDetail edge={open.data.edge} ext={open.data.ext} fw={open.data.fw} />}
      </div>
    </aside>
  );
}
export { Inspector };
