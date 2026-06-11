import React from "react";
import { Icons } from "./icons";
import { LFPM } from "./data";
import { triggerRulesSync } from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Settings — admin console (read-only demo)
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateS } = React;

const SETTINGS_TABS = [
  { id: 'connectors',    label: 'Connectors',     count: 5 },
  { id: 'schedules',     label: 'Analyzer schedule' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'access',        label: 'Access & roles' },
  { id: 'api',           label: 'API & secrets' },
  { id: 'audit-log',     label: 'Audit log' },
  { id: 'about',         label: 'About' },
];

function Settings({ openInspector, refreshData }) {
  const I = window.Icons;
  const [tab, setTab] = useStateS('connectors');

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Platform configuration · viewing as <span className="mono" style={{ color: 'var(--fg-1)' }}>hamza@lumina-fpm.local</span> · role <span className="mono" style={{ color: 'var(--fg-1)' }}>admin</span></p>
        </div>
        <div className="row gap-2" style={{ marginLeft: 'auto' }}>
          <span className="chip">read-only demo</span>
        </div>
      </div>

      <div style={{ flex: 1, display:'grid', gridTemplateColumns:'220px 1fr', minHeight: 0, overflow:'hidden' }}>
        {/* Left sub-nav */}
        <aside className="filter-side">
          <div style={{ padding: '12px 6px', borderBottom: '1px solid var(--bd-1)' }}>
            {SETTINGS_TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                style={{
                  width:'100%',
                  padding:'7px 12px',
                  display:'flex', justifyContent:'space-between', alignItems:'center',
                  background: tab === t.id ? 'var(--bg-3)' : 'transparent',
                  color: tab === t.id ? 'var(--fg-0)' : 'var(--fg-2)',
                  fontWeight: tab === t.id ? 500 : 400,
                  borderRadius: 4,
                  fontSize: 12,
                  marginBottom: 2,
                  position: 'relative',
                }}
              >
                {tab === t.id && <span style={{ position:'absolute', left:-6, top:8, bottom:8, width:2, background:'var(--accent)', borderRadius:1 }} />}
                <span>{t.label}</span>
                {t.count != null && <span className="muted mono" style={{ fontSize: 10.5 }}>{t.count}</span>}
              </button>
            ))}
          </div>
          <div style={{ padding: 14, fontSize: 11, color: 'var(--fg-3)', lineHeight: 1.6 }}>
            All config changes are written to <span className="mono" style={{ color:'var(--fg-1)' }}>lumina.yaml</span> on the master node and require analyzer restart.
          </div>
        </aside>

        {/* Right content */}
        <div style={{ overflow:'auto', minHeight: 0, padding: '16px 20px', background: 'var(--bg-0)' }}>
          {tab === 'connectors'    && <Connectors openInspector={openInspector} refreshData={refreshData} />}
          {tab === 'schedules'     && <Schedules />}
          {tab === 'notifications' && <Notifications />}
          {tab === 'access'        && <AccessRoles />}
          {tab === 'api'           && <ApiSecrets />}
          {tab === 'audit-log'     && <AuditLog />}
          {tab === 'about'         && <About />}
        </div>
      </div>
    </div>
  );
}

/* ── Connectors ─────────────────────────────────────────────── */
function Connectors({ openInspector, refreshData }) {
  const I = window.Icons;
  return (
    <>
      <SectionHead title="Connectors" desc="Firewall integrations and external threat feeds. Sync runs every 5 minutes." />
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div className="panel-title"><I.Shield size={12} /> firewall fleet</div>
          <div className="panel-meta">{LFPM.firewalls.length} connected</div>
        </div>
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>device</th>
              <th>vendor</th>
              <th>endpoint</th>
              <th>auth</th>
              <th>status</th>
              <th>last sync</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {LFPM.firewalls.map(fw => (
              <tr key={fw.id} onClick={() => openInspector({ kind:'firewall', data: fw })}>
                <td>
                  <span className="mono strong">{fw.display}</span>
                  <div className="mono dim" style={{ fontSize: 10.5 }}>{fw.serial}</div>
                </td>
                <td>{fw.vendor.includes('Palo') ? 'palo alto' : 'fortinet'}</td>
                <td className="mono dim">https://{fw.ip}/api/v1</td>
                <td className="mono dim">api-key · rotated 3d ago</td>
                <td>
                  <span className={`stat-text ${fw.status === 'online' ? 'safe' : 'high'}`}>
                    <span className="dot" />{fw.status === 'online' ? 'connected' : 'degraded'}
                  </span>
                </td>
                <td className="mono dim">{LFPM.fmt.rel(fw.lastSync)}</td>
                <td style={{ textAlign: 'right', paddingRight: 14 }}>
                  <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }}>
                    <button
                      className="btn ghost"
                      onClick={async (e) => {
                        e.stopPropagation();
                        window.toast(`Syncing ${fw.display} ruleset...`, { kind:'info' });
                        try {
                          const result = await triggerRulesSync(fw.id);
                          if (typeof refreshData === 'function') await refreshData();
                          window.toast('Sync complete', { kind:'ok', sub: result.message || `Successfully synced rules` });
                        } catch (err) {
                          window.toast('Sync failed', { kind:'crit', sub: err.message || String(err) });
                        }
                      }}
                      title="Sync ruleset from firewall device"
                      style={{ padding: '4px 8px', minHeight: 0 }}
                    ><I.Refresh size={12} /></button>
                    <button
                      className="btn ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        openInspector({ kind:'firewall', data: fw });
                      }}
                      title="View connector details"
                      style={{ padding: '4px 8px', minHeight: 0 }}
                    ><I.Settings size={12} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: 10, borderTop:'1px solid var(--bd-1)', display:'flex', gap: 8, alignItems: 'center' }}>
          <span className="muted" style={{ fontSize: 11.5 }}>New connectors onboard via CLI · UI in Pro roadmap</span>
          <button
            style={{ marginLeft: 'auto' }}
            className="btn ghost"
            onClick={async () => {
              window.toast('Triggering sync across fleet...', { kind:'info' });
              try {
                await Promise.all(LFPM.firewalls.map(fw => triggerRulesSync(fw.id)));
                if (typeof refreshData === 'function') await refreshData();
                window.toast('Fleet sync complete', { kind:'ok', sub:'All connected devices synchronized successfully' });
              } catch (err) {
                window.toast('Fleet sync failed', { kind:'crit', sub: err.message || String(err) });
              }
            }}
          ><I.Refresh size={13} /> sync all</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div className="panel-title"><I.Globe size={12} /> threat intel feeds</div>
        </div>
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>feed</th>
              <th>endpoint</th>
              <th>cadence</th>
              <th>status</th>
              <th>last pull</th>
            </tr>
          </thead>
          <tbody>
            {[
              { n: 'nvd',                u: 'https://services.nvd.nist.gov/rest/json/cves/2.0', c: '4h', s: 'connected', t: '12m ago' },
              { n: 'cisa kev',           u: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', c: '1h', s: 'connected', t: '4m ago' },
              { n: 'palo alto psirt',    u: 'https://security.paloaltonetworks.com/api/v1/advisories', c: '1h', s: 'connected', t: '14m ago' },
              { n: 'fortinet psirt',     u: 'https://www.fortiguard.com/psirt/api/v1', c: '1h', s: 'connected', t: '4m ago' },
              { n: 'mitre att&ck',       u: 'https://attack.mitre.org/api/v1/techniques', c: '24h', s: 'connected', t: '6h ago' },
            ].map((f, i) => (
              <tr key={i}>
                <td style={{ paddingLeft: 14 }}><span className="mono strong">{f.n}</span></td>
                <td className="mono dim truncate" style={{ maxWidth: 340 }}>{f.u}</td>
                <td className="mono dim">{f.c}</td>
                <td><span className="stat-text safe"><span className="dot" />{f.s}</span></td>
                <td className="mono dim">{f.t}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ── Schedules ────────────────────────────────────────────────── */
function Schedules() {
  const I = window.Icons;
  const rows = [
    { name: 'ruleset analyzer',         schedule: '*/15 * * * *', desc: 'shadow / redundant / permissive analysis · runs against each firewall', last:'14:24 UTC', ok: true },
    { name: 'cross-vendor reconciler',  schedule: '0 */6 * * *',  desc: 'finds transitive policy conflicts spanning multiple firewalls',          last:'12:00 UTC', ok: true },
    { name: 'topology discovery',       schedule: '*/30 * * * *', desc: 'pulls live zone / asset / interface mapping',                            last:'14:30 UTC', ok: true },
    { name: 'cve correlation',          schedule: '0 */4 * * *',  desc: 'matches deployed firmware versions against advisory feed',               last:'12:00 UTC', ok: true },
    { name: 'rule-hit aggregation',     schedule: '*/5 * * * *',  desc: 'streams hit counters into the time-series store',                        last:'14:31 UTC', ok: true },
    { name: 'weekly report',            schedule: '0 6 * * MON',  desc: 'pdf digest emailed to soc-ops@acme.local',                               last:'mon 06:00', ok: true },
  ];
  return (
    <>
      <SectionHead title="Analyzer schedule" desc="Cron jobs that drive ruleset analysis, threat correlation, and topology discovery." />
      <div className="panel">
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>job</th>
              <th>cron</th>
              <th>description</th>
              <th>last run</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td style={{ paddingLeft: 14 }}>
                  <span className="mono strong">{r.name}</span>
                </td>
                <td className="mono dim">{r.schedule}</td>
                <td className="dim" style={{ fontSize: 11.5 }}>{r.desc}</td>
                <td className="mono dim">{r.last}</td>
                <td><span className="stat-text safe"><span className="dot" />ok</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ── Notifications ────────────────────────────────────────────── */
const NOTIF_LS_KEY = 'lumina_notif_rules';
const NOTIF_DEFAULTS = [
  { id: 'crit',      trigger: 'severity ≥ critical',         channel: 'pagerduty · soc-on-call',      enabled: true },
  { id: 'kev',       trigger: 'cisa kev match',              channel: 'slack · #soc-alerts',          enabled: true },
  { id: 'shadowed',  trigger: 'new shadowed rule detected',  channel: 'jira · backlog SOC-INF',       enabled: true },
  { id: 'conflict',  trigger: 'cross-vendor conflict opened', channel: 'email · soc-ops@lumina.local', enabled: true },
  { id: 'offline',   trigger: 'firewall offline > 5m',       channel: 'pagerduty · network-on-call',  enabled: true },
  { id: 'jobfail',   trigger: 'analyzer job failed',         channel: 'slack · #platform',            enabled: true },
  { id: 'redundant', trigger: 'redundant rule found',        channel: 'jira · backlog (low)',         enabled: false },
  { id: 'digest',    trigger: 'weekly digest',               channel: 'email · soc-ops@lumina.local', enabled: true },
];

function loadNotifRules() {
  try {
    const raw = localStorage.getItem(NOTIF_LS_KEY);
    if (!raw) return NOTIF_DEFAULTS;
    const saved = JSON.parse(raw);
    return NOTIF_DEFAULTS.map(d => ({
      ...d,
      enabled: saved[d.id] != null ? !!saved[d.id] : d.enabled,
    }));
  } catch {
    return NOTIF_DEFAULTS;
  }
}

function Notifications() {
  const I = window.Icons;
  const [rules, setRules] = useStateS(loadNotifRules);
  const toggleRule = (id) => {
    setRules(prev => {
      const next = prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r);
      try {
        const map = Object.fromEntries(next.map(r => [r.id, r.enabled]));
        localStorage.setItem(NOTIF_LS_KEY, JSON.stringify(map));
      } catch {}
      const hit = next.find(r => r.id === id);
      window.toast(hit?.enabled ? 'Notification enabled' : 'Notification paused', {
        kind: 'ok', sub: hit?.trigger || id,
      });
      return next;
    });
  };
  return (
    <>
      <SectionHead title="Notifications" desc="Route security findings to email, Slack, PagerDuty, and ticketing." />
      <div className="panel">
        <div className="panel-head">
          <div className="panel-title"><I.Bell size={12} /> routing rules</div>
        </div>
        <div className="col" style={{ padding: 0 }}>
          {rules.map((n) => (
            <div
              key={n.id}
              style={{
                padding: '10px 14px', display: 'grid',
                gridTemplateColumns: '2fr 2fr 80px',
                borderBottom: '1px solid var(--bd-1)', alignItems: 'center', gap: 14,
                cursor: 'pointer',
              }}
              onClick={() => toggleRule(n.id)}
              title="Click to toggle"
            >
              <span style={{ fontSize: 12, color: 'var(--fg-1)' }}>{n.trigger}</span>
              <span className="mono dim" style={{ fontSize: 11.5 }}>{n.channel}</span>
              <span className={`stat-text ${n.enabled ? 'safe' : 'dim'}`} style={{ justifySelf: 'end' }}>
                <span className="dot" />{n.enabled ? 'enabled' : 'paused'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ── Access & roles ───────────────────────────────────────────── */
function AccessRoles() {
  const I = window.Icons;
  return (
    <>
      <SectionHead title="Access & roles" desc="SSO via Okta · MFA enforced · least-privilege roles." />
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div className="panel-title"><I.Users size={12} /> members</div>
          <div className="panel-meta">{LFPM.users.length} users</div>
        </div>
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>user</th>
              <th>email</th>
              <th>role</th>
              <th>department</th>
              <th>mfa</th>
              <th>last login</th>
            </tr>
          </thead>
          <tbody>
            {LFPM.users.map(u => (
              <tr key={u.id}>
                <td style={{ paddingLeft: 14 }}>
                  <div className="row gap-2">
                    <div className="tb-avatar" style={{ width: 22, height: 22 }}>{u.avatar}</div>
                    <span style={{ color:'var(--fg-1)' }}>{u.name}</span>
                  </div>
                </td>
                <td className="mono dim">{u.email}</td>
                <td><span className="chip">{u.role}</span></td>
                <td className="dim">{u.dept}</td>
                <td><span className="stat-text safe"><span className="dot" />webauthn</span></td>
                <td className="mono dim">14:28 UTC</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <div className="panel-head">
          <div className="panel-title"><I.Lock size={12} /> session policy</div>
        </div>
        <div className="col" style={{ padding: 0 }}>
          {[
            { k: 'sso provider',           v: 'okta · oidc' },
            { k: 'mfa requirement',        v: 'webauthn (preferred) · totp fallback' },
            { k: 'session timeout',        v: '30 minutes of inactivity' },
            { k: 'idle re-auth',           v: 'on critical actions (delete, role change)' },
            { k: 'ip allowlist',           v: '10.0.0.0/8, 192.168.0.0/16, vpn-egress.acme.local' },
            { k: 'audit logging',          v: 'enabled · retained 2 years' },
          ].map((r, i) => (
            <div key={i} style={{
              display: 'grid', gridTemplateColumns: '180px 1fr',
              padding: '8px 14px', borderBottom: '1px solid var(--bd-1)',
              fontSize: 12,
            }}>
              <span className="muted">{r.k}</span>
              <span className="mono" style={{ color:'var(--fg-1)' }}>{r.v}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ── API & secrets ────────────────────────────────────────────── */
function ApiSecrets() {
  const I = window.Icons;
  return (
    <>
      <SectionHead title="API & secrets" desc="Personal & service tokens for the Lumina FPM REST API." />
      <div className="panel">
        <div className="panel-head">
          <div className="panel-title"><I.Key size={12} /> active tokens</div>
        </div>
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>name</th>
              <th>prefix</th>
              <th>scope</th>
              <th>owner</th>
              <th>created</th>
              <th>last used</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {[
              { n: 'ci-deploy',     prefix:'lfpm_pat_3a91…', scope:'read:policies',                  owner:'hamza',  created:'14d',  last:'2m ago',  ok: true },
              { n: 'sap-readonly',  prefix:'lfpm_svc_b22a…', scope:'read:policies, read:assets',     owner:'service',created:'62d',  last:'4h ago',  ok: true },
              { n: 'splunk-export', prefix:'lfpm_svc_c012…', scope:'read:audit-log',                 owner:'service',created:'90d',  last:'8m ago',  ok: true },
              { n: 'youssef-laptop',prefix:'lfpm_pat_d711…', scope:'read:cves, read:policies',       owner:'youssef',created:'3d',   last:'12h ago', ok: true },
            ].map((r, i) => (
              <tr key={i}>
                <td style={{ paddingLeft: 14 }}><span className="mono strong">{r.n}</span></td>
                <td className="mono dim">{r.prefix}</td>
                <td className="mono dim">{r.scope}</td>
                <td className="dim">{r.owner}</td>
                <td className="mono dim">{r.created}</td>
                <td className="mono dim">{r.last}</td>
                <td><span className="stat-text safe"><span className="dot" />active</span></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ padding: 10, borderTop: '1px solid var(--bd-1)', display:'flex', gap: 8 }}>
          <button
            className="btn primary"
            onClick={() => {
              const token = {
                name: `demo-token-${Date.now().toString(36)}`,
                prefix: `lfpm_pat_${Math.random().toString(36).slice(2, 6)}…`,
                scope: 'read:policies, read:cves',
                created: new Date().toISOString(),
                note: 'Demo token manifest — store securely; not persisted server-side',
              };
              const fname = `${token.name}.json`;
              const blob = new Blob([JSON.stringify(token, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url; a.download = fname;
              document.body.appendChild(a); a.click(); a.remove();
              setTimeout(() => URL.revokeObjectURL(url), 1000);
              window.toast('Demo token created', { kind:'ok', sub: `${fname} downloaded` });
            }}
          ><I.Plus size={13} /> create token</button>
          <button
            className="btn"
            onClick={() => {
              window.open('/docs', '_blank', 'noopener');
              window.toast('API docs opened', { kind:'info', sub:'FastAPI Swagger UI · /docs' });
            }}
          ><I.Code size={13} /> open api docs</button>
        </div>
      </div>
    </>
  );
}

/* ── Audit log ────────────────────────────────────────────────── */
function AuditLog() {
  const I = window.Icons;
  const rows = [
    { t:'14:32:08', user:'hamza',   action:'firewall.sync',              target:'fw-004',  ok: true },
    { t:'14:30:18', user:'youssef', action:'rule.disable',               target:'POL-018', ok: true },
    { t:'14:28:55', user:'hamza',   action:'session.open',               target:'102.43.18.4', ok: true },
    { t:'14:24:02', user:'system',  action:'analyzer.run',               target:'all',     ok: true },
    { t:'14:18:46', user:'ali',     action:'export.csv',                 target:'policy-audit', ok: true },
    { t:'14:02:31', user:'hamza',   action:'connector.create',           target:'fg-200f-dr', ok: true },
    { t:'13:58:00', user:'system',  action:'cve.correlate',              target:'all', ok: true },
    { t:'13:44:11', user:'youssef', action:'token.create:ci-deploy',     target:'self',  ok: true },
    { t:'12:18:09', user:'system',  action:'cron.failed',                target:'topology.discovery', ok: false },
    { t:'12:00:00', user:'system',  action:'cron.start',                 target:'cross-vendor', ok: true },
  ];
  return (
    <>
      <SectionHead title="Audit log" desc="Every admin action is recorded with actor, target, and outcome." />
      <div className="panel">
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>time (utc)</th>
              <th>actor</th>
              <th>action</th>
              <th>target</th>
              <th>result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td style={{ paddingLeft: 14 }} className="mono dim">2026-04-13 {r.t}</td>
                <td className="mono">{r.user}</td>
                <td className="mono strong">{r.action}</td>
                <td className="mono dim">{r.target}</td>
                <td>
                  <span className={`stat-text ${r.ok ? 'safe' : 'critical'}`}>
                    <span className="dot" />{r.ok ? 'ok' : 'failed'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ── About ───────────────────────────────────────────────────── */
function About() {
  return (
    <>
      <SectionHead title="About" desc="Platform build info & support." />
      <div className="panel">
        <div className="col" style={{ padding: 0 }}>
          {[
            { k:'product',         v:'Lumina FPM · firewall policy management' },
            { k:'version',         v:'2.4.1 (build 8a91c2 · 2026-04-09)' },
            { k:'analyzer engine', v:'lumina-analyzer v3.1' },
            { k:'data plane',      v:'fastapi · python 3.12 · postgres 15' },
            { k:'license',         v:'enterprise · 250 device pack · expires 2027-04-30' },
            { k:'support',         v:'support@lumina-fpm.io · 24x7 named contacts' },
            { k:'runbook',         v:'docs.lumina-fpm.io/runbook' },
          ].map((r, i) => (
            <div key={i} style={{
              display:'grid', gridTemplateColumns:'200px 1fr',
              padding: '8px 14px', borderBottom: '1px solid var(--bd-1)',
              fontSize: 12,
            }}>
              <span className="muted">{r.k}</span>
              <span className="mono" style={{ color: 'var(--fg-1)' }}>{r.v}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function SectionHead({ title, desc }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: 'var(--fg-0)', letterSpacing:'-0.01em' }}>{title}</h2>
      <p style={{ margin: '4px 0 0', fontSize: 12.5, color: 'var(--fg-2)' }}>{desc}</p>
    </div>
  );
}

export { Settings };
