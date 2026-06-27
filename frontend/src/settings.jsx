import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
import {
  triggerRulesSync,
  fetchDevices, createDevice, updateDevice, deleteDevice,
  setDeviceCredential, testDeviceConnection,
  fetchSchedules, updateSchedule, runScheduleNow,
  fetchNotifications, markAllNotificationsRead,
} from "./api";
/* ─────────────────────────────────────────────────────────────────
 * Settings — admin console
 * Firewalls / Scheduling / Notifications are LIVE (wired to the backend).
 * Read-only toward firewall devices: configuration lives in LuminaFPM only.
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateS, useEffect: useEffectS, useCallback: useCallbackS } = React;

const SETTINGS_TABS = [
  { id: 'connectors',    label: 'Firewalls' },
  { id: 'schedules',     label: 'Scheduling' },
  { id: 'notifications', label: 'Notifications' },
  { id: 'access',        label: 'Access & roles' },
  { id: 'api',           label: 'API & secrets' },
  { id: 'audit-log',     label: 'Audit log' },
  { id: 'about',         label: 'About' },
];

const inputStyle = {
  background: 'var(--bg-2)', color: 'var(--fg-1)', border: '1px solid var(--bd-1)',
  borderRadius: 4, padding: '6px 8px', fontSize: 12, width: '100%', fontFamily: 'inherit',
};
const labelStyle = { fontSize: 10.5, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 3, display: 'block' };

function fmtWhen(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function Settings({ openInspector, refreshData }) {
  const [tab, setTab] = useStateS('connectors');

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Platform configuration · viewing as <span className="mono" style={{ color: 'var(--fg-1)' }}>hamza@lumina-fpm.local</span> · role <span className="mono" style={{ color: 'var(--fg-1)' }}>admin</span></p>
        </div>
        <div className="row gap-2" style={{ marginLeft: 'auto' }}>
          <span className="chip">read-only toward firewalls</span>
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
              </button>
            ))}
          </div>
          <div style={{ padding: 14, fontSize: 11, color: 'var(--fg-3)', lineHeight: 1.6 }}>
            Firewall credentials are <span style={{ color:'var(--fg-1)' }}>encrypted at rest</span>. Schedules run on the platform scheduler; runs surface in Notifications.
          </div>
        </aside>

        {/* Right content */}
        <div style={{ overflow:'auto', minHeight: 0, padding: '16px 20px', background: 'var(--bg-0)' }}>
          {tab === 'connectors'    && <Firewalls refreshData={refreshData} />}
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

/* ── Firewalls (device management) ───────────────────────────────── */
const AUTH_TYPES = {
  fortinet: [['fortigate_api_token', 'FortiGate API token']],
  paloalto: [['panos_api_key', 'PAN-OS API key'], ['panos_userpass', 'PAN-OS user:password']],
};

function Firewalls({ refreshData }) {
  const I = window.Icons;
  const [devices, setDevices] = useStateS([]);
  const [loading, setLoading] = useStateS(true);
  const [form, setForm] = useStateS(null);   // add/edit device
  const [cred, setCred] = useStateS(null);   // credential entry
  const [testingId, setTestingId] = useStateS(null);

  const load = useCallbackS(async () => {
    setLoading(true);
    try { setDevices((await fetchDevices()) || []); }
    catch (e) { window.toast('Failed to load firewalls', { kind: 'crit', sub: String(e.message || e) }); }
    finally { setLoading(false); }
  }, []);
  useEffectS(() => { load(); }, [load]);

  const reloadAll = async () => { await load(); if (typeof refreshData === 'function') await refreshData(); };

  const openAdd = () => setForm({ __new: true, hostname: '', vendor_type: 'fortinet', management_ip: '', location: '', use_http: false });
  const openEdit = (d) => setForm({
    __new: false, device_id: d.device_id, hostname: d.hostname || '', vendor_type: d.vendor_type || 'fortinet',
    management_ip: d.management_ip || '', location: d.location || '', use_http: !!d.use_http,
  });

  const saveForm = async () => {
    const f = form;
    if (!f.hostname.trim() || !f.management_ip.trim()) { window.toast('Hostname and IP are required', { kind: 'warn' }); return; }
    const payload = {
      vendor_type: f.vendor_type, hostname: f.hostname.trim(),
      management_ip: f.management_ip.trim(), location: f.location.trim() || null, use_http: f.use_http,
    };
    try {
      if (f.__new) { await createDevice(payload); window.toast('Firewall added', { kind: 'ok', sub: f.hostname }); }
      else { await updateDevice(f.device_id, payload); window.toast('Firewall updated', { kind: 'ok', sub: f.hostname }); }
      setForm(null);
      await reloadAll();
    } catch (e) { window.toast('Save failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  const openCred = (d) => setCred({
    device_id: d.device_id, hostname: d.hostname,
    auth_type: (AUTH_TYPES[d.vendor_type] || AUTH_TYPES.fortinet)[0][0], secret: '',
  });
  const saveCred = async () => {
    if (!cred.secret.trim()) { window.toast('Secret is required', { kind: 'warn' }); return; }
    try {
      await setDeviceCredential(cred.device_id, cred.auth_type, cred.secret.trim());
      window.toast('Credential saved (encrypted at rest)', { kind: 'ok', sub: cred.hostname });
      setCred(null);
    } catch (e) { window.toast('Save failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  const test = async (d) => {
    setTestingId(d.device_id);
    window.toast(`Testing ${d.hostname}…`, { kind: 'info' });
    try {
      const r = await testDeviceConnection(d.device_id);
      if (r && r.ok) window.toast('Connection OK', { kind: 'ok', sub: d.hostname });
      else window.toast('Connection failed', { kind: 'warn', sub: `${(r && r.error_code) || ''} ${(r && r.detail) || ''}`.trim() || 'no response' });
    } catch (e) { window.toast('Test failed', { kind: 'crit', sub: String(e.message || e) }); }
    finally { setTestingId(null); }
  };

  const poll = async (d) => {
    window.toast(`Acquiring ${d.hostname}…`, { kind: 'info' });
    try { await triggerRulesSync(d.device_id); window.toast('Acquisition queued', { kind: 'ok', sub: `${d.hostname} · watch Notifications for the result` }); }
    catch (e) { window.toast('Acquisition failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  const remove = async (d) => {
    if (!window.confirm(`Delete ${d.hostname}? This removes the firewall and all of its acquired data from LuminaFPM. The firewall itself is not touched.`)) return;
    try { await deleteDevice(d.device_id); window.toast('Firewall removed', { kind: 'ok', sub: d.hostname }); await reloadAll(); }
    catch (e) { window.toast('Delete failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  return (
    <>
      <SectionHead title="Firewalls" desc="Add and configure the firewalls LuminaFPM connects to. Acquisition is read-only — Lumina never writes to a device." />

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <div className="panel-title"><I.Shield size={12} /> firewall fleet</div>
          <div className="panel-meta">{devices.length} configured</div>
        </div>
        <table className="t">
          <thead>
            <tr>
              <th style={{ paddingLeft: 14 }}>device</th>
              <th>vendor</th>
              <th>endpoint</th>
              <th>status</th>
              <th>last poll</th>
              <th style={{ textAlign: 'right', paddingRight: 14 }}>actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} style={{ padding: 16 }} className="muted">loading…</td></tr>
            )}
            {!loading && devices.length === 0 && (
              <tr><td colSpan={6} style={{ padding: 16 }} className="muted">No firewalls configured yet. Click <strong>Add firewall</strong> to onboard one.</td></tr>
            )}
            {devices.map(d => {
              const scheme = d.use_http ? 'http' : 'https';
              return (
                <tr key={d.device_id}>
                  <td style={{ paddingLeft: 14 }}>
                    <span className="mono strong">{d.hostname}</span>
                    {d.location && <div className="mono dim" style={{ fontSize: 10.5 }}>{d.location}</div>}
                  </td>
                  <td>{d.vendor_type === 'paloalto' ? 'palo alto' : d.vendor_type === 'fortinet' ? 'fortinet' : (d.vendor_type || '—')}</td>
                  <td className="mono dim">
                    {scheme}://{d.management_ip}
                    {d.use_http && <span className="chip" style={{ marginLeft: 6, fontSize: 9.5 }}>http</span>}
                  </td>
                  <td>
                    <span className={`stat-text ${d.status === 'online' ? 'safe' : 'dim'}`}>
                      <span className="dot" />{d.status || 'unknown'}
                    </span>
                  </td>
                  <td className="mono dim">{fmtWhen(d.last_poll_time)}</td>
                  <td style={{ textAlign: 'right', paddingRight: 14 }}>
                    <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }}>
                      <button className="btn ghost" style={{ padding: '4px 8px', minHeight: 0 }} title="Enter / rotate API credential" onClick={() => openCred(d)}><I.Key size={12} /></button>
                      <button className="btn ghost" style={{ padding: '4px 8px', minHeight: 0 }} title="Test connection (read-only)" disabled={testingId === d.device_id} onClick={() => test(d)}><I.Activity size={12} /></button>
                      <button className="btn ghost" style={{ padding: '4px 8px', minHeight: 0 }} title="Acquire now (re-poll config)" onClick={() => poll(d)}><I.Refresh size={12} /></button>
                      <button className="btn ghost" style={{ padding: '4px 8px', minHeight: 0 }} title="Edit firewall" onClick={() => openEdit(d)}><I.Settings size={12} /></button>
                      <button className="btn ghost" style={{ padding: '4px 8px', minHeight: 0, color: 'var(--crit, #e5484d)' }} title="Delete firewall" onClick={() => remove(d)}><I.Close size={12} /></button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div style={{ padding: 10, borderTop: '1px solid var(--bd-1)', display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="muted" style={{ fontSize: 11.5 }}>Credentials are encrypted with the platform key and never returned to the UI.</span>
          <button style={{ marginLeft: 'auto' }} className="btn primary" onClick={openAdd}><I.Plus size={13} /> add firewall</button>
        </div>
      </div>

      {/* Add / edit device form */}
      {form && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head"><div className="panel-title"><I.Shield size={12} /> {form.__new ? 'add firewall' : `edit ${form.hostname || 'firewall'}`}</div></div>
          <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={labelStyle}>hostname</label>
              <input style={inputStyle} value={form.hostname} placeholder="FGT-LAB-01" onChange={e => setForm({ ...form, hostname: e.target.value })} />
            </div>
            <div>
              <label style={labelStyle}>vendor</label>
              <select style={inputStyle} value={form.vendor_type} onChange={e => setForm({ ...form, vendor_type: e.target.value })}>
                <option value="fortinet">Fortinet (FortiOS REST)</option>
                <option value="paloalto">Palo Alto (PAN-OS XML)</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>management ip / host</label>
              <input style={inputStyle} value={form.management_ip} placeholder="192.168.1.99" onChange={e => setForm({ ...form, management_ip: e.target.value })} />
            </div>
            <div>
              <label style={labelStyle}>location (optional)</label>
              <input style={inputStyle} value={form.location} placeholder="Lab · Rack 2" onChange={e => setForm({ ...form, location: e.target.value })} />
            </div>
            <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--fg-1)', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.use_http} onChange={e => setForm({ ...form, use_http: e.target.checked })} />
                Use plain HTTP for this device's API
              </label>
              <span className="muted" style={{ fontSize: 11 }}>lab only — e.g. a FortiGate whose HTTPS admin cert is broken</span>
            </div>
          </div>
          <div style={{ padding: 10, borderTop: '1px solid var(--bd-1)', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button className="btn ghost" onClick={() => setForm(null)}>cancel</button>
            <button className="btn primary" onClick={saveForm}>{form.__new ? 'add firewall' : 'save changes'}</button>
          </div>
        </div>
      )}

      {/* Credential entry form */}
      {cred && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-head"><div className="panel-title"><I.Key size={12} /> credential · {cred.hostname}</div></div>
          <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 12 }}>
            <div>
              <label style={labelStyle}>auth type</label>
              <select style={inputStyle} value={cred.auth_type} onChange={e => setCred({ ...cred, auth_type: e.target.value })}>
                {(AUTH_TYPES[devices.find(d => d.device_id === cred.device_id)?.vendor_type] || AUTH_TYPES.fortinet).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={labelStyle}>{cred.auth_type === 'panos_userpass' ? 'user:password' : 'api token / key'}</label>
              <input style={inputStyle} type="password" autoComplete="off" value={cred.secret}
                placeholder={cred.auth_type === 'panos_userpass' ? 'admin:secret' : 'paste the API token'}
                onChange={e => setCred({ ...cred, secret: e.target.value })} />
            </div>
          </div>
          <div style={{ padding: 10, borderTop: '1px solid var(--bd-1)', display: 'flex', gap: 8, justifyContent: 'flex-end', alignItems: 'center' }}>
            <span className="muted" style={{ fontSize: 11, marginRight: 'auto' }}>Stored encrypted (Fernet) · write-only · never shown again.</span>
            <button className="btn ghost" onClick={() => setCred(null)}>cancel</button>
            <button className="btn primary" onClick={saveCred}>save credential</button>
          </div>
        </div>
      )}
    </>
  );
}

/* ── Scheduling ──────────────────────────────────────────────────── */
const OP_META = {
  acquisition:  { label: 'Data acquisition',    desc: 'Poll every configured firewall and re-normalize its live config.' },
  detection:    { label: 'Anomaly detection',   desc: 'Run the deterministic anomaly engine across all devices.' },
  threat_intel: { label: 'Threat intelligence', desc: 'Refresh CTI indicators and firmware-CVE evidence.' },
};
const INTERVAL_PRESETS = [
  [15, 'every 15 minutes'], [30, 'every 30 minutes'], [60, 'every hour'],
  [360, 'every 6 hours'], [720, 'every 12 hours'], [1440, 'every 24 hours'],
];

function Schedules() {
  const I = window.Icons;
  const [rows, setRows] = useStateS([]);
  const [loading, setLoading] = useStateS(true);

  const load = useCallbackS(async () => {
    setLoading(true);
    try { const d = await fetchSchedules(); setRows(d?.items || []); }
    catch (e) { window.toast('Failed to load schedules', { kind: 'crit', sub: String(e.message || e) }); }
    finally { setLoading(false); }
  }, []);
  useEffectS(() => { load(); }, [load]);

  const patchLocal = (op, changes) => setRows(rs => rs.map(r => r.operation === op ? { ...r, ...changes } : r));

  const save = async (row) => {
    const payload = {
      enabled: row.enabled, mode: row.mode,
      interval_minutes: row.interval_minutes || 360,
      cron_expression: row.mode === 'cron' ? (row.cron_expression || '') : null,
    };
    try {
      const updated = await updateSchedule(row.operation, payload);
      patchLocal(row.operation, updated);
      window.toast('Schedule saved', { kind: 'ok', sub: `${OP_META[row.operation].label} · ${updated.enabled ? updated.summary : 'disabled'}` });
    } catch (e) { window.toast('Save failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  const runNow = async (row) => {
    window.toast(`Running ${OP_META[row.operation].label}…`, { kind: 'info' });
    try { await runScheduleNow(row.operation); window.toast('Dispatched', { kind: 'ok', sub: 'watch Notifications for the result' }); }
    catch (e) { window.toast('Run failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  return (
    <>
      <SectionHead title="Scheduling" desc="Run acquisition, anomaly detection, and threat intelligence on demand or on a schedule. Each operation can run immediately (Run now) or on a recurring cadence." />
      {loading && <div className="muted" style={{ padding: 8 }}>loading…</div>}
      {rows.map(row => {
        const meta = OP_META[row.operation] || { label: row.operation, desc: '' };
        return (
          <div key={row.operation} className="panel" style={{ marginBottom: 14 }}>
            <div className="panel-head" style={{ alignItems: 'center' }}>
              <div className="panel-title"><I.Calendar size={12} /> {meta.label}</div>
              <label style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--fg-1)', cursor: 'pointer' }}>
                <input type="checkbox" checked={!!row.enabled} onChange={e => patchLocal(row.operation, { enabled: e.target.checked })} />
                {row.enabled ? 'enabled' : 'disabled'}
              </label>
            </div>
            <div style={{ padding: '12px 14px' }}>
              <p style={{ margin: '0 0 12px', fontSize: 12, color: 'var(--fg-2)' }}>{meta.desc}</p>
              <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: 12, alignItems: 'center' }}>
                <label style={labelStyle}>mode</label>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <select style={{ ...inputStyle, width: 130 }} value={row.mode} onChange={e => patchLocal(row.operation, { mode: e.target.value })}>
                    <option value="interval">Interval</option>
                    <option value="cron">Cron (advanced)</option>
                  </select>
                  {row.mode === 'interval' ? (
                    <select style={{ ...inputStyle, width: 200 }} value={row.interval_minutes || 360} onChange={e => patchLocal(row.operation, { interval_minutes: Number(e.target.value) })}>
                      {INTERVAL_PRESETS.map(([m, l]) => <option key={m} value={m}>{l}</option>)}
                    </select>
                  ) : (
                    <input style={{ ...inputStyle, width: 200, fontFamily: 'var(--f-mono)' }} value={row.cron_expression || ''} placeholder="0 2 * * *"
                      onChange={e => patchLocal(row.operation, { cron_expression: e.target.value })} />
                  )}
                  {row.mode === 'cron' && <span className="mono dim" style={{ fontSize: 10.5 }}>min hour dom month dow</span>}
                </div>
              </div>
            </div>
            <div style={{ padding: 10, borderTop: '1px solid var(--bd-1)', display: 'flex', gap: 14, alignItems: 'center' }}>
              <span className="mono dim" style={{ fontSize: 11 }}>last run: {fmtWhen(row.last_run_at)}</span>
              <span className="mono dim" style={{ fontSize: 11 }}>next run: {row.enabled ? fmtWhen(row.next_run_at) : '—'}</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                <button className="btn ghost" onClick={() => runNow(row)} title="Run this operation immediately"><I.Refresh size={12} /> run now</button>
                <button className="btn primary" onClick={() => save(row)}>save schedule</button>
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}

/* ── Notifications (in-app feed) ─────────────────────────────────── */
const LEVEL_CLASS = { critical: 'critical', warning: 'high', success: 'safe', info: 'dim' };

function Notifications() {
  const I = window.Icons;
  const [notes, setNotes] = useStateS([]);
  const [loading, setLoading] = useStateS(true);

  const load = useCallbackS(async () => {
    setLoading(true);
    try { const d = await fetchNotifications(40); setNotes(d?.items || []); }
    catch (e) { window.toast('Failed to load notifications', { kind: 'crit', sub: String(e.message || e) }); }
    finally { setLoading(false); }
  }, []);
  useEffectS(() => { load(); }, [load]);

  const markAll = async () => {
    try { await markAllNotificationsRead(); window.toast('All marked read', { kind: 'ok' }); await load(); }
    catch (e) { window.toast('Failed', { kind: 'crit', sub: String(e.message || e) }); }
  };

  const unread = notes.filter(n => !n.read).length;

  return (
    <>
      <SectionHead title="Notifications" desc="In-app alerts when acquisition, detection, or threat-intel runs complete or fail — and when a scan surfaces high/critical findings. Delivered to the bell in the top bar." />
      <div className="panel">
        <div className="panel-head" style={{ alignItems: 'center' }}>
          <div className="panel-title"><I.Bell size={12} /> activity</div>
          <div className="panel-meta" style={{ marginLeft: 'auto' }}>{unread} unread · {notes.length} total</div>
          <button className="btn ghost" style={{ marginLeft: 10, padding: '4px 10px', minHeight: 0 }} onClick={markAll} disabled={!unread}>mark all read</button>
        </div>
        <div className="col" style={{ padding: 0 }}>
          {loading && <div className="muted" style={{ padding: 14 }}>loading…</div>}
          {!loading && notes.length === 0 && (
            <div className="muted" style={{ padding: 16 }}>No notifications yet. Run an acquisition or a scan (or schedule one) and the result will appear here and on the bell.</div>
          )}
          {notes.map(n => (
            <div key={n.id} style={{
              padding: '10px 14px', display: 'grid', gridTemplateColumns: '12px 1fr auto',
              borderBottom: '1px solid var(--bd-1)', alignItems: 'start', gap: 12,
              background: n.read ? 'transparent' : 'var(--bg-1)',
            }}>
              <span className={`stat-text ${LEVEL_CLASS[n.level] || 'dim'}`} style={{ marginTop: 2 }}><span className="dot" /></span>
              <div>
                <div style={{ fontSize: 12, color: 'var(--fg-0)' }}>{n.title}</div>
                {n.body && <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>{n.body}</div>}
                <div className="mono dim" style={{ fontSize: 10.5, marginTop: 3 }}>{n.category}</div>
              </div>
              <span className="mono dim" style={{ fontSize: 10.5, whiteSpace: 'nowrap' }}>{fmtWhen(n.created_at)}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

/* ── Access & roles ───────────────────────────────────────────────── */
function AccessRoles() {
  const { data: LFPM } = useLFPM();
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

/* ── API & secrets ────────────────────────────────────────────────── */
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

/* ── Audit log ────────────────────────────────────────────────────── */
function AuditLog() {
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

/* ── About ───────────────────────────────────────────────────────── */
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
