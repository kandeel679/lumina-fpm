import React from "react";
import { Icons } from "./icons";
import { LFPM } from "./data";
/* ─────────────────────────────────────────────────────────────────
 * Toast system + popover menus
 *
 * Exposes window.toast(message, opts) — usable from any component.
 * Renders: <ToastHost />  (mount once at app root)
 *
 * Popovers (UserMenu / NotifMenu / TenantMenu / TimeRangeMenu)
 * each handle their own outside-click + escape close.
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateM, useEffect: useEffectM, useRef: useRefM, useCallback: useCallbackM } = React;

/* ── Toast event bus (module-level) ─────────────────────────────── */
const toastBus = {
  listeners: new Set(),
  push(t) { this.listeners.forEach(fn => fn(t)); },
  subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
};

/* Global helper */
window.toast = function (titleOrOpts, opts = {}) {
  const t = typeof titleOrOpts === 'string'
    ? { id: Date.now() + Math.random(), title: titleOrOpts, ...opts }
    : { id: Date.now() + Math.random(), ...titleOrOpts };
  if (!t.kind) t.kind = 'info';
  if (!t.duration) t.duration = 3500;
  toastBus.push(t);
  return t.id;
};

/* ── Toast host (renders the stack) ─────────────────────────────── */
function ToastHost() {
  const I = window.Icons;
  const [toasts, setToasts] = useStateM([]);
  const [exiting, setExiting] = useStateM(new Set());

  useEffectM(() => toastBus.subscribe((t) => {
    setToasts((prev) => [...prev, t]);
    setTimeout(() => dismiss(t.id), t.duration);
  }), []);

  const dismiss = (id) => {
    setExiting(prev => new Set(prev).add(id));
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
      setExiting(prev => {
        const n = new Set(prev); n.delete(id); return n;
      });
    }, 180);
  };

  const iconFor = (kind) => {
    if (kind === 'ok')   return I.CheckCirc;
    if (kind === 'err')  return I.AlertCirc;
    if (kind === 'warn') return I.AlertTri;
    return I.Activity;
  };

  return (
    <div className="toast-stack">
      {toasts.map(t => {
        const Ico = iconFor(t.kind);
        return (
          <div key={t.id} className={`toast ${t.kind} ${exiting.has(t.id) ? 'exiting' : ''}`}>
            <span className="ico"><Ico size={14} /></span>
            <div className="text">
              <div className="title">{t.title}</div>
              {t.sub && <div className="sub">{t.sub}</div>}
            </div>
            <span className="close" onClick={() => dismiss(t.id)}>
              <I.Close size={12} />
            </span>
          </div>
        );
      })}
    </div>
  );
}
export { ToastHost, UserMenu, NotifMenu, TenantMenu, TimeRangeMenu };

/* ── Outside-click hook ─────────────────────────────────────────── */
function useOutsideClick(ref, onClose, active) {
  useEffectM(() => {
    if (!active) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) onClose();
    };
    const key = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('mousedown', handler);
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('keydown', key);
    };
  }, [active, onClose]);
}
window.useOutsideClick = useOutsideClick;

/* ── User Menu ──────────────────────────────────────────────────── */
function UserMenu({ user, onClose, onNavigate, onSignOut }) {
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  return (
    <div ref={ref} className="popover" style={{ right: 12, top: 'calc(var(--topbar-h) + 4px)', width: 280 }}>
      <div className="popover-user">
        <div className="row gap-2" style={{ marginBottom: 6 }}>
          <div className="tb-avatar" style={{ width: 32, height: 32, fontSize: 12 }}>{user.avatar}</div>
          <div className="col" style={{ lineHeight: 1.2 }}>
            <span className="name">{user.name}</span>
            <span className="email">{user.email}</span>
          </div>
        </div>
        <div className="meta-row">
          <span className="chip accent">{user.role}</span>
          <span className="muted" style={{ fontSize: 11 }}>{user.dept}</span>
        </div>
      </div>
      <div className="popover-body">
        <div className="popover-row" onClick={() => { onNavigate('settings'); onClose(); }}>
          <span className="ico"><I.Users size={14} /></span>
          profile & preferences
        </div>
        <div className="popover-row" onClick={() => { onNavigate('settings'); onClose(); }}>
          <span className="ico"><I.Key size={14} /></span>
          api tokens
        </div>
        <div className="popover-row" onClick={() => { window.toast('Theme toggle is disabled in this build', { kind:'info', sub: 'Dark mode only' }); onClose(); }}>
          <span className="ico"><I.Settings size={14} /></span>
          appearance
        </div>
        <div className="popover-divider" />
        <div className="popover-row" onClick={() => { window.toast('Help center coming soon', { kind:'info' }); onClose(); }}>
          <span className="ico"><I.AlertCirc size={14} /></span>
          help & docs
        </div>
        <div className="popover-row danger" onClick={() => { onSignOut(); onClose(); }}>
          <span className="ico"><I.Logout size={14} /></span>
          sign out
        </div>
      </div>
      <div className="popover-footer">
        <span className="muted mono">session ends in 28m</span>
      </div>
    </div>
  );
}

/* ── Notification Menu ──────────────────────────────────────────── */
function NotifMenu({ onClose, onOpenInspector }) {
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  const items = [
    { id:'n1', kind:'crit',  title:'CVE-2024-3400 still unpatched on pa-820-branch', t:'2m ago', cveId:'CVE-2024-3400' },
    { id:'n2', kind:'high',  title:'New shadowed rule detected · POL-018 on pa-3260-dmz', t:'8m ago', ruleId:'POL-018' },
    { id:'n3', kind:'high',  title:'pa-820-branch · connector status degraded',         t:'14m ago', fwId:'fw-003' },
    { id:'n4', kind:'med',   title:'Weekly audit digest available', t:'1h ago' },
    { id:'n5', kind:'read',  title:'fortinet psirt sync · ok',     t:'1h ago' },
  ];
  const openFor = (it) => {
    if (it.cveId)   onOpenInspector({ kind:'cve',      data: window.LFPM.threats.find(t => t.id === it.cveId) });
    else if (it.ruleId) onOpenInspector({ kind:'rule', data: window.LFPM.policies.find(p => p.id === it.ruleId) });
    else if (it.fwId)   onOpenInspector({ kind:'firewall', data: window.LFPM.firewalls.find(f => f.id === it.fwId) });
    else window.toast('Opened report', { kind:'info' });
    onClose();
  };
  return (
    <div ref={ref} className="popover" style={{ right: 92, top: 'calc(var(--topbar-h) + 4px)', width: 360 }}>
      <div className="popover-head" style={{ display:'flex', alignItems:'center' }}>
        <div className="popover-title">notifications</div>
        <span className="muted mono" style={{ marginLeft: 'auto', fontSize: 10.5 }}>3 unread</span>
      </div>
      <div className="popover-body" style={{ padding: 0 }}>
        {items.map(it => (
          <div key={it.id} className="notif-row" onClick={() => openFor(it)}>
            <span className={`left ${it.kind}`} />
            <div className="body">
              <div className="title">{it.title}</div>
              <div className="meta">{it.t}</div>
            </div>
          </div>
        ))}
      </div>
      <div className="popover-footer" style={{ justifyContent: 'space-between' }}>
        <span className="sb-link" onClick={() => { window.toast('Marked all as read'); onClose(); }}>mark all as read</span>
        <span className="muted">esc to close</span>
      </div>
    </div>
  );
}

/* ── Tenant Menu ────────────────────────────────────────────────── */
function TenantMenu({ onClose }) {
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  const tenants = [
    { id:'acme',     name:'Acme Industrial',   env:'prod',    region:'eu-west-1', active:true,  letter:'A' },
    { id:'acme-stg', name:'Acme Industrial',   env:'staging', region:'eu-west-1', active:false, letter:'A' },
    { id:'globex',   name:'Globex Corp',       env:'prod',    region:'us-east-2', active:false, letter:'G' },
    { id:'initech',  name:'Initech',           env:'prod',    region:'us-west-1', active:false, letter:'I' },
  ];
  const pick = (t) => {
    if (t.active) { onClose(); return; }
    window.toast('Org switching disabled in this build', { kind:'info', sub: `would load ${t.name} · ${t.env}` });
    onClose();
  };
  return (
    <div ref={ref} className="popover" style={{ left: 8, top: 'calc(var(--topbar-h) + 4px)', width: 260 }}>
      <div className="popover-head"><div className="popover-title">switch organization</div></div>
      <div className="popover-body" style={{ padding: 4 }}>
        {tenants.map(t => (
          <div key={t.id} className={`popover-row ${t.active ? 'active' : ''}`} onClick={() => pick(t)}>
            <div className="tb-tenant-mark" style={{ width: 22, height: 22, fontSize: 10 }}>{t.letter}</div>
            <div className="col" style={{ lineHeight: 1.15 }}>
              <span style={{ color:'var(--fg-0)', fontSize: 12.5 }}>{t.name}</span>
              <span className="muted mono" style={{ fontSize: 10.5 }}>{t.env} · {t.region}</span>
            </div>
            <span className="check"><I.CheckCirc size={13} /></span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Time-range Menu ────────────────────────────────────────────── */
function TimeRangeMenu({ current, onPick, onClose }) {
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  const opts = [
    { id:'1h',  label:'last 1 hour' },
    { id:'6h',  label:'last 6 hours' },
    { id:'24h', label:'last 24 hours' },
    { id:'7d',  label:'last 7 days' },
    { id:'30d', label:'last 30 days' },
    { id:'90d', label:'last 90 days' },
  ];
  return (
    <div ref={ref} className="popover" style={{ right: 150, top: 'calc(var(--topbar-h) + 4px)', width: 200 }}>
      <div className="popover-head"><div className="popover-title">time range</div></div>
      <div className="popover-body" style={{ padding: 4 }}>
        {opts.map(o => (
          <div
            key={o.id}
            className={`popover-row ${current === o.id ? 'active' : ''}`}
            onClick={() => { onPick(o.id); onClose(); }}
          >
            {o.label}
            <span className="check"><I.CheckCirc size={13} /></span>
          </div>
        ))}
        <div className="popover-divider" />
        <div className="popover-row" onClick={() => { window.toast('Custom range picker coming soon', { kind:'info' }); onClose(); }}>
          <span className="ico"><I.Calendar size={14} /></span>
          custom range…
        </div>
      </div>
    </div>
  );
}
