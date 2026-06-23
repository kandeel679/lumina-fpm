import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
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
    /* Defer to a microtask so a toast fired synchronously during another
     * component's render (e.g. App) never triggers setState-in-render. */
    queueMicrotask(() => {
      setToasts((prev) => [...prev, t]);
      setTimeout(() => dismiss(t.id), t.duration);
    });
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

// The Topbar (shell.jsx) renders these via window.* (matching the codebase's
// window.Icons / window.toast pattern). Register them or the dropdowns silently
// render nothing.
Object.assign(window, { UserMenu, NotifMenu, TenantMenu, TimeRangeMenu });

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
function UserMenu({ user, onClose, onNavigate, onSignOut, theme, onToggleTheme }) {
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
        <div className="popover-row" onClick={() => { onToggleTheme?.(); onClose(); }}>
          <span className="ico">{theme === 'dark' ? <I.Sun size={14} /> : <I.Moon size={14} />}</span>
          appearance · {theme === 'dark' ? 'dark' : 'light'} — switch to {theme === 'dark' ? 'light' : 'dark'}
        </div>
        <div className="popover-divider" />
        <div className="popover-row" onClick={() => { window.toast('Keyboard shortcuts', { kind:'info', sub: '⌘K search · / filter · j/k rows · esc close', duration: 4500 }); onClose(); }}>
          <span className="ico"><I.AlertCirc size={14} /></span>
          help & shortcuts
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
function NotifMenu({ onClose, onOpenInspector, onNavigate }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  /* Live items: top of the activity feed (same source as the dashboard) */
  const sevToKind = { critical:'crit', high:'high', medium:'med' };
  const items = (LFPM.activityFeed || []).slice(0, 5).map((a, i) => ({
    id: `n${i}`,
    kind: sevToKind[a.sev] || (a.kind === 'alert' ? 'high' : 'read'),
    title: a.text || '—',
    t: a.t || '',
    link: a.link || null,
  }));
  const openFor = (it) => {
    if (it.link && onNavigate) onNavigate(it.link.page, it.link.params || null);
    else window.toast('No linked view for this event', { kind:'info', sub: it.title });
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
  return (
    <div ref={ref} className="popover" style={{ left: 8, top: 'calc(var(--topbar-h) + 4px)', width: 260 }}>
      <div className="popover-head"><div className="popover-title">organization</div></div>
      <div className="popover-body" style={{ padding: 4 }}>
        <div className="popover-row active" onClick={onClose}>
          <div className="tb-tenant-mark" style={{ width: 22, height: 22, fontSize: 10 }}>N</div>
          <div className="col" style={{ lineHeight: 1.15 }}>
            <span style={{ color:'var(--fg-0)', fontSize: 12.5 }}>NovaTech Industries</span>
            <span className="muted mono" style={{ fontSize: 10.5 }}>prod · eu-west-1</span>
          </div>
          <span className="check"><I.CheckCirc size={13} /></span>
        </div>
      </div>
      <div className="popover-footer">
        <span className="muted" style={{ fontSize: 10.5 }}>Multi-tenant — Pro roadmap</span>
      </div>
    </div>
  );
}

/* ── Time-range Menu ────────────────────────────────────────────── */
function TimeRangeMenu({ current, onPick, onClose }) {
  const I = window.Icons;
  const ref = useRefM(null);
  useOutsideClick(ref, onClose, true);
  const [showCustom, setShowCustom] = useStateM(false);
  const [from, setFrom] = useStateM('');
  const [to, setTo] = useStateM('');
  const fmt = (iso) => {
    const d = new Date(iso + 'T00:00:00');
    return Number.isNaN(d.getTime())
      ? null
      : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };
  const applyCustom = () => {
    const a = fmt(from);
    const b = fmt(to);
    if (!a || !b) {
      window.toast('Pick both dates', { kind: 'warn', sub: 'a start and end date are required' });
      return;
    }
    onPick('custom', `${a} – ${b}`);
    onClose();
  };
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
        <div className="popover-row" onClick={() => setShowCustom(s => !s)}>
          <span className="ico"><I.Calendar size={14} /></span>
          custom range…
        </div>
        {showCustom && (
          <div className="col" style={{ gap: 6, padding: '6px 8px 8px' }}>
            <input
              type="date"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              style={{ background: 'var(--bg-2)', color: 'var(--fg-1)', border: '1px solid var(--bd-1)', borderRadius: 4, padding: '4px 6px', fontSize: 11.5, fontFamily: 'var(--f-mono)' }}
            />
            <input
              type="date"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              style={{ background: 'var(--bg-2)', color: 'var(--fg-1)', border: '1px solid var(--bd-1)', borderRadius: 4, padding: '4px 6px', fontSize: 11.5, fontFamily: 'var(--f-mono)' }}
            />
            <button
              onClick={applyCustom}
              style={{ background: 'var(--accent)', color: 'var(--bg-0)', border: 'none', borderRadius: 4, padding: '5px 8px', fontSize: 11.5, fontWeight: 600, cursor: 'pointer' }}
            >
              apply range
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
