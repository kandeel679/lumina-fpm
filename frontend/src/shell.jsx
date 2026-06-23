import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
import { triggerRulesSync } from "./api";
/* ─────────────────────────────────────────────────────────────────
 * App shell — left rail, topbar, status bar
 * ───────────────────────────────────────────────────────────────── */

const { useState, useEffect, useMemo } = React;

/* ── Sparkline (used in KPI strip + threat hits) ────────────────── */
function Sparkline({ data, w = 140, h = 18, color = 'var(--accent)' }) {
  if (!data || data.length === 0) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const stepX = w / (data.length - 1);
  const pts = data.map((v, i) => {
    const x = i * stepX;
    const y = h - ((v - min) / range) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const last = data[data.length - 1];
  const lastX = (data.length - 1) * stepX;
  const lastY = h - ((last - min) / range) * h;
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.2" />
      <circle cx={lastX} cy={lastY} r="1.6" fill={color} />
    </svg>
  );
}

/* ── Left rail (icon navigation) ────────────────────────────────── */
function Rail({ current, onNav, criticalCount }) {
  const I = window.Icons;
  const items = [
    { id: 'dashboard', icon: I.Dashboard, label: 'Overview' },
    { id: 'audit',     icon: I.Audit,     label: 'Policy Audit',         badge: criticalCount },
    { id: 'risk',      icon: I.Activity,  label: 'Risk Posture' },
    { id: 'topology',  icon: I.Network,   label: 'Topology' },
    { id: 'threats',   icon: I.Threat,    label: 'Threat Intelligence' },
    { id: 'settings',  icon: I.Settings,  label: 'Settings' },
  ];
  return (
    <div className="rail">
      <div className="rail-logo" title="Lumina FPM">
        <I.Logo size={16} stroke={1.8} />
      </div>
      {items.map(it => {
        const Ico = it.icon;
        return (
          <button
            key={it.id}
            className={`rail-item ${current === it.id ? 'active' : ''}`}
            onClick={() => onNav(it.id)}
          >
            <Ico size={18} stroke={1.6} />
            {it.badge > 0 && <span className="rail-badge">{it.badge}</span>}
            <span className="rail-tip">{it.label}</span>
          </button>
        );
      })}
      <div className="rail-spacer" />
      <button
        className="rail-item"
        title="Keyboard shortcuts"
        onClick={() => window.toast('Keyboard shortcuts', {
          kind: 'info',
          sub: '⌘K search · / filter · j/k rows · esc close',
          duration: 4500,
        })}
      >
        <I.AlertCirc size={18} />
        <span className="rail-tip">Help · ?</span>
      </button>
    </div>
  );
}
export { Sparkline, Rail, Topbar, StatusBar };

/* ── Topbar ──────────────────────────────────────────────────────── */
function Topbar({ crumbs = [], onPalette, user, timeRange, timeRangeLabel, onTimeRange, onSignOut, onNavigate, onOpenInspector, onSync, theme, onToggleTheme }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const [open, setOpen] = useState(null); // 'user' | 'notif' | 'tenant' | 'range' | null
  const [syncing, setSyncing] = useState(false);

  const handleSync = async () => {
    if (syncing) return;
    setSyncing(true);
    const n = LFPM.firewalls?.length || 0;
    window.toast('Sync started', { kind: 'info', sub: `pulling rules from ${n} firewall${n === 1 ? '' : 's'}…` });
    try {
      const results = await Promise.allSettled(
        (LFPM.firewalls || []).map(fw => triggerRulesSync(fw.id))
      );
      const ok = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.length - ok;
      if (typeof onSync === 'function') await onSync();
      if (ok === 0) {
        window.toast('Sync failed', { kind: 'crit', sub: 'backend unreachable — no devices synced' });
      } else {
        window.toast('Sync complete', {
          kind: failed > 0 ? 'warn' : 'ok',
          sub: `${ok}/${results.length} devices · ${LFPM.policies?.length || 0} rules${failed > 0 ? ` · ${failed} failed` : ''}`,
        });
      }
    } catch (err) {
      window.toast('Sync failed', { kind: 'crit', sub: String(err.message || err) });
    } finally {
      setSyncing(false);
    }
  };

  const trLabel = timeRangeLabel || ({
    '1h':'last 1h', '6h':'last 6h', '24h':'last 24h', '7d':'last 7d', '30d':'last 30d', '90d':'last 90d',
  })[timeRange] || 'last 24h';

  return (
    <header className="topbar" style={{ position: 'relative' }}>
      <button className="tb-tenant" onClick={() => setOpen(open === 'tenant' ? null : 'tenant')} title="Switch organization">
        <div className="tb-tenant-mark">N</div>
        <div className="col" style={{ lineHeight: 1.15 }}>
          <span className="tb-tenant-name">NovaTech Industries</span>
          <span className="tb-tenant-env">prod · eu-west-1</span>
        </div>
        <I.Chevron size={12} />
      </button>

      <div className="tb-divider" />

      <div className="tb-crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={i}>
            <span className={i === crumbs.length - 1 ? 'tb-crumb-active' : ''}>{c}</span>
            {i < crumbs.length - 1 && <I.ChevronR className="tb-crumb-sep" size={11} />}
          </React.Fragment>
        ))}
      </div>

      <div className="tb-spacer" />

      <button className="tb-kbar" onClick={onPalette}>
        <I.Search size={13} />
        <span>Search rules, firewalls, CVEs, hosts…</span>
        <div className="tb-kbar-spacer" />
        <span className="kbd">⌘K</span>
      </button>

      <button className="tb-range" onClick={() => setOpen(open === 'range' ? null : 'range')} title="Time range">
        <I.Calendar size={13} />
        <span>{trLabel}</span>
        <I.Chevron size={11} />
      </button>

      <button
        className="tb-iconbtn"
        title="Notifications · 3 unread"
        onClick={() => setOpen(open === 'notif' ? null : 'notif')}
      >
        <I.Bell size={15} />
        <span className="dot" />
      </button>

      <button
        className="tb-iconbtn"
        title={syncing ? 'Syncing…' : 'Sync data now'}
        onClick={handleSync}
        style={syncing ? { color: 'var(--accent)' } : {}}
      >
        <I.Refresh size={14} style={syncing ? { animation: 'spin 0.8s linear infinite' } : {}} />
      </button>

      <button
        className="tb-iconbtn"
        title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        aria-label={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        onClick={onToggleTheme}
      >
        {theme === 'dark'
          ? <I.Sun size={15} stroke={1.7} />
          : <I.Moon size={15} stroke={1.7} />}
      </button>

      <div className="tb-divider" />

      <button className="tb-user" onClick={() => setOpen(open === 'user' ? null : 'user')}>
        <div className="tb-avatar">{user?.avatar || '?'}</div>
        <div className="col" style={{ lineHeight: 1.15 }}>
          <span className="tb-username">{user?.name || '—'}</span>
          <span style={{ fontSize: 10.5, color: 'var(--fg-3)' }}>{user?.role}</span>
        </div>
        <I.Chevron size={12} style={{ color: 'var(--fg-3)' }} />
      </button>

      {open === 'tenant' && <window.TenantMenu onClose={() => setOpen(null)} />}
      {open === 'range'  && <window.TimeRangeMenu current={timeRange} onPick={onTimeRange} onClose={() => setOpen(null)} />}
      {open === 'notif'  && <window.NotifMenu onClose={() => setOpen(null)} onOpenInspector={onOpenInspector} onNavigate={onNavigate} />}
      {open === 'user'   && <window.UserMenu user={user} onClose={() => setOpen(null)} onNavigate={onNavigate} onSignOut={onSignOut} theme={theme} onToggleTheme={onToggleTheme} />}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </header>
  );
}

/* ── Status bar (terminal-style bottom strip) ───────────────────── */
function formatLastSync(iso) {
  if (!iso) return 'no scans yet';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'no scans yet';
  const utc = d.toISOString().slice(11, 19) + ' UTC';
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return `${utc} · just now`;
  if (mins < 60) return `${utc} · ${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${utc} · ${hrs}h ago`;
  return `${utc} · ${Math.floor(hrs / 24)}d ago`;
}

function StatusBar({ queue = 0, region = 'soc-eu-west-1', env = 'prod', user, dataVersion }) {
  const { data: LFPM } = useLFPM();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const i = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(i);
  }, []);
  const utc = now.toISOString().slice(11, 19) + ' UTC';
  const lastSync = formatLastSync(LFPM.meta?.lastScanAt);
  void dataVersion;
  return (
    <footer className="statusbar">
      <div className="sb-seg">
        <span className="sb-dot" />
        <span className="value">connected</span>
      </div>
      <div className="sb-seg">
        <span className="label">region</span>
        <span className="value">{region}</span>
      </div>
      <div className="sb-seg">
        <span className="label">env</span>
        <span className="value">{env}</span>
      </div>
      <div className="sb-seg">
        <span className="label">last sync</span>
        <span className="value">{lastSync}</span>
      </div>
      <div className="sb-seg">
        <span className="label">queue</span>
        <span className="value">{queue}</span>
      </div>
      <div className="sb-spacer" />
      <div className="sb-seg">
        <span className="label">user</span>
        <span className="value">{user?.email?.split('@')[0] || 'guest'}@lumina-fpm</span>
      </div>
      <div className="sb-seg">
        <span className="label">role</span>
        <span className="value">{user?.role || '—'}</span>
      </div>
      <div className="sb-seg">
        <span className="label">build</span>
        <span className="value">v2.4.1+8a91c2</span>
      </div>
      <div className="sb-seg">
        <span className="value">{utc}</span>
      </div>
    </footer>
  );
}
