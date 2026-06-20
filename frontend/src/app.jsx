/* ─────────────────────────────────────────────────────────────────
 * App root — auth gate, nav state, palette + inspector orchestration
 * ───────────────────────────────────────────────────────────────── */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useLFPM } from './context/LFPMContext';
import { Icons } from './icons';
import { ToastHost } from './menus';
import { Rail, Topbar, StatusBar } from './shell';
import { CommandPalette } from './palette';
import { Inspector } from './inspector';
import { Login } from './login';
import { Dashboard } from './dashboard';
import { PolicyAudit } from './audit';
import { Topology } from './topology';
import { ThreatIntelligence } from './threats';
import { Settings } from './settings';

/* Bump this when login flow changes so existing sessions are invalidated. */
const LFPM_SESSION_VERSION = 2;

/* Theme: SOC platforms default to dark; persisted to localStorage so the
 * preference survives refresh AND applies across every page (login + app). */
const LFPM_THEME_KEY = 'lumina_theme';
function readTheme() {
  try {
    const v = localStorage.getItem(LFPM_THEME_KEY);
    return v === 'light' ? 'light' : 'dark';
  } catch { return 'dark'; }
}
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
}
/* Apply ASAP — before React mounts — so the login screen also opens in the
 * correct theme and there is no dark→light flash on refresh. */
applyTheme(readTheme());

/* ===============================================================
 *  Hash-routed navigation
 * =============================================================== */
const VALID_PAGES = new Set(['dashboard','audit','topology','threats','settings']);

function parseHash() {
  const raw = (window.location.hash || '').replace(/^#\/?/, '');
  if (!raw) return { page: null, intent: null };
  const [path, qs] = raw.split('?');
  const page = VALID_PAGES.has(path) ? path : null;
  if (!qs) return { page, intent: null };
  const intent = {};
  new URLSearchParams(qs).forEach((v, k) => { intent[k] = v; });
  return { page, intent: Object.keys(intent).length ? intent : null };
}
function makeHash(page, intent) {
  if (!intent || !Object.keys(intent).length) return `#${page}`;
  const qs = new URLSearchParams(intent).toString();
  return `#${page}?${qs}`;
}

export default function App() {
  const { data, loading, error, refreshData } = useLFPM();

  const [user, setUser] = useState(() => {
    try {
      const raw = sessionStorage.getItem('lumina_demo_user');
      const ver = +sessionStorage.getItem('lumina_session_ver') || 0;
      if (ver !== LFPM_SESSION_VERSION) {
        sessionStorage.removeItem('lumina_demo_user');
        return null;
      }
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  });
  const [page, setPage] = useState(() => {
    const fromHash = parseHash().page;
    return fromHash || sessionStorage.getItem('lumina_page') || 'dashboard';
  });
  const [intent, setIntent] = useState(() => parseHash().intent);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [inspector, setInspector]     = useState(null);
  const [timeRange, setTimeRange]     = useState('24h');
  const [timeRangeLabel, setTimeRangeLabel] = useState(null);
  const [theme, setTheme]             = useState(readTheme);

  /* Persist theme + apply to <html> on every change */
  useEffect(() => {
    applyTheme(theme);
    try { localStorage.setItem(LFPM_THEME_KEY, theme); } catch {}
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme(t => {
      const next = t === 'dark' ? 'light' : 'dark';
      window.toast?.(next === 'dark' ? 'Dark mode' : 'Light mode', {
        kind: 'info',
        sub: next === 'dark' ? 'SOC-friendly low-glare palette' : 'Enterprise light theme',
        duration: 2000,
      });
      return next;
    });
  }, []);

  /* Persist nav state */
  useEffect(() => { sessionStorage.setItem('lumina_page', page); }, [page]);

  /* Mirror page + intent into the URL hash */
  useEffect(() => {
    const desired = makeHash(page, intent);
    if (window.location.hash !== desired) {
      window.history.replaceState(null, '', desired);
    }
  }, [page, intent]);

  /* React to manual hash changes (back/forward, paste link). */
  useEffect(() => {
    const onHash = () => {
      const { page: p, intent: i } = parseHash();
      if (p && p !== page) setPage(p);
      setIntent(i);
    };
    window.addEventListener('hashchange', onHash);
    window.addEventListener('popstate',  onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
      window.removeEventListener('popstate',  onHash);
    };
  }, [page]);

  /* Single navigation entry-point */
  const goTo = useCallback((nextPage, params = null) => {
    if (!VALID_PAGES.has(nextPage)) return;
    setInspector(null);
    setPaletteOpen(false);
    setPage(nextPage);
    setIntent(params && Object.keys(params).length ? params : null);
  }, []);

  /* Persist user */
  useEffect(() => {
    if (user) {
      sessionStorage.setItem('lumina_demo_user', JSON.stringify(user));
      sessionStorage.setItem('lumina_session_ver', String(LFPM_SESSION_VERSION));
    } else {
      sessionStorage.removeItem('lumina_demo_user');
    }
  }, [user]);

  /* Keyboard: ⌘K opens palette */
  useEffect(() => {
    const handler = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(true);
      }
      if (e.key === '/' &&
          document.activeElement?.tagName !== 'INPUT' &&
          document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  /* Stats for badge count on Audit nav */
  const criticalCount = useMemo(() =>
    data.policies.filter(p => p.status !== 'clean').length, [data.policies]);

  const openInspector  = useCallback((payload) => setInspector(payload), []);
  const closeInspector = useCallback(() => setInspector(null), []);

  /* Sign-out handler */
  const handleSignOut = useCallback(() => {
    const name = user?.name?.split(' ')[0] || 'user';
    window.toast(`Signed out · see you, ${name}`, { kind: 'info', sub: 'session ended · jwt revoked' });
    setInspector(null);
    setPaletteOpen(false);
    setIntent(null);
    setPage('dashboard');
    setUser(null);
  }, [user]);

  /* Login handler */
  const handleLogin = useCallback((u) => {
    setUser(u);
    setTimeout(() => {
      const greeting = u.role === 'viewer'
        ? 'Read-only access · audits & dashboards'
        : u.role === 'analyst'
          ? 'Analyst role · audit + threat hunter unlocked'
          : 'Admin role · full platform access';
      window.toast(`Welcome back, ${u.name.split(' ')[0]}`, {
        kind: 'ok',
        sub: greeting,
        duration: 4500,
      });
    }, 250);
  }, []);

  /* Time-range handler */
  const handleTimeRange = useCallback((id, customLabel) => {
    setTimeRange(id);
    setTimeRangeLabel(customLabel || null);
    const label = customLabel || ({
      '1h':'last hour', '6h':'last 6 hours', '24h':'last 24 hours',
      '7d':'last 7 days', '30d':'last 30 days', '90d':'last 90 days',
    })[id] || id;
    window.toast(`Time range: ${label}`, { kind: 'info', sub: 'metrics and charts refreshed' });
  }, []);

  /* Not signed in → login */
  if (!user) {
    return (
      <>
        <Login onLogin={handleLogin} theme={theme} onToggleTheme={toggleTheme} />
        <ToastHost />
      </>
    );
  }

  /* Initialization Loader */
  if (loading) {
    return (
      <div className="login-wrap" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100vh', gap: '20px', background: 'var(--bg-0)' }}>
        <div className="term-log" style={{ width: '450px', padding: '24px', border: '1px solid var(--bd-1)', borderRadius: '6px', background: 'var(--bg-1)', boxShadow: '0 20px 40px rgba(0,0,0,0.4)', fontFamily: 'var(--f-mono)' }}>
          <div className="term-line cmd" style={{ color: 'var(--accent)', marginBottom: 8, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: 'var(--accent)', animation: 'pulse 1.5s infinite' }} />
            Initializing LuminaFPM Client...
          </div>
          <div className="term-line" style={{ color: 'var(--fg-2)', fontSize: 12, marginBottom: 4 }}>[SYS] Connecting to FastAPI backend service...</div>
          <div className="term-line info" style={{ color: 'var(--fg-3)', fontSize: 12, marginBottom: 4 }}>[DB] Synchronizing devices, rules, objects & anomalies from PostgreSQL...</div>
          <div className="term-line ok" style={{ color: 'var(--sev-safe)', fontSize: 12 }}>[OK] Ready. Orchestrating state...</div>
        </div>
      </div>
    );
  }

  /* Crumb path for current page */
  const crumbs = ({
    dashboard: ['Overview'],
    audit:     ['Policy', 'Audit'],
    topology:  ['Topology'],
    threats:   ['Threat Intelligence'],
    settings:  ['Settings'],
  })[page] || [];

  return (
    <div className="shell">
      <div className="shell-rail">
        <Rail current={page} onNav={goTo} criticalCount={criticalCount} />
      </div>
      <div className="shell-top">
        <Topbar
          crumbs={crumbs}
          onPalette={() => setPaletteOpen(true)}
          user={user}
          timeRange={timeRange}
          onTimeRange={handleTimeRange}
          onSignOut={handleSignOut}
          onNavigate={goTo}
          onOpenInspector={openInspector}
          onSync={refreshData}
          theme={theme}
          onToggleTheme={toggleTheme}
          timeRangeLabel={timeRangeLabel}
        />
      </div>
      <main className="shell-main">
        {page === 'dashboard' && <Dashboard            user={user} openInspector={openInspector} goTo={goTo} timeRange={timeRange} onTimeRange={setTimeRange} refreshData={refreshData} />}
        {page === 'audit'     && <PolicyAudit          user={user} openInspector={openInspector} goTo={goTo} intent={intent} selectedRuleId={inspector?.kind === 'rule' ? inspector.data.id : null} refreshData={refreshData} />}
        {page === 'topology'  && <Topology             user={user} openInspector={openInspector} goTo={goTo} intent={intent} />}
        {page === 'threats'   && <ThreatIntelligence   user={user} openInspector={openInspector} goTo={goTo} intent={intent} refreshData={refreshData} />}
        {page === 'settings'  && <Settings             user={user} openInspector={openInspector} goTo={goTo} refreshData={refreshData} />}
      </main>
      <div className="shell-status">
        <StatusBar queue={0} user={user} dataVersion={0} />
      </div>

      <Inspector open={inspector} onClose={closeInspector} />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNavigate={(p, params) => goTo(p, params)}
        onOpenInspector={openInspector}
      />

      <ToastHost />
    </div>
  );
}
