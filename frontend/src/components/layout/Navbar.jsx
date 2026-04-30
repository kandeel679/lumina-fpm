import { useState, useRef, useEffect } from 'react';
import { Search, Bell, RefreshCw, User, LogOut, RefreshCcw, ChevronDown, Shield, Clock, Sun, Moon } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { mockUsers } from '../../data/mockUsers';

const pageTitles = {
  '/':              'Dashboard',
  '/topology':      'Network Topology',
  '/policy-audit':  'Policy Audit',
  '/threats':       'Threat Intelligence',
  '/settings':      'Settings',
};

const roleColors = {
  Admin:       { bg: 'rgba(6,182,212,0.12)',   border: 'rgba(6,182,212,0.3)',   color: '#22d3ee' },
  Analyst:     { bg: 'rgba(139,92,246,0.12)',  border: 'rgba(139,92,246,0.3)',  color: '#a78bfa' },
  'Read-Only': { bg: 'rgba(249,115,22,0.12)',  border: 'rgba(249,115,22,0.3)',  color: '#fb923c' },
};

function RoleBadge({ role }) {
  const s = roleColors[role] ?? roleColors['Read-Only'];
  return (
    <span style={{
      fontSize: '0.65rem', fontWeight: 600, padding: '0.12rem 0.45rem',
      borderRadius: 4, background: s.bg, border: `1px solid ${s.border}`, color: s.color,
      letterSpacing: '0.04em', textTransform: 'uppercase', flexShrink: 0,
    }}>
      {role}
    </span>
  );
}

export default function Navbar() {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { user, logout, switchAccount } = useAuth();
  const { theme, toggleTheme } = useTheme();

  const [searchVal, setSearchVal]       = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [switchOpen, setSwitchOpen]     = useState(false);
  const [loggingOut, setLoggingOut]     = useState(false);

  const dropdownRef = useRef(null);

  const title = pageTitles[location.pathname] ?? 'Lumina FPM';
  const now = new Date().toLocaleDateString('en-US', {
    weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
  });

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
        setSwitchOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutside);
    return () => document.removeEventListener('mousedown', handleOutside);
  }, []);

  const handleLogout = async () => {
    setLoggingOut(true);
    setDropdownOpen(false);
    await new Promise(r => setTimeout(r, 400));
    logout();
    navigate('/login', { replace: true });
  };

  const handleSwitch = (targetUser) => {
    switchAccount(targetUser);
    setDropdownOpen(false);
    setSwitchOpen(false);
  };

  const otherUsers = mockUsers.filter(u => u.id !== user?.id);

  const loginAt = user?.loginAt
    ? new Date(user.loginAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
    : null;

  return (
    <header className="navbar">
      <div className="navbar-title">
        {title}
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: '0.75rem', fontWeight: 400 }}>
          {now}
        </span>
      </div>

      {/* Search */}
      <div className="navbar-search">
        <Search size={14} color="var(--text-muted)" />
        <input
          id="navbar-search"
          placeholder="Search policies, CVEs, firewalls…"
          value={searchVal}
          onChange={e => setSearchVal(e.target.value)}
        />
      </div>

      {/* Refresh */}
      <button className="icon-btn" title="Sync data" id="navbar-refresh-btn">
        <RefreshCw size={16} />
      </button>

      {/* Theme Toggle */}
      <button className="icon-btn" title="Toggle theme" onClick={toggleTheme}>
        {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
      </button>

      {/* Notifications */}
      <button className="icon-btn" title="Notifications" id="navbar-notif-btn">
        <Bell size={16} />
        <span className="notif-badge" />
      </button>

      {/* Live indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span className="pulse-dot" />
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Live</span>
      </div>

      {/* ── Profile dropdown ───────────────────────────── */}
      <div ref={dropdownRef} style={{ position: 'relative' }}>
        {/* Avatar trigger */}
        <button
          id="navbar-avatar-btn"
          onClick={() => { setDropdownOpen(o => !o); setSwitchOpen(false); }}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.5rem',
            background: dropdownOpen ? 'var(--bg-surface)' : 'transparent',
            border: `1px solid ${dropdownOpen ? 'var(--border-bright)' : 'transparent'}`,
            borderRadius: 8, padding: '0.3rem 0.5rem 0.3rem 0.35rem',
            cursor: 'pointer', transition: 'all 0.15s',
          }}
          onMouseEnter={e => {
            if (!dropdownOpen) e.currentTarget.style.background = 'var(--bg-surface)';
          }}
          onMouseLeave={e => {
            if (!dropdownOpen) e.currentTarget.style.background = 'transparent';
          }}
          title="Account menu"
        >
          <div style={{
            width: 32, height: 32, borderRadius: '50%',
            background: user?.avatarColor ?? 'linear-gradient(135deg, #06b6d4, #6366f1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '0.72rem', fontWeight: 700, color: '#fff',
            border: '2px solid var(--border-bright)', flexShrink: 0,
            transition: 'border-color 0.15s',
            boxShadow: dropdownOpen ? '0 0 0 2px rgba(6,182,212,0.3)' : 'none',
          }}>
            {user?.avatar ?? '?'}
          </div>
          <div style={{ textAlign: 'left', lineHeight: 1.25, display: 'flex', flexDirection: 'column', paddingRight: '0.5rem' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {user?.name ?? 'User'}
            </span>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
              Logged in as: <strong style={{ color: 'var(--accent)', fontWeight: 600 }}>{user?.role ?? 'Guest'}</strong>
            </span>
          </div>
          <ChevronDown
            size={14}
            color="var(--text-muted)"
            style={{ transform: dropdownOpen ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s' }}
          />
        </button>

        {/* Dropdown panel */}
        {dropdownOpen && (
          <div
            id="profile-dropdown"
            style={{
              position: 'absolute', right: 0, top: 'calc(100% + 8px)',
              width: 260, zIndex: 200,
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-bright)',
              borderRadius: 12,
              boxShadow: '0 16px 48px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.04)',
              overflow: 'hidden',
              animation: 'dropdownIn 0.18s ease',
            }}
          >
            {/* User info header */}
            <div style={{
              padding: '1rem 1rem 0.75rem',
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg-surface)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }}>
                <div style={{
                  width: 40, height: 40, borderRadius: '50%',
                  background: user?.avatarColor ?? 'linear-gradient(135deg, #06b6d4, #6366f1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '0.85rem', fontWeight: 700, color: '#fff',
                  border: '2px solid var(--border-bright)', flexShrink: 0,
                }}>
                  {user?.avatar ?? '?'}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {user?.name}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {user?.email}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <RoleBadge role={user?.role} />
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{user?.department}</span>
              </div>
              {loginAt && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.4rem' }}>
                  <Clock size={11} color="var(--text-muted)" />
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Session started {loginAt}</span>
                </div>
              )}
            </div>

            {/* Menu items */}
            <div style={{ padding: '0.4rem' }}>
              {/* Profile */}
              <DropdownItem
                icon={<User size={15} />}
                label="Profile"
                sub="View your account details"
                onClick={() => { navigate('/settings'); setDropdownOpen(false); }}
                id="dropdown-profile"
              />

              {/* Switch Account */}
              <div style={{ position: 'relative' }}>
                <DropdownItem
                  icon={<RefreshCcw size={15} />}
                  label="Switch Account"
                  sub={`${otherUsers.length} other account${otherUsers.length !== 1 ? 's' : ''}`}
                  onClick={() => setSwitchOpen(o => !o)}
                  id="dropdown-switch"
                  hasArrow
                  arrowOpen={switchOpen}
                />

                {/* Switch sub-panel */}
                {switchOpen && (
                  <div style={{
                    marginTop: 2, borderRadius: 8,
                    background: 'var(--bg-card)', border: '1px solid var(--border)',
                    overflow: 'hidden', animation: 'dropdownIn 0.15s ease',
                  }}>
                    {otherUsers.map(u => (
                      <button
                        key={u.id}
                        id={`switch-to-${u.id}`}
                        onClick={() => handleSwitch(u)}
                        style={{
                          display: 'flex', alignItems: 'center', gap: '0.6rem',
                          width: '100%', padding: '0.55rem 0.75rem',
                          background: 'transparent', border: 'none', cursor: 'pointer',
                          transition: 'background 0.12s', textAlign: 'left',
                          borderBottom: '1px solid var(--border)',
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-surface)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <div style={{
                          width: 28, height: 28, borderRadius: '50%',
                          background: u.avatarColor,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: '0.65rem', fontWeight: 700, color: '#fff', flexShrink: 0,
                        }}>
                          {u.avatar}
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {u.name}
                          </div>
                          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{u.department}</div>
                        </div>
                        <RoleBadge role={u.role} />
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div style={{ height: 1, background: 'var(--border)', margin: '0.25rem 0' }} />

              {/* Logout */}
              <DropdownItem
                icon={<LogOut size={15} />}
                label={loggingOut ? 'Signing out…' : 'Sign Out'}
                sub="End your current session"
                onClick={handleLogout}
                id="dropdown-logout"
                danger
                disabled={loggingOut}
              />
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes dropdownIn {
          from { opacity: 0; transform: translateY(-6px) scale(0.98); }
          to   { opacity: 1; transform: translateY(0)   scale(1); }
        }
      `}</style>
    </header>
  );
}

/* ── Reusable dropdown menu item ─────────────────────── */
function DropdownItem({ icon, label, sub, onClick, id, danger, disabled, hasArrow, arrowOpen }) {
  const [hovered, setHovered] = useState(false);
  return (
    <button
      id={id}
      onClick={onClick}
      disabled={disabled}
      style={{
        display: 'flex', alignItems: 'center', gap: '0.6rem',
        width: '100%', padding: '0.55rem 0.65rem',
        background: hovered
          ? danger ? 'rgba(239,68,68,0.08)' : 'var(--bg-surface)'
          : 'transparent',
        border: 'none', borderRadius: 7, cursor: disabled ? 'not-allowed' : 'pointer',
        transition: 'background 0.12s', textAlign: 'left', opacity: disabled ? 0.6 : 1,
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span style={{ color: danger ? (hovered ? '#f87171' : '#ef4444') : (hovered ? 'var(--accent)' : 'var(--text-secondary)'), transition: 'color 0.12s', flexShrink: 0 }}>
        {icon}
      </span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '0.82rem', fontWeight: 600, color: danger ? (hovered ? '#f87171' : '#ef4444') : 'var(--text-primary)', lineHeight: 1.2 }}>
          {label}
        </div>
        {sub && (
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>{sub}</div>
        )}
      </div>
      {hasArrow && (
        <ChevronDown
          size={13}
          color="var(--text-muted)"
          style={{ transform: arrowOpen ? 'rotate(180deg)' : 'rotate(0)', transition: 'transform 0.2s', flexShrink: 0 }}
        />
      )}
    </button>
  );
}
