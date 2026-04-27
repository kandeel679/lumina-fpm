import { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Network, ShieldCheck, Swords,
  Settings, ChevronLeft, ChevronRight, ShieldAlert,
} from 'lucide-react';

const navItems = [
  { label: 'Dashboard',          icon: LayoutDashboard, to: '/' },
  { label: 'Topology',           icon: Network,         to: '/topology' },
  { label: 'Policy Audit',       icon: ShieldCheck,     to: '/policy-audit' },
  { label: 'Threat Intelligence',icon: Swords,          to: '/threats' },
  { label: 'Settings',           icon: Settings,        to: '/settings' },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">
          <ShieldAlert size={18} color="#fff" />
        </div>
        <div className="sidebar-logo-text">
          <h1>Lumina FPM</h1>
          <p>Firewall Policy Mgr</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        <span className="nav-section-label">Navigation</span>
        {navItems.map(({ label, icon: Icon, to }) => {
          const isActive = to === '/'
            ? location.pathname === '/'
            : location.pathname.startsWith(to);
          return (
            <NavLink
              key={to}
              to={to}
              className={`nav-item ${isActive ? 'active' : ''}`}
              title={collapsed ? label : undefined}
            >
              <Icon size={18} className="nav-item-icon" />
              <span className="nav-item-label">{label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="sidebar-footer">
        <button
          className="nav-item"
          style={{ width: '100%', cursor: 'pointer', background: 'none', border: 'none' }}
          onClick={() => setCollapsed(c => !c)}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed
            ? <ChevronRight size={18} className="nav-item-icon" />
            : <><ChevronLeft size={18} className="nav-item-icon" /><span className="nav-item-label">Collapse</span></>
          }
        </button>
      </div>
    </aside>
  );
}
