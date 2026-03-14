import { Home, Share2, FileText, ShieldAlert, Settings, Flame } from 'lucide-react';
import { NavLink } from 'react-router-dom';

const navLinks = [
    { name: 'Dashboard', path: '/', icon: <Home size={20} /> },
    { name: 'Anomaly Detection', path: '/anomaly-detection', icon: <Share2 size={20} className="rotate-90" /> },
    { name: 'Topology', path: '/topology', icon: <Share2 size={20} /> },
    { name: 'Policy Audit', path: '/audit', icon: <FileText size={20} /> },
    { name: 'Threat Intel', path: '/threats', icon: <ShieldAlert size={20} /> },
    { name: 'Settings', path: '/settings', icon: <Settings size={20} /> },
];

export function Sidebar() {
    return (
        <aside className="w-64 border-r border-border bg-background flex flex-col h-full flex-shrink-0">
            {/* Brand area */}
            <div className="flex items-center gap-3 px-6 h-16 border-b border-border text-primary font-bold tracking-wider text-xl">
                <Flame className="text-primary" size={24} />
                LUMINA<span className="text-xs text-text-secondary mt-1 font-normal select-none">FPM</span>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-4 py-8 flex flex-col gap-2 overflow-y-auto">
                {navLinks.map((link) => (
                    <NavLink
                        key={link.name}
                        to={link.path}
                        className={({ isActive }) =>
                            `flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${isActive
                                ? 'bg-surface text-primary border-l-2 border-primary'
                                : 'text-text-secondary hover:bg-surface hover:text-white'
                            }`
                        }
                    >
                        {link.icon}
                        {link.name}
                    </NavLink>
                ))}
            </nav>
        </aside>
    );
}
