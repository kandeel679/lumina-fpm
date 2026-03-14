import { Search, Bell } from 'lucide-react';

export function TopNav() {
    return (
        <header className="h-16 border-b border-border flex items-center justify-between px-6 bg-background">
            <div className="flex-1 max-w-xl">
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" size={18} />
                    <input
                        type="text"
                        placeholder="Search policies, threats, or devices..."
                        className="w-full bg-surface border border-border text-sm rounded-full py-2 pl-10 pr-4 text-text-primary focus:outline-none focus:border-primary transition-colors placeholder-text-muted"
                    />
                </div>
            </div>

            <div className="flex items-center gap-4">
                <button className="relative text-text-secondary hover:text-white transition-colors">
                    <Bell size={20} />
                    <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-danger rounded-full border-2 border-background"></span>
                </button>
            </div>
        </header>
    );
}
