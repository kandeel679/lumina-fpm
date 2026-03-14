export function ThreatIntel() {
    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 h-full flex flex-col">
            <div className="mb-8">
                <h1 className="text-2xl font-bold mb-1">Threat Intelligence Feed</h1>
                <p className="text-text-secondary text-sm">Real-time threat streams grouped by vendor ecosystem.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 flex-1">
                {/* Palo Alto Stream */}
                <div className="space-y-4">
                    <h2 className="text-primary text-sm font-semibold flex items-center gap-2 mb-2">
                        <span className="w-2 h-2 rounded-full bg-primary inline-block shadow-[0_0_8px_#00d2ff]"></span>
                        Palo Alto Networks
                    </h2>

                    <div className="card hover:border-warning/50 transition-colors border-l-2 border-l-warning cursor-pointer">
                        <div className="flex justify-between items-start mb-2">
                            <h3 className="font-bold text-white text-sm">Credentials for PA-Firewall-01 leaked</h3>
                            <span className="text-[10px] uppercase tracking-wider text-warning font-semibold border border-warning/30 bg-warning/10 px-2 py-0.5 rounded">High</span>
                        </div>
                        <div className="text-xs text-text-muted mb-3">Pastebin • 4 hours ago</div>
                        <p className="text-xs text-text-secondary mb-4 leading-relaxed">
                            A dump of 500+ VPN credentials includes admin access for an IP matching PA-Firewall-01.
                        </p>
                        <div className="inline-block text-[10px] text-white px-2 py-1 bg-surface border border-border rounded font-mono">
                            PA-Firewall-01
                        </div>
                    </div>

                    <div className="card hover:border-warning/50 transition-colors border-l-2 border-l-warning cursor-pointer">
                        <div className="flex justify-between items-start mb-2">
                            <h3 className="font-bold text-white text-sm">Palo Alto GlobalProtect CVE-2024-0012</h3>
                            <span className="text-[10px] uppercase tracking-wider text-yellow-400 font-semibold border border-yellow-400/30 bg-yellow-400/10 px-2 py-0.5 rounded">Medium</span>
                        </div>
                        <div className="text-xs text-text-muted mb-3">NIST NVD • 2 days ago</div>
                        <p className="text-xs text-text-secondary mb-4 leading-relaxed">
                            New vulnerability in GlobalProtect app causing potential privilege escalation. Patch 10.1.9 recommended.
                        </p>
                        <div className="inline-block text-[10px] text-white px-2 py-1 bg-surface border border-border rounded font-mono">
                            PA-Firewall-03
                        </div>
                    </div>
                </div>

                {/* Fortinet Stream */}
                <div className="space-y-4">
                    <h2 className="text-purple-400 text-sm font-semibold flex items-center gap-2 mb-2">
                        <span className="w-2 h-2 rounded-full bg-purple-500 inline-block shadow-[0_0_8px_#a855f7]"></span>
                        Fortinet
                    </h2>

                    <div className="card hover:border-danger/50 transition-colors border-l-2 border-l-danger cursor-pointer relative overflow-hidden">
                        <div className="absolute top-0 right-0 w-16 h-16 bg-danger/10 blur-xl rounded-full pointer-events-none"></div>
                        <div className="flex justify-between items-start mb-2 relative">
                            <h3 className="font-bold text-white text-sm">LockBit Ransomware targeting FortiOS v7.2</h3>
                            <span className="text-[10px] uppercase tracking-wider text-white font-bold border border-danger bg-danger px-2 py-0.5 rounded shadow-[0_0_10px_rgba(255,77,79,0.5)]">CRITICAL</span>
                        </div>
                        <div className="text-xs text-text-muted mb-3 relative">Dark Web Forum A1 • 1 hour ago</div>
                        <p className="text-xs text-text-secondary mb-4 leading-relaxed relative">
                            Active discussions on XSS forum regarding a new zero-day RCE exploit specifically for FortiOS 7.2.0. Actors are selling a weaponized payload.
                        </p>
                        <div className="inline-block text-[10px] text-white px-2 py-1 bg-surface border border-border rounded font-mono relative">
                            FortiGate-01
                        </div>
                    </div>

                    <div className="card hover:border-warning/50 transition-colors border-l-2 border-l-warning cursor-pointer">
                        <div className="flex justify-between items-start mb-2">
                            <h3 className="font-bold text-white text-sm">Fortinet FG-IR-23-001 Buffer Overflow</h3>
                            <span className="text-[10px] uppercase tracking-wider text-warning font-semibold border border-warning/30 bg-warning/10 px-2 py-0.5 rounded">High</span>
                        </div>
                        <div className="text-xs text-text-muted mb-3">FortiGuard Labs • 5 hours ago</div>
                        <p className="text-xs text-text-secondary mb-4 leading-relaxed">
                            Heap-based buffer overflow in FortiOS SSL-VPN functionality. Allows unauthenticated remote code execution.
                        </p>
                        <div className="inline-block text-[10px] text-white px-2 py-1 bg-surface border border-border rounded font-mono">
                            FortiGate-02
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
