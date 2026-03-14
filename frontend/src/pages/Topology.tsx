import { AlertTriangle } from 'lucide-react';

export function Topology() {
    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6 h-full flex flex-col">
            <div className="flex justify-between items-center mb-4">
                <h1 className="text-xl font-bold">Network Topology</h1>
                <button className="px-3 py-1.5 border border-primary text-primary rounded text-xs hover:bg-primary/10 transition-colors">
                    Refresh Layout
                </button>
            </div>

            <div className="flex-1 card flex p-0 overflow-hidden relative border-border">
                {/* Mockup Canvas */}
                <div className="flex-1 bg-[#05080f] relative flex items-center justify-center overflow-hidden">
                    {/* Mock Node Connections Background */}
                    <div className="absolute inset-0 opacity-20 pointer-events-none" style={{
                        backgroundImage: 'radial-gradient(circle at 2px 2px, #333 1px, transparent 0)',
                        backgroundSize: '24px 24px'
                    }}></div>

                    {/* Example Nodes Layout simulating the screenshot */}
                    <div className="relative w-full max-w-2xl h-[400px]">
                        {/* Palo Alto Group Box */}
                        <div className="absolute top-4 left-4 right-4 h-48 border border-[#8b5cf6]/30 bg-[#8b5cf6]/5 rounded-lg border-dashed">
                            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-background px-2 text-[#8b5cf6] text-xs font-bold tracking-widest">
                                PALO ALTO NETWORKS
                            </div>
                        </div>

                        {/* Fortinet Group Box */}
                        <div className="absolute bottom-4 left-24 right-24 h-40 border border-[#b11f26]/30 bg-[#b11f26]/5 rounded-lg border-dashed">
                            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-background px-2 text-[#b11f26] text-xs font-bold tracking-widest">
                                FORTINET
                            </div>
                        </div>

                        {/* Nodes */}
                        <div className="absolute top-12 left-[20%] w-16 h-16 rounded-full border-4 border-[#00d2ff] bg-surface flex items-center justify-center"></div>
                        <div className="absolute top-32 left-[20%] -translate-y-4 -translate-x-1/2 text-xs text-[#00d2ff]">PA-Firewall-03</div>

                        <div className="absolute top-16 left-[50%] w-20 h-20 rounded-full border-4 border-[#faad14] bg-[#faad14]/20 flex items-center justify-center shadow-[0_0_20px_rgba(250,173,20,0.4)]"></div>
                        <div className="absolute top-40 left-[50%] -translate-y-4 -translate-x-1/2 text-xs text-[#faad14]">PA-Firewall-01</div>

                        <div className="absolute top-24 left-[80%] w-14 h-14 rounded-full border-4 border-[#00d2ff] bg-surface flex items-center justify-center"></div>
                        <div className="absolute top-40 left-[80%] -translate-y-2 -translate-x-1/2 text-xs text-[#00d2ff]">PA-Firewall-02</div>

                        {/* Bottom Row */}
                        <div className="absolute bottom-12 left-[30%] w-16 h-16 rounded-full border-4 border-[#faad14] bg-surface flex items-center justify-center"></div>
                        <div className="absolute bottom-4 left-[30%] -translate-x-1/2 text-xs text-[#faad14]">FortiGate-03</div>

                        <div className="absolute bottom-16 left-[50%] w-16 h-16 rounded-full border-4 border-[#ff4d4f] bg-surface flex items-center justify-center shadow-[0_0_15px_rgba(255,77,79,0.3)]"></div>
                        <div className="absolute bottom-6 left-[50%] -translate-x-1/2 text-xs text-[#ff4d4f]">FortiGate-01</div>

                        <div className="absolute bottom-8 left-[75%] w-16 h-16 rounded-full border-4 border-[#00d2ff] bg-surface flex items-center justify-center"></div>
                        <div className="absolute -bottom-2 left-[75%] -translate-x-1/2 text-xs text-[#00d2ff]">FortiGate-02</div>

                        {/* SVG Lines */}
                        <svg className="absolute inset-0 w-full h-full pointer-events-none">
                            <line x1="26%" y1="70px" x2="45%" y2="80px" stroke="#4b5563" strokeWidth="2" />
                            <line x1="56%" y1="90px" x2="78%" y2="115px" stroke="#4b5563" strokeWidth="2" />
                            <line x1="22%" y1="95px" x2="31%" y2="290px" stroke="#faad14" strokeWidth="2" strokeDasharray="4 4" />
                            <line x1="53%" y1="125px" x2="52%" y2="280px" stroke="#faad14" strokeWidth="2" strokeDasharray="4 4" />
                            <line x1="55%" y1="295px" x2="72%" y2="310px" stroke="#4b5563" strokeWidth="2" />
                            <line x1="78%" y1="140px" x2="75%" y2="305px" stroke="#4b5563" strokeWidth="2" strokeDasharray="2 2" />
                        </svg>
                    </div>

                    <div className="absolute bottom-6 left-6 bg-surface/80 backdrop-blur border border-border rounded-lg p-3 text-xs w-48">
                        <h4 className="font-semibold text-white mb-2 uppercase text-[10px] tracking-wider">Traffic Legend</h4>
                        <div className="flex items-center gap-2 text-text-muted mb-1"><span className="w-4 h-0.5 bg-gray-500"></span> Normal Flow</div>
                        <div className="flex items-center gap-2 text-text-muted"><span className="w-4 h-0.5 bg-warning border-dashed border-b border-warning inline-block"></span> Anomaly</div>
                    </div>
                </div>

                {/* Right Details Sidebar */}
                <div className="w-72 bg-surface border-l border-border p-5 flex flex-col">
                    <div className="flex justify-between items-center mb-6">
                        <h3 className="text-sm font-semibold flex items-center gap-2 text-white"><span className="rotate-90">⊟</span> Details</h3>
                        <button className="text-text-muted hover:text-white">✕</button>
                    </div>
                    <div className="bg-warning/10 border border-warning/30 rounded p-3 mb-6">
                        <div className="flex items-center gap-2 text-warning text-xs font-bold mb-1">
                            <AlertTriangle size={14} /> WARNING
                        </div>
                        <p className="text-[10px] text-text-secondary leading-relaxed">Current operational status</p>
                    </div>
                    <div className="space-y-4 text-xs font-mono">
                        <div>
                            <div className="text-text-muted mb-1 text-[10px] sans-serif tracking-wider uppercase">Device Name</div>
                            <div className="text-white text-sm">PA-Firewall-01</div>
                        </div>
                        <div>
                            <div className="text-text-muted mb-1 text-[10px] sans-serif tracking-wider uppercase">IP Address</div>
                            <div className="text-primary text-sm">10.0.1.1</div>
                        </div>
                        <div>
                            <div className="text-text-muted mb-1 text-[10px] sans-serif tracking-wider uppercase">Firmware Version</div>
                            <div className="text-white text-sm">PAN-OS 10.1.4</div>
                        </div>
                        <div className="pt-2 border-t border-border">
                            <div className="text-text-muted mb-1 text-[10px] sans-serif tracking-wider uppercase">Active Rules</div>
                            <div className="text-white flex items-center gap-2">~ 1450</div>
                        </div>
                    </div>
                    <div className="mt-auto">
                        <button className="w-full bg-surface border border-primary/50 text-primary py-2 text-xs rounded hover:bg-primary/10 transition-colors">
                            View Full Policy
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
