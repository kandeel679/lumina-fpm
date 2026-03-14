import { AlertTriangle, ShieldOff, Copy } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const pieData = [
    { name: 'Shadowed', value: 130, color: '#faad14' },
    { name: 'Redundant', value: 200, color: '#8c98a4' },
    { name: 'Permissive', value: 100, color: '#ff4d4f' },
];

export function AnomalyDetection() {
    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6">
            <div className="mb-8">
                <h1 className="text-2xl font-bold mb-1 flex items-center gap-2">
                    POLICY <span className="text-primary">ANOMALY DETECTION</span>
                </h1>
                <p className="text-text-secondary text-sm">Identify and resolve firewall configuration inefficiencies and conflicts.</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="card flex flex-col items-center justify-center p-6 bg-surface">
                            <AlertTriangle className="text-warning mb-2" size={28} />
                            <div className="text-3xl font-bold text-white mb-1">130</div>
                            <div className="text-xs text-text-muted uppercase tracking-wider">SHADOWED RULES</div>
                        </div>
                        <div className="card flex flex-col items-center justify-center p-6 bg-surface">
                            <ShieldOff className="text-danger mb-2" size={28} />
                            <div className="text-3xl font-bold text-white mb-1">100</div>
                            <div className="text-xs text-text-muted uppercase tracking-wider">PERMISSIVE RULES</div>
                        </div>
                    </div>
                    <div className="card flex flex-col items-center justify-center p-6 bg-surface">
                        <Copy className="text-text-secondary mb-2" size={28} />
                        <div className="text-3xl flex items-center gap-2 font-bold text-white mb-1">
                            200 <span className="text-sm font-normal text-text-muted">Unused / Duplicate</span>
                        </div>
                        <div className="text-xs text-text-muted uppercase tracking-wider">REDUNDANT RULES</div>
                    </div>
                </div>

                <div className="card flex items-center p-6">
                    <div className="w-1/2 h-48 relative">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                    stroke="none"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: '#121826', borderColor: '#1f2937' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="w-1/2 pl-6">
                        <h3 className="text-sm font-semibold mb-4 text-white">Anomaly Distribution</h3>
                        <div className="space-y-3 pl-2">
                            {pieData.map((item, idx) => (
                                <div key={idx} className="flex items-center justify-between text-sm">
                                    <div className="flex items-center gap-2">
                                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                                        <span className="text-text-secondary">{item.name}</span>
                                    </div>
                                    <span className="font-semibold text-white">{item.value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6">
                <div className="card col-span-1 lg:col-span-1 flex flex-col p-0 overflow-hidden">
                    <div className="p-4 border-b border-border flex justify-between items-center text-sm font-medium">
                        <span>Detected Issues</span>
                        <span className="text-xs text-danger pr-2">3 Found</span>
                    </div>
                    <div className="p-3">
                        <input type="text" placeholder="Search Rule ID..." className="w-full bg-background border border-border text-sm rounded py-2 px-3 text-white placeholder-text-muted mb-3" />
                        <div className="space-y-2">
                            <div className="border border-primary rounded-md p-3 bg-primary/5 relative cursor-pointer">
                                <div className="flex justify-between mb-1">
                                    <span className="text-primary font-bold text-sm">R-1001</span>
                                    <AlertTriangle size={14} className="text-warning" />
                                </div>
                                <div className="text-xs text-text-muted mb-2">PA-Firewall-01</div>
                                <span className="text-[10px] bg-warning/20 text-warning px-2 py-0.5 rounded">Shadowed</span>
                            </div>
                            <div className="border border-border rounded-md p-3 relative cursor-pointer hover:bg-surface/50">
                                <div className="flex justify-between mb-1">
                                    <span className="text-white font-bold text-sm">R-9999</span>
                                    <ShieldOff size={14} className="text-danger" />
                                </div>
                                <div className="text-xs text-text-muted mb-2">FortiGate-01</div>
                                <span className="text-[10px] bg-danger/20 text-danger px-2 py-0.5 rounded">Risky</span>
                            </div>
                            <div className="border border-border rounded-md p-3 relative cursor-pointer hover:bg-surface/50">
                                <div className="flex justify-between mb-1">
                                    <span className="text-white font-bold text-sm">R-2050</span>
                                    <Copy size={14} className="text-text-secondary" />
                                </div>
                                <div className="text-xs text-text-muted mb-2">FortiGate-03</div>
                                <span className="text-[10px] bg-surface text-text-secondary border border-border px-2 py-0.5 rounded">Redundant</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="card col-span-1 lg:col-span-2">
                    <h3 className="text-sm font-medium mb-4 flex items-center gap-2 text-white">
                        <span className="text-primary">⇄</span> Conflict Analysis
                    </h3>
                    <div className="flex gap-4 items-center mb-6">
                        <div className="flex-1 bg-background border border-border rounded p-4">
                            <div className="flex justify-between items-center mb-3">
                                <span className="text-[10px] text-text-muted border border-border px-2 py-0.5 rounded tracking-wider uppercase">Shadowed Rule</span>
                                <span className="text-xs text-text-muted">R-1001</span>
                            </div>
                            <div className="grid grid-cols-2 gap-y-2 text-xs">
                                <div className="text-text-secondary">SOURCE</div><div className="text-white">10.0.0.0/8</div>
                                <div className="text-text-secondary">DEST</div><div className="text-white">192.168.1.50</div>
                                <div className="text-text-secondary">SERVICE</div><div className="text-white">SSH</div>
                                <div className="text-text-secondary">ACTION</div><div className="text-primary font-bold">ALLOW</div>
                            </div>
                        </div>

                        <div className="text-danger border border-danger rounded-full p-1 bg-danger/10">
                            <ShieldOff size={16} />
                        </div>

                        <div className="flex-1 bg-surface border border-warning/30 rounded p-4 relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-1 h-full bg-warning"></div>
                            <div className="flex justify-between items-center mb-3">
                                <span className="text-[10px] text-warning bg-warning/10 border border-warning/30 px-2 py-0.5 rounded tracking-wider uppercase">Shadowing Rule</span>
                                <span className="text-xs text-text-muted">R-1000</span>
                            </div>
                            <div className="grid grid-cols-2 gap-y-2 text-xs">
                                <div className="text-text-secondary">SOURCE</div><div className="text-white">10.0.0.0/8</div>
                                <div className="text-text-secondary">DEST</div><div className="text-white">192.168.1.0/24</div>
                                <div className="text-text-secondary">SERVICE</div><div className="text-white">ANY</div>
                                <div className="text-text-secondary">ACTION</div><div className="text-danger font-bold">DENY</div>
                            </div>
                        </div>
                    </div>

                    <div className="bg-background/50 border border-border rounded p-4">
                        <h4 className="text-xs font-semibold text-white mb-2">Why is this a conflict?</h4>
                        <p className="text-xs text-text-secondary leading-relaxed">
                            The rule <span className="text-primary font-mono bg-surface px-1 rounded">R-1001</span> is never evaluated because rule <span className="text-warning font-mono bg-surface px-1 rounded">R-1000</span> matches the same traffic criteria and appears earlier in the policy list. This makes 'R-1001' effectively useless.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
