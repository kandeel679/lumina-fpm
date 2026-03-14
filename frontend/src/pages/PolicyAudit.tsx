import { AlertTriangle, CheckCircle, ShieldOff, Filter } from 'lucide-react';

const rules = [
    { id: 'R-1001', vendor: 'Palo Alto Networks', fw: 'PA-Firewall-01', src: '10.0.0.0/8', dest: '192.168.1.50', svc: 'SSH', action: 'Allow', status: 'Shadowed by R-1000', icon: <AlertTriangle size={14} className="text-warning inline mr-2" /> },
    { id: 'R-1000', vendor: 'Palo Alto Networks', fw: 'PA-Firewall-01', src: '10.0.0.0/8', dest: '192.168.1.0/24', svc: 'ANY', action: 'Deny', status: 'Clean', icon: <CheckCircle size={14} className="text-success inline mr-2" /> },
    { id: 'R-9999', vendor: 'Fortinet', fw: 'FortiGate-01', src: 'ANY', dest: 'ANY', svc: 'ANY', action: 'Allow', status: 'Permissive (Any/Any)', icon: <ShieldOff size={14} className="text-danger inline mr-2" /> },
    { id: 'R-2050', vendor: 'Fortinet', fw: 'FortiGate-03', src: '172.16.0.10', dest: '8.8.8.8', svc: 'DNS', action: 'Allow', status: 'Redundant', icon: <AlertTriangle size={14} className="text-text-secondary inline mr-2" /> },
    { id: 'R-3000', vendor: 'Palo Alto Networks', fw: 'PA-Firewall-01', src: '10.10.0.0/24', dest: '192.168.0.5', svc: 'HTTP', action: 'Allow', status: 'Clean', icon: <CheckCircle size={14} className="text-success inline mr-2" /> },
    { id: 'R-3001', vendor: 'Fortinet', fw: 'FortiGate-02', src: '10.10.1.0/24', dest: '192.168.1.5', svc: 'HTTPS', action: 'Deny', status: 'Clean', icon: <CheckCircle size={14} className="text-success inline mr-2" /> },
    { id: 'R-3002', vendor: 'Palo Alto Networks', fw: 'PA-Firewall-03', src: '10.10.2.0/24', dest: '192.168.2.5', svc: 'SSH', action: 'Allow', status: 'Clean', icon: <CheckCircle size={14} className="text-success inline mr-2" /> },
    { id: 'R-3003', vendor: 'Fortinet', fw: 'FortiGate-01', src: '10.10.3.0/24', dest: '192.168.3.5', svc: 'RDP', action: 'Deny', status: 'Clean', icon: <CheckCircle size={14} className="text-success inline mr-2" /> },
];

export function PolicyAudit() {
    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6">
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-2xl font-bold mb-1">Policy Audit</h1>
                    <p className="text-text-secondary text-sm">Review firewall rules and detect configuration anomalies.</p>
                </div>
                <button className="px-4 py-2 border border-border rounded-lg text-sm bg-surface hover:bg-surface/80 transition-colors flex items-center gap-2">
                    <Filter size={16} /> All Vendors
                </button>
            </div>

            <div className="card overflow-x-auto p-0">
                <table className="w-full text-left border-collapse text-sm">
                    <thead>
                        <tr className="border-b border-border bg-background uppercase text-[10px] tracking-wider text-text-muted">
                            <th className="px-6 py-4 font-semibold">Rule ID</th>
                            <th className="px-6 py-4 font-semibold">Vendor / Firewall</th>
                            <th className="px-6 py-4 font-semibold">Source</th>
                            <th className="px-6 py-4 font-semibold">Destination</th>
                            <th className="px-6 py-4 font-semibold">Service</th>
                            <th className="px-6 py-4 font-semibold">Action</th>
                            <th className="px-6 py-4 font-semibold">Status / Anomalies</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border/50 bg-surface">
                        {rules.map((rule, idx) => (
                            <tr key={idx} className="hover:bg-background/40 transition-colors">
                                <td className="px-6 py-4 font-mono text-white tracking-wider">{rule.id}</td>
                                <td className="px-6 py-4">
                                    <div className="text-white text-xs block">{rule.vendor}</div>
                                    <div className="text-text-muted text-[10px] block mt-0.5">{rule.fw}</div>
                                </td>
                                <td className="px-6 py-4 text-xs font-mono">{rule.src}</td>
                                <td className="px-6 py-4 text-xs font-mono">{rule.dest}</td>
                                <td className="px-6 py-4 text-xs">{rule.svc}</td>
                                <td className="px-6 py-4">
                                    <span className={`px-2 py-1 text-[10px] rounded border ${rule.action === 'Allow' ? 'border-primary text-primary bg-primary/10' : 'border-purple-500 text-purple-400 bg-purple-500/10'
                                        }`}>
                                        {rule.action}
                                    </span>
                                </td>
                                <td className="px-6 py-4 text-xs">
                                    {rule.icon}{rule.status}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
