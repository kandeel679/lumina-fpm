import { ShieldCheck, AlertTriangle, Activity, Globe } from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const areaData = [
    { name: 'Mon', asa: 10, fortios: 12, panos: 5 },
    { name: 'Tue', asa: 8, fortios: 10, panos: 4 },
    { name: 'Wed', asa: 12, fortios: 15, panos: 6 },
    { name: 'Thu', asa: 10, fortios: 28, panos: 5 },
    { name: 'Fri', asa: 8, fortios: 42, panos: 6 },
    { name: 'Sat', asa: 9, fortios: 35, panos: 5 },
    { name: 'Sun', asa: 8, fortios: 30, panos: 4 },
];

const barData = [
    { name: 'Perimeter FW', clean: 800, permissive: 50, redundant: 30, shadowed: 20 },
    { name: 'Core FW', clean: 1100, permissive: 150, redundant: 80, shadowed: 50 },
    { name: 'Branch FW', clean: 250, permissive: 20, redundant: 10, shadowed: 5 },
];

export function Dashboard() {
    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6">
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-2xl font-bold mb-1">Security Overview</h1>
                    <p className="text-text-secondary text-sm">AI-Powered Dark Web Intelligence & Policy Hygiene</p>
                </div>
                <button className="px-4 py-2 border border-border rounded-lg text-sm bg-surface hover:bg-surface/80 transition-colors">
                    Last 24 Hours
                </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                    { title: 'TOTAL RULES', value: '2,660', sub: 'Across all firewall groups', icon: <ShieldCheck size={20} className="text-primary" /> },
                    { title: 'RULE ANOMALIES', value: '455', sub: 'Shadowed, redundant, & permissive', icon: <AlertTriangle size={20} className="text-warning" /> },
                    { title: 'DARK WEB MENTIONS', value: '118', sub: 'FortiOS 7.2 exploit trending ↑', icon: <Activity size={20} className="text-primary" /> },
                    { title: 'CRITICAL THREATS', value: '1', sub: 'Zero-day exploit for FortiOS', icon: <Globe size={20} className="text-primary" /> },
                ].map((stat, i) => (
                    <div key={i} className="card flex flex-col justify-between h-32">
                        <div className="flex justify-between items-start">
                            <span className="text-xs text-text-secondary font-medium tracking-wider">{stat.title}</span>
                            {stat.icon}
                        </div>
                        <div>
                            <div className="text-3xl font-bold mb-1">{stat.value}</div>
                            <div className="text-xs text-text-muted">{stat.sub}</div>
                        </div>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
                <div className="card h-96">
                    <h3 className="text-sm font-medium mb-1">Firmware Risk Exposure</h3>
                    <p className="text-xs text-text-muted mb-6">Dark web mentions of your firewall versions (Last 7 days)</p>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={areaData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                                <XAxis dataKey="name" stroke="#8c98a4" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis stroke="#8c98a4" fontSize={12} tickLine={false} axisLine={false} />
                                <Tooltip contentStyle={{ backgroundColor: '#121826', borderColor: '#1f2937' }} />
                                <Area type="monotone" dataKey="fortios" stroke="#ff4d4f" fill="#ff4d4f" fillOpacity={0.1} strokeWidth={2} />
                                <Area type="monotone" dataKey="asa" stroke="#00d2ff" fill="#00d2ff" fillOpacity={0.1} strokeWidth={2} />
                                <Area type="monotone" dataKey="panos" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.1} strokeWidth={2} strokeDasharray="5 5" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card h-96">
                    <h3 className="text-sm font-medium mb-1">Policy Health by Firewall Group</h3>
                    <p className="text-xs text-text-muted mb-6">Breakdown of rule integrity across your network</p>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={barData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                                <XAxis dataKey="name" stroke="#8c98a4" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis stroke="#8c98a4" fontSize={12} tickLine={false} axisLine={false} />
                                <Tooltip contentStyle={{ backgroundColor: '#121826', borderColor: '#1f2937' }} cursor={{ fill: '#1f2937', opacity: 0.4 }} />
                                <Bar dataKey="clean" stackId="a" fill="#52c41a" />
                                <Bar dataKey="permissive" stackId="a" fill="#ff4d4f" />
                                <Bar dataKey="redundant" stackId="a" fill="#faad14" />
                                <Bar dataKey="shadowed" stackId="a" fill="#d48806" />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
}
