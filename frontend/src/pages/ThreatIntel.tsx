import { useState, useEffect } from 'react';
import { Shield, Crosshair, Clock, AlertTriangle, TrendingUp, Loader2, Radio, ChevronDown, ChevronRight, Copy, ExternalLink, Search } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { getDashboardStats, listReports, getReportDetail, triggerScan, createScanStream } from '../api/threatIntel';
import type {
    DashboardStats,
    ReportSummary,
    ReportDetail,
    FindingResponse,
    Severity,
    ThreatCategory,
    SSEEventType,
} from '../types/threatIntel';
import { SEVERITY_CONFIG, CATEGORY_LABELS } from '../types/threatIntel';

// ── Severity Badge ──
function SeverityBadge({ severity }: { severity: Severity }) {
    const cfg = SEVERITY_CONFIG[severity];
    return (
        <span
            className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded border"
            style={{
                color: cfg.color,
                backgroundColor: cfg.bg,
                borderColor: cfg.border,
                ...(severity === 'critical' ? { boxShadow: `0 0 10px ${cfg.border}` } : {}),
            }}
        >
            {cfg.label}
        </span>
    );
}

// ── Category Badge ──
function CategoryBadge({ category }: { category: ThreatCategory }) {
    const icons: Record<ThreatCategory, string> = {
        exploit: '🔓', credential: '🔑', c2: '📡', ransomware: '🦠', iab: '🚪',
    };
    return (
        <span className="text-[10px] px-2 py-0.5 rounded bg-surface border border-border text-text-secondary">
            {icons[category]} {CATEGORY_LABELS[category]}
        </span>
    );
}

// ── Finding Card ──
function FindingCard({ finding }: { finding: FindingResponse }) {
    const [open, setOpen] = useState(false);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <div
            className="card hover:border-border/80 transition-all cursor-pointer"
            style={{ borderLeftWidth: 3, borderLeftColor: SEVERITY_CONFIG[finding.severity].color }}
        >
            <div className="flex justify-between items-start mb-2" onClick={() => setOpen(!open)}>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={finding.severity} />
                        <CategoryBadge category={finding.category} />
                        {finding.is_new_since_last_scan && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/20 text-primary font-semibold animate-pulse">
                                NEW
                            </span>
                        )}
                    </div>
                    <h3 className="font-bold text-white text-sm truncate">{finding.title}</h3>
                </div>
                <div className="flex items-center gap-2 ml-2 shrink-0">
                    <span className="text-xs text-text-muted">
                        {finding.confidence}% conf
                    </span>
                    {open ? <ChevronDown size={16} className="text-text-muted" /> : <ChevronRight size={16} className="text-text-muted" />}
                </div>
            </div>

            {finding.source_marketplace_or_forum && (
                <div className="text-xs text-text-muted mb-2">
                    {finding.source_marketplace_or_forum}
                    {finding.source_scraped_at && ` • ${new Date(finding.source_scraped_at).toLocaleDateString()}`}
                </div>
            )}

            <p className="text-xs text-text-secondary leading-relaxed line-clamp-2 mb-2">
                {finding.description}
            </p>

            {/* Correlated rules badge */}
            {finding.matched_rule_ids.length > 0 && (
                <div className="flex items-center gap-1 mb-2">
                    <AlertTriangle size={12} className="text-warning" />
                    <span className="text-[10px] text-warning font-medium">
                        Matches {finding.matched_rule_ids.length} firewall rule(s)
                    </span>
                </div>
            )}

            {/* Expanded detail */}
            {open && (
                <div className="mt-3 pt-3 border-t border-border space-y-3 animate-in fade-in">
                    {/* IOCs */}
                    {finding.iocs.length > 0 && (
                        <div>
                            <div className="text-[10px] uppercase text-text-muted tracking-wider mb-1">Indicators</div>
                            <div className="flex flex-wrap gap-1">
                                {finding.iocs.map((ioc) => (
                                    <button
                                        key={ioc.id}
                                        onClick={() => copyToClipboard(ioc.ioc_value)}
                                        className="group text-[10px] font-mono px-2 py-0.5 bg-surface border border-border rounded hover:border-primary/50 transition-colors flex items-center gap-1"
                                        title="Click to copy"
                                    >
                                        <span className="text-text-muted">{ioc.ioc_type}:</span>
                                        <span className="text-text-primary">{ioc.ioc_value}</span>
                                        <Copy size={10} className="text-text-muted group-hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Raw excerpt */}
                    {finding.source_raw_excerpt && (
                        <div>
                            <div className="text-[10px] uppercase text-text-muted tracking-wider mb-1">Source Excerpt</div>
                            <div className="text-xs text-text-secondary bg-background p-2 rounded border border-border font-mono leading-relaxed max-h-24 overflow-y-auto">
                                {finding.source_raw_excerpt}
                            </div>
                        </div>
                    )}

                    {/* Recommended actions */}
                    {finding.recommended_actions.length > 0 && (
                        <div>
                            <div className="text-[10px] uppercase text-text-muted tracking-wider mb-1">Recommended Actions</div>
                            <ul className="list-disc list-inside text-xs text-text-secondary space-y-0.5">
                                {finding.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                            </ul>
                        </div>
                    )}

                    {/* Source link */}
                    {finding.source_onion_url && (
                        <div className="flex items-center gap-1 text-[10px] text-text-muted">
                            <ExternalLink size={10} />
                            <span className="font-mono truncate max-w-xs">{finding.source_onion_url}</span>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ── Scan Progress Modal ──
function ScanProgress({ reportId, onDone }: { reportId: number; onDone: () => void }) {
    const [steps, setSteps] = useState<Array<{ event: string; data: Record<string, unknown>; done: boolean }>>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const es = createScanStream(reportId);

        const handleEvent = (type: string) => (e: MessageEvent) => {
            const data = JSON.parse(e.data);
            setSteps(prev => [...prev, { event: type, data, done: true }]);
            if (type === 'done') {
                es.close();
                setTimeout(onDone, 1000);
            }
            if (type === 'failed') {
                es.close();
                setError(data.error || 'Scan failed');
            }
        };

        const events: SSEEventType[] = [
            'scan_started', 'keywords_extracted', 'queries_generated',
            'scraping_progress', 'category_refined', 'correlation_complete',
            'done', 'failed',
        ];
        events.forEach(evt => es.addEventListener(evt, handleEvent(evt)));
        es.onerror = () => { setError('Connection lost'); es.close(); };

        return () => es.close();
    }, [reportId, onDone]);

    const stepLabels: Record<string, string> = {
        scan_started: '🚀 Scan initiated',
        keywords_extracted: '🔑 Keywords extracted from firewall inventory',
        queries_generated: '🔍 Dark-web queries generated',
        scraping_progress: '🌐 Scraping .onion pages',
        category_refined: '🧠 Analyzing findings',
        correlation_complete: '🔗 Correlated with firewall rules',
        done: '✅ Scan complete!',
        failed: '❌ Scan failed',
    };

    return (
        <div className="card border-primary/30 space-y-3">
            <div className="flex items-center gap-2 mb-2">
                <Radio size={16} className="text-primary animate-pulse" />
                <span className="text-sm font-semibold text-primary">Scan in Progress</span>
            </div>
            {steps.map((step, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="text-success">✓</span>
                    <span className="text-text-secondary">
                        {stepLabels[step.event] || step.event}
                        {step.data && Object.keys(step.data).length > 0 && (
                            <span className="text-text-muted ml-1">
                                ({Object.entries(step.data).map(([k, v]) => `${k}: ${v}`).join(', ')})
                            </span>
                        )}
                    </span>
                </div>
            ))}
            {!error && steps[steps.length - 1]?.event !== 'done' && (
                <div className="flex items-center gap-2 text-xs text-text-muted">
                    <Loader2 size={12} className="animate-spin" />
                    <span>Processing...</span>
                </div>
            )}
            {error && <div className="text-xs text-danger">{error}</div>}
        </div>
    );
}

// ── MAIN PAGE ──
export function ThreatIntel() {
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [reports, setReports] = useState<ReportSummary[]>([]);
    const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState<number | null>(null);
    const [filterSeverity, setFilterSeverity] = useState<string>('');
    const [filterCategory, setFilterCategory] = useState<string>('');
    const [searchText, setSearchText] = useState('');

    // Load initial data
    useEffect(() => {
        async function load() {
            try {
                const [s, r] = await Promise.all([getDashboardStats(), listReports(1, 10)]);
                setStats(s);
                setReports(r.items as ReportSummary[]);

                // Auto-load latest completed report
                const latest = (r.items as ReportSummary[]).find(rep => rep.status === 'completed' || rep.status === 'partial');
                if (latest) {
                    const detail = await getReportDetail(latest.id);
                    setSelectedReport(detail);
                }
            } catch (e) {
                console.error('Failed to load threat intel data:', e);
            } finally {
                setLoading(false);
            }
        }
        load();
    }, []);

    // Trigger scan
    const handleScan = async () => {
        try {
            const res = await triggerScan();
            setScanning(res.report_id);
        } catch (e: unknown) {
            alert(e instanceof Error ? e.message : 'Failed to trigger scan');
        }
    };

    const handleScanDone = async () => {
        setScanning(null);
        // Reload data
        const [s, r] = await Promise.all([getDashboardStats(), listReports(1, 10)]);
        setStats(s);
        setReports(r.items as ReportSummary[]);
        if ((r.items as ReportSummary[]).length > 0) {
            const detail = await getReportDetail((r.items as ReportSummary[])[0].id);
            setSelectedReport(detail);
        }
    };

    // Filter findings
    const filteredFindings = (selectedReport?.findings || []).filter(f => {
        if (filterSeverity && f.severity !== filterSeverity) return false;
        if (filterCategory && f.category !== filterCategory) return false;
        if (searchText && !f.title.toLowerCase().includes(searchText.toLowerCase())
            && !f.description.toLowerCase().includes(searchText.toLowerCase())) return false;
        return true;
    });

    // Category donut data
    const donutData = selectedReport?.stats
        ? Object.entries(selectedReport.stats.by_category || {}).map(([key, val]) => ({
            name: CATEGORY_LABELS[key as ThreatCategory] || key,
            value: val,
        }))
        : [];
    const DONUT_COLORS = ['#dc2626', '#f97316', '#3b82f6', '#8b5cf6', '#10b981'];

    if (loading) {
        return (
            <div className="flex items-center justify-center h-full">
                <Loader2 size={32} className="animate-spin text-primary" />
            </div>
        );
    }

    return (
        <div className="p-8 max-w-7xl mx-auto space-y-6">
            {/* Header */}
            <div className="flex justify-between items-center mb-4">
                <div>
                    <h1 className="text-2xl font-bold mb-1">Threat Intelligence</h1>
                    <p className="text-text-secondary text-sm">
                        AI-powered dark web reconnaissance correlated with your firewall inventory
                    </p>
                </div>
                <button
                    onClick={handleScan}
                    disabled={scanning !== null}
                    className="px-5 py-2.5 bg-primary text-background rounded-lg text-sm font-semibold
                             hover:bg-primary/90 transition-all disabled:opacity-50 disabled:cursor-not-allowed
                             flex items-center gap-2 shadow-lg shadow-primary/20"
                >
                    {scanning ? (
                        <>
                            <Loader2 size={16} className="animate-spin" />
                            Scanning...
                        </>
                    ) : (
                        <>
                            <Crosshair size={16} />
                            Scan Now
                        </>
                    )}
                </button>
            </div>

            {/* Scan Progress */}
            {scanning && <ScanProgress reportId={scanning} onDone={handleScanDone} />}

            {/* Stats Cards */}
            {stats && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div className="card flex flex-col justify-between h-28">
                        <div className="flex justify-between items-start">
                            <span className="text-xs text-text-secondary font-medium tracking-wider">TOTAL SCANS</span>
                            <Shield size={18} className="text-primary" />
                        </div>
                        <div>
                            <div className="text-3xl font-bold">{stats.total_scans}</div>
                            <div className="text-xs text-text-muted">
                                {stats.last_scan_at ? `Last: ${new Date(stats.last_scan_at).toLocaleDateString()}` : 'No scans yet'}
                            </div>
                        </div>
                    </div>
                    <div className="card flex flex-col justify-between h-28">
                        <div className="flex justify-between items-start">
                            <span className="text-xs text-text-secondary font-medium tracking-wider">FINDINGS (7D)</span>
                            <TrendingUp size={18} className="text-primary" />
                        </div>
                        <div>
                            <div className="text-3xl font-bold">{stats.total_findings_last_7d}</div>
                            <div className="text-xs text-text-muted">{stats.new_findings_last_scan} new in last scan</div>
                        </div>
                    </div>
                    <div className="card flex flex-col justify-between h-28 border-l-2" style={{ borderLeftColor: SEVERITY_CONFIG.critical.color }}>
                        <div className="flex justify-between items-start">
                            <span className="text-xs text-text-secondary font-medium tracking-wider">CRITICAL</span>
                            <AlertTriangle size={18} style={{ color: SEVERITY_CONFIG.critical.color }} />
                        </div>
                        <div>
                            <div className="text-3xl font-bold" style={{ color: SEVERITY_CONFIG.critical.color }}>
                                {stats.critical_findings_last_7d}
                            </div>
                            <div className="text-xs text-text-muted">Last 7 days</div>
                        </div>
                    </div>
                    <div className="card flex flex-col justify-between h-28">
                        <div className="flex justify-between items-start">
                            <span className="text-xs text-text-secondary font-medium tracking-wider">CORRELATED</span>
                            <Clock size={18} className="text-warning" />
                        </div>
                        <div>
                            <div className="text-3xl font-bold text-warning">{stats.correlated_rules_count}</div>
                            <div className="text-xs text-text-muted">Findings matching firewall rules</div>
                        </div>
                    </div>
                </div>
            )}

            {/* Report Selector + Donut */}
            {reports.length > 0 && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Report list */}
                    <div className="lg:col-span-2 card max-h-64 overflow-y-auto">
                        <h3 className="text-sm font-medium mb-3">Recent Scans</h3>
                        <div className="space-y-1">
                            {reports.map(r => (
                                <button
                                    key={r.id}
                                    onClick={async () => {
                                        const detail = await getReportDetail(r.id);
                                        setSelectedReport(detail);
                                    }}
                                    className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-center justify-between transition-colors ${
                                        selectedReport?.id === r.id
                                            ? 'bg-primary/10 border border-primary/30 text-primary'
                                            : 'hover:bg-surface text-text-secondary'
                                    }`}
                                >
                                    <div className="flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full ${
                                            r.status === 'completed' ? 'bg-success'
                                            : r.status === 'running' ? 'bg-primary animate-pulse'
                                            : r.status === 'partial' ? 'bg-warning'
                                            : 'bg-danger'
                                        }`} />
                                        <span>Scan #{r.id}</span>
                                        <span className="text-text-muted">•</span>
                                        <span className="text-text-muted">{r.trigger_type}</span>
                                    </div>
                                    <div className="flex items-center gap-3">
                                        {r.stats && (
                                            <span className="text-text-muted">{r.stats.total_findings} findings</span>
                                        )}
                                        <span className="text-text-muted">
                                            {r.scan_started_at ? new Date(r.scan_started_at).toLocaleDateString() : ''}
                                        </span>
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Category donut */}
                    <div className="card flex flex-col items-center justify-center">
                        <h3 className="text-sm font-medium mb-2 self-start">By Category</h3>
                        {donutData.length > 0 ? (
                            <ResponsiveContainer width="100%" height={180}>
                                <PieChart>
                                    <Pie
                                        data={donutData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={45}
                                        outerRadius={70}
                                        paddingAngle={3}
                                        dataKey="value"
                                    >
                                        {donutData.map((_entry, i) => (
                                            <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#121826', borderColor: '#1f2937', fontSize: 12 }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        ) : (
                            <span className="text-text-muted text-xs">No data</span>
                        )}
                    </div>
                </div>
            )}

            {/* Narrative */}
            {selectedReport?.narrative_summary && (
                <div className="card">
                    <h3 className="text-sm font-medium mb-3">Executive Summary</h3>
                    <div className="text-xs text-text-secondary leading-relaxed whitespace-pre-line">
                        {selectedReport.narrative_summary}
                    </div>
                </div>
            )}

            {/* Filter Bar */}
            {selectedReport && selectedReport.findings.length > 0 && (
                <div className="flex flex-wrap items-center gap-3 p-3 card">
                    <div className="relative flex-1 max-w-xs">
                        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                        <input
                            type="text"
                            placeholder="Search findings..."
                            value={searchText}
                            onChange={e => setSearchText(e.target.value)}
                            className="w-full bg-background border border-border text-xs rounded-lg py-2 pl-9 pr-3 text-text-primary placeholder-text-muted focus:outline-none focus:border-primary transition-colors"
                        />
                    </div>
                    <select
                        value={filterSeverity}
                        onChange={e => setFilterSeverity(e.target.value)}
                        className="bg-background border border-border text-xs rounded-lg py-2 px-3 text-text-secondary focus:outline-none focus:border-primary"
                    >
                        <option value="">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select
                        value={filterCategory}
                        onChange={e => setFilterCategory(e.target.value)}
                        className="bg-background border border-border text-xs rounded-lg py-2 px-3 text-text-secondary focus:outline-none focus:border-primary"
                    >
                        <option value="">All Categories</option>
                        <option value="exploit">Exploits</option>
                        <option value="credential">Credentials</option>
                        <option value="c2">C2</option>
                        <option value="ransomware">Ransomware</option>
                        <option value="iab">IAB</option>
                    </select>
                    <span className="text-xs text-text-muted">
                        {filteredFindings.length} of {selectedReport.findings.length} findings
                    </span>
                </div>
            )}

            {/* Findings List */}
            {selectedReport && (
                <div className="space-y-3">
                    {filteredFindings.length > 0 ? (
                        filteredFindings.map(f => <FindingCard key={f.id} finding={f} />)
                    ) : selectedReport.findings.length === 0 ? (
                        <div className="card text-center text-text-muted text-sm py-12">
                            No findings in this scan. Your firewall inventory may not have matching dark-web exposure.
                        </div>
                    ) : (
                        <div className="card text-center text-text-muted text-sm py-8">
                            No findings match the current filters.
                        </div>
                    )}
                </div>
            )}

            {/* No reports state */}
            {!loading && reports.length === 0 && !scanning && (
                <div className="card text-center py-16 space-y-4">
                    <Shield size={48} className="text-text-muted mx-auto" />
                    <h3 className="text-lg font-semibold text-text-secondary">No threat intelligence data yet</h3>
                    <p className="text-sm text-text-muted max-w-md mx-auto">
                        Click <strong>Scan Now</strong> to search the dark web for threats
                        relevant to your firewall inventory.
                    </p>
                </div>
            )}
        </div>
    );
}
