import { useState, useEffect, useMemo } from 'react';
import {
  LayoutDashboard, ShieldAlert, Copy, AlertTriangle,
  TrendingUp, Server, Activity, ExternalLink, Loader,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, RadialBarChart, RadialBar, Legend,
} from 'recharts';
import { fetchAllData } from '../api/api';
import { Badge, RiskBar, riskColor, riskLabel } from '../components/ui/Badge';

/* ── KPI card ─────────────────────────────────────────── */
function KpiCard({ label, value, sub, icon: Icon, variant, pulse }) {
  return (
    <div className={`kpi-card ${variant}`} style={pulse ? { animation: 'pulse-safe 2s infinite' } : {}}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value animate-count">{value}</div>
      <div className="kpi-sub">{sub}</div>
      {Icon && <div className="kpi-icon-wrap"><Icon size={40} /></div>}
    </div>
  );
}

/* ── Custom tooltip ───────────────────────────────────── */
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '0.65rem 0.9rem', fontSize: '0.8rem',
    }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.fill, display: 'flex', gap: 8 }}>
          <span>{p.name}:</span><span style={{ fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAllData()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: '0.75rem', color: 'var(--text-muted)' }}>
      <Loader size={20} className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
      Loading dashboard data…
    </div>
  );
  if (error) return (
    <div style={{ padding: '2rem', color: 'var(--critical)' }}>
      <AlertTriangle size={20} style={{ marginRight: 8, verticalAlign: 'middle' }} />
      Failed to load data: {error}
    </div>
  );

  const { vendors, firewalls, policies, threats } = data;

  // Derived stats
  const total     = policies.length;
  const shadowed  = policies.filter(p => p.status === 'Shadowed').length;
  const redundant = policies.filter(p => p.status === 'Redundant').length;
  const permissive= policies.filter(p => p.status === 'Overly Permissive').length;
  const clean     = policies.filter(p => p.status === 'Clean').length;
  const avgRisk   = total ? Math.round(policies.reduce((a, p) => a + p.riskScore, 0) / total) : 0;

  const anomalies = [...policies]
    .filter(p => p.status !== 'Clean')
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 6);

  const topThreats = [...threats]
    .sort((a, b) => b.cvss - a.cvss)
    .slice(0, 4);

  // Chart data: per-vendor rule breakdown
  const vendorChart = vendors.map(v => {
    const vPolicies = policies.filter(p => p.vendor === v.name);
    return {
      name: v.name.length > 12 ? v.name.slice(0, 12) + '…' : v.name,
      Clean:     vPolicies.filter(p => p.status === 'Clean').length,
      Shadowed:  vPolicies.filter(p => p.status === 'Shadowed').length,
      Redundant: vPolicies.filter(p => p.status === 'Redundant').length,
      Permissive:vPolicies.filter(p => p.status === 'Overly Permissive').length,
    };
  });

  // Per-firewall risk
  const fwRisk = firewalls.map(f => ({
    name: f.name.length > 14 ? f.name.slice(0, 14) + '…' : f.name,
    riskScore: f.riskScore,
    anomalyCount: f.anomalyCount,
  })).sort((a, b) => b.riskScore - a.riskScore);

  // Status distribution for radial
  const radialData = [
    { name: 'Clean',     value: clean,     fill: '#22c55e' },
    { name: 'Shadowed',  value: shadowed,  fill: '#ef4444' },
    { name: 'Redundant', value: redundant, fill: '#eab308' },
    { name: 'Permissive',value: permissive,fill: '#f97316' },
  ];

  return (
    <div>
      {/* Page header */}
      <div className="page-header">
        <div>
          <h2 className="page-title">Security Overview</h2>
          <p className="page-subtitle">Cross-vendor firewall policy health · {total} rules across {firewalls.length} devices</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span className="firmware-tag">Last sync: just now</span>
          <span className="badge badge-info"><Activity size={10} style={{marginRight:3}}/>Live</span>
        </div>
      </div>

      {/* KPI Row */}
      <div className="kpi-grid mb-3">
        <KpiCard label="Total Rules"         value={total}     sub={`${firewalls.length} firewalls`}     icon={Server}       variant="accent" />
        <KpiCard label="Shadowed Rules"      value={shadowed}  sub="Never evaluated"                    icon={ShieldAlert}  variant="critical" />
        <KpiCard label="Redundant Rules"     value={redundant} sub="Duplicate coverage"                 icon={Copy}         variant="medium" />
        <KpiCard label="Overly Permissive"   value={permissive}sub="Any/any violations"                 icon={AlertTriangle} variant="high" />
        <KpiCard label="Clean Rules"         value={clean}     sub="No anomalies detected"              icon={LayoutDashboard} variant="safe" />
        <KpiCard label="Avg Risk Score"      value={avgRisk}   sub={`${riskLabel(avgRisk)} overall`}    icon={TrendingUp}   variant={avgRisk >= 60 ? 'high' : avgRisk >= 40 ? 'medium' : 'safe'} />
      </div>

      {/* Charts row */}
      <div className="grid-2 mb-3" style={{ alignItems: 'stretch' }}>
        {/* Vendor breakdown bar chart */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: '1rem' }}>Rule Status by Vendor</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={vendorChart} barGap={3} barCategoryGap="35%">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="Clean"      name="Clean"      fill="#22c55e" radius={[3,3,0,0]} />
              <Bar dataKey="Shadowed"   name="Shadowed"   fill="#ef4444" radius={[3,3,0,0]} />
              <Bar dataKey="Redundant"  name="Redundant"  fill="#eab308" radius={[3,3,0,0]} />
              <Bar dataKey="Permissive" name="Permissive" fill="#f97316" radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Firewall risk scores */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: '1rem' }}>Firewall Risk Scores</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
            {fwRisk.map(fw => (
              <div key={fw.name} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', minWidth: 115, fontFamily: 'monospace' }}>
                  {fw.name}
                </span>
                <div style={{ flex: 1 }}>
                  <RiskBar score={fw.riskScore} showLabel={false} />
                </div>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: riskColor(fw.riskScore), minWidth: 28, textAlign: 'right' }}>
                  {fw.riskScore}
                </span>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', minWidth: 60 }}>
                  {fw.anomalyCount} anomalies
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid-2">
        {/* Recent anomalies */}
        <div className="table-wrapper">
          <div className="table-header">
            <span className="section-title" style={{ margin: 0 }}>Recent Anomalies</span>
            <a href="/policy-audit" style={{ fontSize: '0.75rem', color: 'var(--accent)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
              View all <ExternalLink size={11} />
            </a>
          </div>
          <div style={{ padding: '0.25rem 1rem' }}>
            {anomalies.map(rule => (
              <div key={rule.id} className="anomaly-item">
                <span className="status-dot" style={{ background: riskColor(rule.riskScore) }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {rule.ruleName}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{rule.firewall}</div>
                </div>
                <Badge label={rule.status} />
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: riskColor(rule.riskScore), minWidth: 28, textAlign: 'right' }}>
                  {rule.riskScore}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top threats */}
        <div className="table-wrapper">
          <div className="table-header">
            <span className="section-title" style={{ margin: 0 }}>Critical CVEs — Active</span>
            <a href="/threats" style={{ fontSize: '0.75rem', color: 'var(--accent)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
              Threat Intel <ExternalLink size={11} />
            </a>
          </div>
          <div style={{ padding: '0.5rem 1rem' }}>
            {topThreats.map(t => (
              <div key={t.id} className="anomaly-item" style={{ gap: '0.6rem', alignItems: 'flex-start', paddingTop: '0.6rem', paddingBottom: '0.6rem' }}>
                <span className={`cvss-score cvss-${t.severity.toLowerCase()}`} style={{ minWidth: 36, fontSize: '0.85rem' }}>
                  {t.cvss}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-primary)', fontWeight: 600 }}>{t.id}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {t.title}
                  </div>
                </div>
                <Badge label={t.severity} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
