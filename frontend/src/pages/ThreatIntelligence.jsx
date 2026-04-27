import React, { useState, useEffect, useMemo } from 'react';
import { ChevronUp, ChevronDown, Search, Shield, Calendar, AlertCircle, ExternalLink, Loader, AlertTriangle } from 'lucide-react';
import { fetchAllData } from '../api/api';
import { Badge, riskColor } from '../components/ui/Badge';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEVERITY_COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6' };

function SortIcon({ dir }) {
  if (dir === 'asc')  return <ChevronUp size={12} />;
  if (dir === 'desc') return <ChevronDown size={12} />;
  return <span style={{ opacity: 0.2 }}><ChevronDown size={12} /></span>;
}

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, padding: '0.65rem 0.9rem', fontSize: '0.8rem' }}>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.fill || p.color, display: 'flex', gap: 8 }}>
          <span>{p.name}:</span><span style={{ fontWeight: 700 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function ThreatIntelligence() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [search, setSearch]       = useState('');
  const [sevFilter, setSevFilter] = useState('All');
  const [vendorFilter, setVendorFilter] = useState('All');
  const [sortKey, setSortKey]     = useState('cvss');
  const [sortDir, setSortDir]     = useState('desc');
  const [expanded, setExpanded]   = useState(null);

  useEffect(() => {
    fetchAllData()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const threats = data?.threats || [];
  const firewalls = data?.firewalls || [];
  const firmwareTimeline = data?.firmwareTimeline || [];

  const vendorNames = useMemo(() => {
    const names = [...new Set(threats.flatMap(t => t.vendors))];
    return ['All', ...names];
  }, [threats]);

  const filtered = useMemo(() => {
    let d = [...threats];
    if (sevFilter !== 'All')    d = d.filter(t => t.severity === sevFilter);
    if (vendorFilter !== 'All') d = d.filter(t => t.vendors.includes(vendorFilter));
    if (search) {
      const q = search.toLowerCase();
      d = d.filter(t =>
        t.id.toLowerCase().includes(q) ||
        t.title.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      );
    }
    d.sort((a, b) => {
      let va = sortKey === 'cvss' ? a.cvss : (sortKey === 'severity' ? SEVERITY_ORDER[a.severity] : a[sortKey]);
      let vb = sortKey === 'cvss' ? b.cvss : (sortKey === 'severity' ? SEVERITY_ORDER[b.severity] : b[sortKey]);
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return d;
  }, [threats, search, sevFilter, vendorFilter, sortKey, sortDir]);

  const handleSort = key => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const Th = ({ label, sortK }) => (
    <th onClick={() => sortK && handleSort(sortK)} style={{ cursor: sortK ? 'pointer' : 'default' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {label}
        {sortK && <SortIcon dir={sortKey === sortK ? sortDir : null} />}
      </div>
    </th>
  );

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: '0.75rem', color: 'var(--text-muted)' }}>
      <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
      Loading threat intelligence…
    </div>
  );
  if (error) return (
    <div style={{ padding: '2rem', color: 'var(--critical)' }}>
      <AlertTriangle size={20} style={{ marginRight: 8, verticalAlign: 'middle' }} />
      Failed to load data: {error}
    </div>
  );

  // Chart data
  const sevDist = Object.entries(
    threats.reduce((acc, t) => { acc[t.severity] = (acc[t.severity] || 0) + 1; return acc; }, {})
  ).map(([name, value]) => ({ name, value, fill: SEVERITY_COLORS[name] }));

  // Vendor exposure: how many CVEs affect each firewall
  const vendorExposure = firewalls.map(fw => {
    const affected = threats.filter(t => t.affectedFirewalls.includes(fw.name)).length;
    return { name: fw.name.length > 14 ? fw.name.slice(0, 14) + '…' : fw.name, affected };
  }).sort((a, b) => b.affected - a.affected);

  const exploitCounts = threats.reduce((acc, t) => {
    acc[t.exploitStatus] = (acc[t.exploitStatus] || 0) + 1; return acc;
  }, {});

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Threat Intelligence</h2>
          <p className="page-subtitle">CVE analysis linked to deployed firmware versions · {threats.length} advisories</p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {Object.entries(exploitCounts).map(([status, count]) => (
            <span key={status} className="badge badge-info" style={{ fontSize: '0.7rem' }}>
              {status}: {count}
            </span>
          ))}
        </div>
      </div>

      {/* Stat cards */}
      <div className="kpi-grid mb-3">
        {[
          { label: 'Total CVEs',      value: threats.length,                              variant: 'accent' },
          { label: 'Critical',        value: threats.filter(t=>t.severity==='Critical').length, variant: 'critical' },
          { label: 'High',            value: threats.filter(t=>t.severity==='High').length,      variant: 'high' },
          { label: 'Active Exploits', value: threats.filter(t=>t.exploitStatus.includes('Active')).length, variant: 'critical' },
          { label: 'PoC Available',   value: threats.filter(t=>t.exploitStatus.includes('PoC')).length,  variant: 'high' },
        ].map(c => (
          <div key={c.label} className={`kpi-card ${c.variant}`}>
            <div className="kpi-label">{c.label}</div>
            <div className="kpi-value animate-count">{c.value}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid-2 mb-3">
        {/* Severity donut */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: '0.75rem' }}>Severity Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={sevDist} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3} dataKey="value">
                {sevDist.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
              <Legend
                formatter={(value, entry) => (
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{value} ({entry.payload.value})</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Vendor exposure */}
        <div className="card">
          <div className="section-title" style={{ marginBottom: '0.75rem' }}>CVE Exposure by Firewall</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={vendorExposure} layout="vertical" barCategoryGap="30%">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
              <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis dataKey="name" type="category" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} width={100} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="affected" name="CVEs" radius={[0,3,3,0]}>
                {vendorExposure.map((_, i) => (
                  <Cell key={i} fill={i === 0 ? '#ef4444' : i === 1 ? '#f97316' : '#06b6d4'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Firmware Timeline */}
      <div className="card mb-3">
        <div className="section-title" style={{ marginBottom: '0.75rem' }}>
          <Calendar size={13} style={{ display: 'inline', marginRight: '0.35rem', verticalAlign: 'middle' }} />
          Firmware Version Exposure Timeline
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Firmware Version</th>
                <th>Vendor</th>
                <th>CVE Count</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {firmwareTimeline.map(f => (
                <tr key={f.firmware}>
                  <td><span className="firmware-tag">{f.firmware}</span></td>
                  <td style={{ fontSize: '0.8rem' }}>{f.vendor}</td>
                  <td>
                    <span style={{ fontWeight: 700, color: f.threatCount >= 3 ? 'var(--critical)' : 'var(--high)' }}>
                      {f.threatCount}
                    </span>
                  </td>
                  <td>
                    {f.isEol
                      ? <Badge label="EOL" variant="badge-critical" />
                      : <Badge label="Supported" variant="badge-safe" />
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Filters + CVE Table */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '0.75rem' }}>
        <div className="filter-chips">
          {['All', 'Critical', 'High', 'Medium'].map(s => (
            <button key={s} className={`chip ${sevFilter === s ? 'active' : ''}`} onClick={() => setSevFilter(s)}>
              {s}
            </button>
          ))}
        </div>
        <div className="filter-chips">
          {vendorNames.map(v => (
            <button key={v} className={`chip ${vendorFilter === v ? 'active' : ''}`} onClick={() => setVendorFilter(v)}>
              {v.length > 15 ? v.slice(0, 15) + '…' : v}
            </button>
          ))}
        </div>
        <div className="navbar-search" style={{ marginLeft: 'auto', minWidth: 200 }}>
          <Search size={13} color="var(--text-muted)" />
          <input id="threat-search" placeholder="Search CVEs…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      <div className="table-wrapper">
        <div className="table-header">
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <strong style={{ color: 'var(--text-primary)' }}>{filtered.length}</strong> advisories
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click a row to expand</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <Th label="CVE ID"       sortK="id" />
                <Th label="Severity"     sortK="severity" />
                <Th label="CVSS"         sortK="cvss" />
                <Th label="Title"        />
                <Th label="Vendors"      />
                <Th label="Affected FW"  />
                <Th label="Exploit"      />
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => (
                <React.Fragment key={t.id}>
                  <tr
                    style={{ cursor: 'pointer' }}
                    onClick={() => setExpanded(expanded === t.id ? null : t.id)}
                    id={`cve-row-${t.id}`}
                  >
                    <td className="mono" style={{ color: 'var(--accent)', fontWeight: 600 }}>{t.id}</td>
                    <td><Badge label={t.severity} /></td>
                    <td>
                      <span className={`cvss-score cvss-${t.severity.toLowerCase()}`} style={{ fontSize: '0.88rem' }}>
                        {typeof t.cvss === 'number' ? t.cvss.toFixed(1) : t.cvss}
                      </span>
                    </td>
                    <td style={{ maxWidth: 240, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--text-primary)', fontSize: '0.8rem', fontWeight: 500 }}>
                      {t.title}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                        {t.vendors.map(v => (
                          <span key={v} className="badge badge-info" style={{ fontSize: '0.67rem' }}>
                            {v.length > 12 ? v.slice(0, 2).toUpperCase() : v}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {t.affectedFirewalls.join(', ')}
                    </td>
                    <td>
                      <span style={{
                        fontSize: '0.72rem', fontWeight: 600,
                        color: t.exploitStatus.includes('Active') ? 'var(--critical)'
                             : t.exploitStatus.includes('PoC') ? 'var(--high)'
                             : t.exploitStatus.includes('Widely') ? 'var(--critical)'
                             : 'var(--text-muted)',
                      }}>
                        {t.exploitStatus}
                      </span>
                    </td>
                  </tr>
                  {expanded === t.id && (
                    <tr style={{ background: 'var(--bg-surface)' }}>
                      <td colSpan={7} style={{ padding: '1rem 1.5rem' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '1.5rem' }}>
                          <div>
                            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                              Description
                            </div>
                            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                              {t.description}
                            </p>
                          </div>
                          <div style={{ minWidth: 200 }}>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                              Patch Info
                            </div>
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                              {t.patchedIn}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                              Affected Firmware
                            </div>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                              {t.affectedFirmware.map(f => (
                                <span key={f} className="firmware-tag">{f}</span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
