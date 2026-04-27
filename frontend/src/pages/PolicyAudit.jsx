import { useState, useEffect, useMemo } from 'react';
import { ChevronUp, ChevronDown, Search, Info, AlertTriangle, GitMerge, Loader } from 'lucide-react';
import { fetchAllData } from '../api/api';
import { Badge, RiskBar, riskColor } from '../components/ui/Badge';
import ConflictDrawer from '../components/policy/ConflictDrawer';

const STATUS_FILTERS = ['All', 'Shadowed', 'Redundant', 'Overly Permissive', 'Clean'];

const chipClass = {
  Shadowed:            'chip-critical',
  Redundant:           'chip-medium',
  'Overly Permissive': 'chip-high',
  Clean:               'chip-safe',
};

function SortIcon({ dir }) {
  if (dir === 'asc')  return <ChevronUp size={12} />;
  if (dir === 'desc') return <ChevronDown size={12} />;
  return <span style={{ opacity: 0.2 }}><ChevronDown size={12} /></span>;
}

export default function PolicyAudit() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [statusFilter, setStatusFilter]   = useState('All');
  const [vendorFilter, setVendorFilter]   = useState('All Vendors');
  const [search, setSearch]               = useState('');
  const [sortKey, setSortKey]             = useState('riskScore');
  const [sortDir, setSortDir]             = useState('desc');
  const [selectedRule, setSelectedRule]   = useState(null);
  const [showConflicts, setShowConflicts] = useState(false);

  useEffect(() => {
    fetchAllData()
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const policies = data?.policies || [];
  const conflicts = data?.conflicts || [];
  const vendorNames = useMemo(() => {
    const names = [...new Set(policies.map(p => p.vendor))];
    return ['All Vendors', ...names];
  }, [policies]);

  /* ── Filtering + Sorting ──────────────────────────── */
  const filtered = useMemo(() => {
    let d = [...policies];
    if (statusFilter !== 'All')       d = d.filter(p => p.status === statusFilter);
    if (vendorFilter !== 'All Vendors') d = d.filter(p => p.vendor === vendorFilter);
    if (search) {
      const q = search.toLowerCase();
      d = d.filter(p =>
        p.ruleName.toLowerCase().includes(q) ||
        p.firewall.toLowerCase().includes(q) ||
        p.srcIp.toLowerCase().includes(q) ||
        p.dstIp.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q)
      );
    }
    d.sort((a, b) => {
      let va = a[sortKey], vb = b[sortKey];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return d;
  }, [policies, statusFilter, vendorFilter, search, sortKey, sortDir]);

  const counts = useMemo(() => ({
    All:               policies.length,
    Shadowed:          policies.filter(p => p.status === 'Shadowed').length,
    Redundant:         policies.filter(p => p.status === 'Redundant').length,
    'Overly Permissive': policies.filter(p => p.status === 'Overly Permissive').length,
    Clean:             policies.filter(p => p.status === 'Clean').length,
  }), [policies]);

  const handleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const Th = ({ label, sortK }) => (
    <th onClick={() => handleSort(sortK)} style={{ cursor: 'pointer' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {label}
        {sortK && <SortIcon dir={sortKey === sortK ? sortDir : null} />}
      </div>
    </th>
  );

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', gap: '0.75rem', color: 'var(--text-muted)' }}>
      <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
      Loading policy data…
    </div>
  );
  if (error) return (
    <div style={{ padding: '2rem', color: 'var(--critical)' }}>
      <AlertTriangle size={20} style={{ marginRight: 8, verticalAlign: 'middle' }} />
      Failed to load data: {error}
    </div>
  );

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Policy Audit</h2>
          <p className="page-subtitle">{policies.length} rules · {conflicts.length} cross-vendor conflicts detected</p>
        </div>
        <button
          className={`btn ${showConflicts ? 'btn-primary' : 'btn-ghost'}`}
          id="conflicts-toggle-btn"
          onClick={() => setShowConflicts(s => !s)}
        >
          <GitMerge size={14} />
          {showConflicts ? 'Hide Conflicts' : 'View Cross-Vendor Conflicts'}
        </button>
      </div>

      {/* Cross-vendor conflicts panel */}
      {showConflicts && (
        <div className="card mb-3" style={{ borderColor: 'rgba(239,68,68,0.25)' }}>
          <div className="section-title" style={{ marginBottom: '0.75rem' }}>
            <AlertTriangle size={13} style={{ display: 'inline', marginRight: '0.4rem', verticalAlign: 'middle', color: 'var(--critical)' }} />
            Cross-Vendor Conflict Analysis
          </div>
          {conflicts.length === 0 ? (
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>No cross-vendor conflicts detected.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {conflicts.map(c => (
                <div key={c.id} style={{
                  background: 'var(--bg-surface)', border: '1px solid var(--border)',
                  borderRadius: 8, padding: '0.85rem',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--accent)' }}>{c.id}</span>
                      <Badge label={c.severity} />
                      <span className="badge badge-info" style={{ fontSize: '0.68rem' }}>{c.type}</span>
                    </div>
                  </div>
                  <p style={{ margin: '0 0 0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {c.description}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '1rem' }}>
        <div className="filter-chips">
          {STATUS_FILTERS.map(f => (
            <button
              key={f}
              id={`filter-${f.toLowerCase().replace(/\s+/g, '-')}`}
              className={`chip ${chipClass[f] || ''} ${statusFilter === f ? 'active' : ''}`}
              onClick={() => setStatusFilter(f)}
            >
              {f} {counts[f] !== undefined ? `(${counts[f]})` : ''}
            </button>
          ))}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          {vendorNames.map(v => (
            <button
              key={v}
              className={`chip ${vendorFilter === v ? 'active' : ''}`}
              onClick={() => setVendorFilter(v)}
            >
              {v === 'All Vendors' ? 'All' : v.length > 12 ? v.slice(0, 12) + '…' : v}
            </button>
          ))}
        </div>
        <div className="navbar-search" style={{ minWidth: 200 }}>
          <Search size={13} color="var(--text-muted)" />
          <input
            id="policy-search"
            placeholder="Search rules…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="table-wrapper">
        <div className="table-header">
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Showing <strong style={{ color: 'var(--text-primary)' }}>{filtered.length}</strong> rules
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click a row to inspect</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <Th label="Rule ID"      sortK="id" />
                <Th label="Rule Name"    sortK="ruleName" />
                <Th label="Firewall"     sortK="firewall" />
                <Th label="Vendor"       sortK="vendor" />
                <Th label="Src Zone"     sortK="srcZone" />
                <Th label="Dst Zone"     sortK="dstZone" />
                <Th label="Source IP"    sortK="srcIp" />
                <Th label="Dest IP"      sortK="dstIp" />
                <Th label="Action"       sortK="action" />
                <Th label="Status"       sortK="status" />
                <Th label="Risk"         sortK="riskScore" />
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={11}>
                    <div className="empty-state">
                      <Search size={28} />
                      <span>No rules match the current filters.</span>
                    </div>
                  </td>
                </tr>
              ) : filtered.map(rule => (
                <tr
                  key={rule.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedRule(rule)}
                  id={`rule-row-${rule.id}`}
                >
                  <td className="mono" style={{ color: 'var(--accent)' }}>{rule.id}</td>
                  <td style={{ fontWeight: 500, color: 'var(--text-primary)', maxWidth: 160, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {rule.ruleName}
                  </td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>{rule.firewall}</td>
                  <td style={{ fontSize: '0.78rem' }}>{rule.vendor.length > 12 ? rule.vendor.slice(0, 12) + '…' : rule.vendor}</td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>{rule.srcZone}</td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>{rule.dstZone}</td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>{rule.srcIp}</td>
                  <td className="mono" style={{ fontSize: '0.78rem', maxWidth: 130, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{rule.dstIp}</td>
                  <td><Badge label={rule.action} /></td>
                  <td><Badge label={rule.status} /></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', minWidth: 70 }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: riskColor(rule.riskScore), minWidth: 24 }}>
                        {rule.riskScore}
                      </span>
                      <div style={{ width: 48 }}><RiskBar score={rule.riskScore} /></div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Conflict drawer */}
      {selectedRule && (
        <ConflictDrawer rule={selectedRule} onClose={() => setSelectedRule(null)} />
      )}
    </div>
  );
}
