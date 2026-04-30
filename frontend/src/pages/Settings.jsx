import { useState, useEffect } from 'react';
import { Shield, Bell, Clock, Server, Users, Database, Lock, Eye, AlertCircle, Loader, AlertTriangle } from 'lucide-react';
import { fetchAllData } from '../api/api';
import { Badge } from '../components/ui/Badge';

const Section = ({ title, icon: Icon, children }) => (
  <div className="card mb-2">
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)' }}>
      {Icon && <Icon size={16} color="var(--accent)" />}
      <span style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>{title}</span>
      <span className="badge badge-info" style={{ marginLeft: 'auto', fontSize: '0.65rem' }}>Read-only</span>
    </div>
    {children}
  </div>
);

const Row = ({ label, desc, value, toggle }) => (
  <div className="settings-row">
    <div>
      <div className="settings-label">{label}</div>
      {desc && <div className="settings-desc">{desc}</div>}
    </div>
    {toggle !== undefined
      ? <div className={`toggle ${toggle ? 'on' : ''}`} title="Read-only" />
      : <span style={{ fontSize: '0.82rem', color: 'var(--accent)', fontFamily: 'monospace' }}>{value}</span>
    }
  </div>
);

export default function Settings() {
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
      <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
      Loading settings…
    </div>
  );
  if (error) return (
    <div style={{ padding: '2rem', color: 'var(--critical)' }}>
      <AlertTriangle size={20} style={{ marginRight: 8, verticalAlign: 'middle' }} />
      Failed to load data: {error}
    </div>
  );

  const { firewalls, vendors } = data;

  return (
    <div>
      <div className="page-header">
        <div>
          <h2 className="page-title">Settings</h2>
          <p className="page-subtitle">Platform configuration — read-only view for analysts</p>
        </div>
        <div className="badge badge-info" style={{ alignSelf: 'flex-start' }}>
          <Lock size={11} style={{ marginRight: 4 }} />
          View Only
        </div>
      </div>

      <div className="grid-2">
        <div>
          {/* Platform */}
          <Section title="Platform Configuration" icon={Shield}>
            <Row label="Platform Name"       value="Lumina FPM v2.4.1" />
            <Row label="Analysis Engine"     value="Ruleset Analyzer 3.1" />
            <Row label="API Endpoint"        value="https://api.lumina-fpm.local" />
            <Row label="Backend Framework"   value="FastAPI + Python 3.12" />
            <Row label="Data Refresh Rate"   value="Every 15 minutes" />
            <Row label="Threat Intel Feed"   value="NVD / CISA / Vendor Advisories" />
          </Section>

          {/* Notification */}
          <Section title="Notification Preferences" icon={Bell}>
            <Row label="Critical Alerts via Email"    desc="Severity ≥ Critical"           toggle={true} />
            <Row label="High Alerts via Email"        desc="Severity ≥ High"               toggle={true} />
            <Row label="Slack Integration"            desc="Webhook to #soc-alerts channel" toggle={true} />
            <Row label="Weekly Policy Report"         desc="PDF digest every Monday 08:00"  toggle={true} />
            <Row label="Firmware Advisory Digest"     desc="New CVE notifications"          toggle={true} />
            <Row label="Redundant Rule Alerts"        desc="Notify on policy scan"          toggle={false} />
          </Section>

          {/* Schedule */}
          <Section title="Scan Schedule" icon={Clock}>
            <Row label="Policy Analysis Scan"   value="Daily 02:00 UTC" />
            <Row label="Cross-Vendor Analysis"  value="Every 6 hours" />
            <Row label="Threat Feed Sync"        value="Every 4 hours" />
            <Row label="Topology Discovery"      value="Every 30 minutes" />
            <Row label="Anomaly Detection"       value="Real-time (continuous)" />
            <Row label="Report Generation"       value="Weekly (Monday 06:00 UTC)" />
          </Section>
        </div>

        <div>
          {/* Registered Firewalls */}
          <Section title="Registered Firewalls" icon={Server}>
            {firewalls.map(fw => (
              <div key={fw.id} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '0.6rem 0', borderBottom: '1px solid var(--border)',
              }}>
                <div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{fw.name}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {fw.ip} · {fw.firmware}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{fw.location}</div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.3rem' }}>
                  <span style={{
                    fontSize: '0.72rem', fontWeight: 600,
                    color: fw.status === 'online' ? 'var(--safe)' : fw.status === 'degraded' ? 'var(--high)' : 'var(--critical)',
                  }}>● {fw.status}</span>
                  <span className="firmware-tag">{fw.vendor.length > 12 ? fw.vendor.slice(0, 2).toUpperCase() : fw.vendor}</span>
                </div>
              </div>
            ))}
            <div style={{ padding: '0.6rem 0', margin: 0 }}></div>
          </Section>

          {/* Vendors */}
          <Section title="Vendor Integrations" icon={Database}>
            {vendors.map(v => (
              <div key={v.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.6rem 0', borderBottom: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <div style={{ width: 30, height: 30, borderRadius: 6, background: v.color + '22', border: `1px solid ${v.color}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.65rem', fontWeight: 700, color: v.color }}>
                    {v.logo}
                  </div>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{v.name}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {firewalls.filter(f => f.vendorId === v.id).length} devices registered
                    </div>
                  </div>
                </div>
                <Badge label="Active" variant="badge-safe" />
              </div>
            ))}
          </Section>

          {/* Access Control */}
          <Section title="Access & Security" icon={Users}>
            <Row label="Current User"        value="hamza.admin" />
            <Row label="Role"                value="SOC Analyst (Read-Only)" />
            <Row label="Authentication"      value="SSO / LDAP" />
            <Row label="Session Timeout"     value="30 minutes" />
            <Row label="Audit Logging"       toggle={true} />
            <Row label="2FA Enforcement"     desc="Required for all admin accounts" toggle={true} />
            <Row label="IP Allowlisting"     desc="Restrict management access by IP" toggle={true} />
          </Section>
        </div>
      </div>

      {/* Info banner */}
      <div style={{
        marginTop: '0.5rem', padding: '0.85rem 1.25rem',
        background: 'rgba(6,182,212,0.07)', border: '1px solid rgba(6,182,212,0.2)',
        borderRadius: 10, display: 'flex', alignItems: 'center', gap: '0.75rem',
      }}>
        <AlertCircle size={16} color="var(--accent)" style={{ flexShrink: 0 }} />
        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
          This is a <strong style={{ color: 'var(--accent)' }}>read-only analyst view</strong>. Configuration changes must be made by a platform administrator through the management CLI or admin portal. All policy edits occur on the firewall devices directly.
        </span>
      </div>
    </div>
  );
}
