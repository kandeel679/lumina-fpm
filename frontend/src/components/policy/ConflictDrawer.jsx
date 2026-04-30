import { X, Brain, AlertTriangle, Zap } from 'lucide-react';
import { Badge, RiskBar, riskLabel, riskColor } from '../ui/Badge';
import { policies } from '../../data/mockPolicies';

const aiInsights = {
  Shadowed: (rule, shadow) =>
    `Rule "${rule.ruleName}" (priority ${rule.priority}) is completely shadowed by "${shadow?.ruleName}" (priority ${shadow?.priority}). Because the shadowing rule appears earlier in the policy list and matches a superset of traffic, "${rule.ruleName}" is never evaluated and has zero effect. This dead rule wastes compute cycles, inflates the rule base, and may mislead auditors into thinking specific controls are in place. Recommended action: Remove or disable this rule.`,
  Redundant: (rule, shadow) =>
    `Rule "${rule.ruleName}" duplicates the effect of "${shadow?.ruleName}". Both rules permit the same traffic class. Keeping both creates ambiguity during audits and complicates troubleshooting. Consolidate into a single, well-documented rule. Risk: Medium — no active exploit path but introduces policy debt.`,
  'Overly Permissive': (rule) =>
    `Rule "${rule.ruleName}" uses overly broad source/destination IP ranges or services (e.g., any/any, 0.0.0.0/0). This violates the principle of least privilege and significantly expands the attack surface. An attacker exploiting a misconfiguration in a connected host could pivot freely through this open path. Recommended action: Restrict to the minimum required IP ranges and service ports.`,
};

function FieldRow({ label, valA, valB }) {
  const differs = valA !== valB;
  return (
    <div className={`conflict-field ${differs ? 'differs' : ''}`}>
      <span className="conflict-field-label">{label}</span>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
        <span className="conflict-field-value">{valA || '—'}</span>
        <span className="conflict-field-value">{valB || '—'}</span>
      </div>
    </div>
  );
}

export default function ConflictDrawer({ rule, onClose }) {
  if (!rule) return null;

  const shadowRule = rule.shadowedBy
    ? policies.find(p => p.id === rule.shadowedBy)
    : null;

  const insightFn = aiInsights[rule.status];
  const insight = insightFn ? insightFn(rule, shadowRule) : null;

  return (
    <>
      <div className="drawer-overlay" onClick={onClose} />
      <aside className="drawer" id="conflict-drawer">
        {/* Header */}
        <div className="drawer-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <AlertTriangle size={16} color="var(--high)" />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Anomaly Detail
              </span>
              <Badge label={rule.status} />
            </div>
            <h2 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {rule.ruleName}
            </h2>
            <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              {rule.id} · {rule.vendor} · {rule.firewall}
            </span>
          </div>
          <button className="close-btn" onClick={onClose} id="drawer-close-btn">
            <X size={16} />
          </button>
        </div>

        <div className="drawer-body">
          {/* Risk Score */}
          <div className="card mb-2" style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div>
              <div className="kpi-label">Risk Score</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 700, color: riskColor(rule.riskScore) }}>
                {rule.riskScore}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {riskLabel(rule.riskScore)} severity
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <RiskBar score={rule.riskScore} showLabel={false} />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginTop: '0.75rem' }}>
                <div>
                  <div className="kpi-label">Action</div>
                  <Badge label={rule.action} />
                </div>
                <div>
                  <div className="kpi-label">Priority</div>
                  <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600 }}>#{rule.priority}</span>
                </div>
                <div>
                  <div className="kpi-label">Service</div>
                  <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--text-primary)' }}>{rule.service}</span>
                </div>
                <div>
                  <div className="kpi-label">Status</div>
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: rule.enabled ? 'var(--safe)' : 'var(--text-muted)' }}>
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Side-by-side comparison */}
          {shadowRule && (
            <>
              <div className="section-title" style={{ marginBottom: '0.5rem' }}>
                <Zap size={13} style={{ display: 'inline', marginRight: '0.35rem', verticalAlign: 'middle' }} />
                Policy Comparison
              </div>
              <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden', marginBottom: '1rem' }}>
                {/* column headers */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0', background: 'var(--bg-surface)', borderBottom: '1px solid var(--border)' }}>
                  <div style={{ padding: '0.6rem 1rem', borderRight: '1px solid var(--border)' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Selected Rule</span>
                    <div style={{ fontSize: '0.82rem', color: 'var(--critical)', fontWeight: 600 }}>{rule.ruleName}</div>
                  </div>
                  <div style={{ padding: '0.6rem 1rem' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                      {rule.status === 'Shadowed' ? 'Shadowed By' : 'Conflicts With'}
                    </span>
                    <div style={{ fontSize: '0.82rem', color: 'var(--safe)', fontWeight: 600 }}>{shadowRule.ruleName}</div>
                  </div>
                </div>
                <div style={{ padding: '0.25rem 1rem' }}>
                  <FieldRow label="Rule ID"        valA={rule.id}         valB={shadowRule.id} />
                  <FieldRow label="Source Zone"    valA={rule.srcZone}    valB={shadowRule.srcZone} />
                  <FieldRow label="Destination Zone" valA={rule.dstZone}  valB={shadowRule.dstZone} />
                  <FieldRow label="Source IP"      valA={rule.srcIp}      valB={shadowRule.srcIp} />
                  <FieldRow label="Destination IP" valA={rule.dstIp}      valB={shadowRule.dstIp} />
                  <FieldRow label="Service"        valA={rule.service}    valB={shadowRule.service} />
                  <FieldRow label="Action"         valA={rule.action}     valB={shadowRule.action} />
                  <FieldRow label="Priority"       valA={`#${rule.priority}`} valB={`#${shadowRule.priority}`} />
                  <FieldRow label="Risk Score"     valA={String(rule.riskScore)} valB={String(shadowRule.riskScore)} />
                </div>
              </div>
            </>
          )}

          {/* AI Insight */}
          {insight && (
            <div style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.25)', borderRadius: 10, padding: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <Brain size={15} color="#818cf8" />
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#818cf8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  AI Insight
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {insight}
              </p>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
