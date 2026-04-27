// Severity/status → badge class
export function severityClass(s) {
  if (!s) return 'badge-info';
  const v = s.toLowerCase();
  if (v === 'critical') return 'badge-critical';
  if (v === 'high')     return 'badge-high';
  if (v === 'medium')   return 'badge-medium';
  if (v === 'low')      return 'badge-low';
  if (v === 'safe' || v === 'clean') return 'badge-clean';
  if (v === 'shadowed') return 'badge-shadowed';
  if (v === 'redundant') return 'badge-redundant';
  if (v === 'overly permissive') return 'badge-permissive';
  if (v === 'allow')    return 'badge-allow';
  if (v === 'deny')     return 'badge-deny';
  return 'badge-info';
}

export function riskColor(score) {
  if (score >= 80) return 'var(--critical)';
  if (score >= 60) return 'var(--high)';
  if (score >= 40) return 'var(--medium)';
  if (score >= 20) return 'var(--low)';
  return 'var(--safe)';
}

export function riskLabel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 20) return 'Low';
  return 'Safe';
}

export function Badge({ label, variant }) {
  const cls = variant ?? severityClass(label);
  return <span className={`badge ${cls}`}>{label}</span>;
}

export function RiskBar({ score, showLabel = false }) {
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div
          className="risk-bar-fill"
          style={{ width: `${score}%`, background: riskColor(score) }}
        />
      </div>
      {showLabel && (
        <span style={{ fontSize: '0.75rem', fontWeight: 600, color: riskColor(score), minWidth: 28 }}>
          {score}
        </span>
      )}
    </div>
  );
}
