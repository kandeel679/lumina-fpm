import React, { useEffect, useState } from 'react';
import { risk, inventory } from './lib/api';
import type { RiskItem, Device, RiskFactorBreakdown } from './lib/api';

/* ─────────────────────────────────────────────────────────────────
 * Risk Posture — deterministic V8 risk (rules + devices) with factor
 * breakdowns. New TSX screen; consumes the typed API client directly.
 * ───────────────────────────────────────────────────────────────── */

function riskColor(score: number): string {
  if (score >= 80) return 'var(--sev-critical)';
  if (score >= 60) return 'var(--sev-high)';
  if (score >= 40) return 'var(--sev-medium)';
  if (score >= 20) return 'var(--sev-low)';
  return 'var(--sev-safe)';
}

function tierClass(tier: string): string {
  return ['critical', 'high', 'medium', 'low'].includes(tier) ? tier : 'safe';
}

function FactorChips({ factors }: { factors: RiskFactorBreakdown | null }) {
  if (!factors) return null;
  const entries = (Object.entries(factors).filter(([, v]) => typeof v === 'number') as [string, number][])
    .sort((a, b) => b[1] - a[1]);
  if (!entries.length) return null;
  return (
    <div className="row gap-2" style={{ flexWrap: 'wrap', marginTop: 6 }}>
      {entries.map(([k, v]) => (
        <span key={k} className="chip" style={{ fontSize: 10.5 }}>
          {k.replace(/_/g, ' ')} <span className="mono" style={{ color: 'var(--fg-1)' }}>+{v}</span>
        </span>
      ))}
    </div>
  );
}

interface RiskProps {
  goTo?: (page: string, params?: Record<string, string>) => void;
}

export function RiskPosture({ goTo }: RiskProps) {
  const [rules, setRules] = useState<RiskItem[]>([]);
  const [devices, setDevices] = useState<RiskItem[]>([]);
  const [deviceMeta, setDeviceMeta] = useState<Record<number, Device>>({});
  const [runId, setRunId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [rRes, dRes, devs] = await Promise.all([
          risk.list('rule', 200),
          risk.list('device', 50),
          inventory.devices(),
        ]);
        if (cancelled) return;
        setRules(rRes.items);
        setDevices(dRes.items);
        setRunId(rRes.analysis_run_id);
        const meta: Record<number, Device> = {};
        devs.forEach((d) => { meta[d.device_id] = d; });
        setDeviceMeta(meta);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const sectionTitle: React.CSSProperties = {
    fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5,
    color: 'var(--fg-3)', margin: '0 0 10px', fontWeight: 600,
  };
  const cardStyle: React.CSSProperties = {
    background: 'var(--bg-1)', border: '1px solid var(--bd-1)', borderRadius: 6,
    padding: '14px 16px', minWidth: 220, flex: '1 1 240px',
  };

  if (loading) {
    return (
      <div className="page">
        <div className="page-head"><h1 className="page-title">Risk Posture</h1></div>
        <div style={{ padding: 40, color: 'var(--fg-3)' }}>Loading deterministic risk…</div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="page">
        <div className="page-head"><h1 className="page-title">Risk Posture</h1></div>
        <div style={{ padding: 40, color: 'var(--sev-critical)' }}>Failed to load risk: {error}</div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Risk Posture</h1>
          <p className="page-sub">
            Deterministic V8 scoring · run #{runId ?? '—'} · {devices.length} devices · {rules.length} rules
          </p>
        </div>
      </div>

      {/* Tier legend (V8 thresholds) */}
      <div className="row gap-3" style={{ padding: '0 0 14px', flexWrap: 'wrap' }}>
        {([['critical', '90–100'], ['high', '70–89'], ['medium', '40–69'], ['low', '1–39']] as const).map(([t, range]) => (
          <span key={t} className={`stat-text ${tierClass(t)}`} style={{ fontSize: 11 }}>
            <span className="dot" />{t} <span className="muted">{range}</span>
          </span>
        ))}
      </div>

      <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Device risk */}
        <section>
          <h4 style={sectionTitle}>Device risk</h4>
          <div className="row gap-3" style={{ flexWrap: 'wrap' }}>
            {devices.map((d) => {
              const meta = deviceMeta[d.scope_id];
              return (
                <div key={d.scope_id} style={cardStyle}>
                  <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="mono strong" style={{ color: 'var(--fg-0)' }}>{meta?.hostname || `device ${d.scope_id}`}</span>
                    <span className={`chip ${tierClass(d.risk_tier)}`}>{d.risk_tier}</span>
                  </div>
                  <div style={{ fontSize: 34, fontFamily: 'var(--f-mono)', color: riskColor(d.risk_score), fontWeight: 600, marginTop: 4 }}>
                    {d.risk_score}
                  </div>
                  <div className="muted mono" style={{ fontSize: 11 }}>{meta?.vendor_type || ''}</div>
                  <FactorChips factors={d.factor_breakdown} />
                </div>
              );
            })}
          </div>
        </section>

        {/* Top risky rules */}
        <section>
          <h4 style={sectionTitle}>Top risky rules</h4>
          <table className="t">
            <thead>
              <tr>
                <th style={{ textAlign: 'right' }}>#</th>
                <th>rule</th>
                <th>device</th>
                <th>vendor</th>
                <th style={{ textAlign: 'right' }}>risk</th>
                <th>tier</th>
                <th>factors</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => {
                const meta = r.device_id != null ? deviceMeta[r.device_id] : undefined;
                const pol = `POL-${String(r.scope_id).padStart(3, '0')}`;
                return (
                  <tr
                    key={r.scope_id}
                    style={{ cursor: goTo ? 'pointer' : 'default' }}
                    onClick={() => goTo && goTo('audit', { rule: pol })}
                  >
                    <td className="num dim">{i + 1}</td>
                    <td>
                      <span className="mono strong">{r.rule_name || `rule ${r.scope_id}`}</span>
                      <span className="mono dim" style={{ fontSize: 10.5, marginLeft: 6 }}>{pol}</span>
                    </td>
                    <td className="mono dim">{meta?.hostname || r.device_id || '—'}</td>
                    <td className="dim">{r.vendor_type || meta?.vendor_type || '—'}</td>
                    <td className="num" style={{ color: riskColor(r.risk_score), fontWeight: 600 }}>{r.risk_score}</td>
                    <td>
                      <span className={`stat-text ${tierClass(r.risk_tier)}`}>
                        <span className="dot" />{r.risk_tier}
                      </span>
                    </td>
                    <td><FactorChips factors={r.factor_breakdown} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}
