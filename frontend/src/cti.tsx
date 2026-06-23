import React, { useCallback, useEffect, useState } from 'react';
import { cti, anomalies } from './lib/api';
import type { CtiIndicator, Anomaly } from './lib/api';

/* ─────────────────────────────────────────────────────────────────
 * CTI / Threat Center (Volume 9) — API-based indicator enrichment.
 * Shows the real indicators extracted from firewall objects, their
 * provider verdicts, and the ALLOW rules the engine flagged
 * (threat_exposure). CTI is NOT an anomaly by default — it feeds risk
 * and a labeled exposure finding. Internal indicators never leave the
 * platform (data minimization).
 * ───────────────────────────────────────────────────────────────── */

function sevClass(sev: string): string {
  const s = (sev || '').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'safe';
}

export function CtiCenter() {
  const [indicators, setIndicators] = useState<CtiIndicator[]>([]);
  const [exposures, setExposures] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toast = (window as unknown as { toast?: (m: string, o?: unknown) => void }).toast;

  const load = useCallback(async () => {
    const [c, a] = await Promise.all([
      cti.list(),
      anomalies.list({ anomaly_type: 'threat_exposure', page_size: 200 }),
    ]);
    setIndicators(c.indicators);
    setExposures(a.items);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try { await load(); }
      catch (e) { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); }
      finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [load]);

  const runEnrichment = async () => {
    setRunning(true);
    setError(null);
    try {
      const r = await cti.run();
      await load();
      toast?.('CTI enrichment complete', {
        kind: 'ok',
        sub: `${r.malicious_indicators} malicious · ${r.indicators_enriched} enriched · ${r.threat_exposure_findings} exposures · [${r.providers.join(', ')}]`,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast?.('CTI enrichment failed', { kind: 'crit', sub: msg });
    } finally {
      setRunning(false);
    }
  };

  // indicator value -> affected ALLOW rules (deduped across runs)
  const rulesByIndicator: Record<string, Set<string>> = {};
  exposures.forEach((a) => {
    const ind = a.evidence && typeof a.evidence.indicator === 'string' ? a.evidence.indicator : null;
    if (!ind) return;
    (rulesByIndicator[ind] ||= new Set()).add(`POL-${String(a.rule_id).padStart(3, '0')}`);
  });

  const malicious = indicators.filter((i) => i.malicious).length;

  return (
    <div className="col" style={{ gap: 12, minHeight: 0, overflow: 'auto' }}>
      <div className="row" style={{ alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div className="row gap-3" style={{ flexWrap: 'wrap' }}>
          <span className="muted">indicators <strong style={{ color: 'var(--fg-0)' }}>{indicators.length}</strong></span>
          <span className="muted">malicious <strong style={{ color: malicious ? 'var(--sev-critical)' : 'var(--fg-0)' }}>{malicious}</strong></span>
          <span className="muted">exposures <strong style={{ color: 'var(--fg-0)' }}>{exposures.length}</strong></span>
        </div>
        <button className="btn primary" style={{ marginLeft: 'auto' }} disabled={running} onClick={runEnrichment}>
          {running ? 'enriching…' : 'run enrichment'}
        </button>
      </div>

      <div style={{ fontSize: 11, color: 'var(--fg-3)' }}>
        API-based providers only · internal (RFC1918) indicators are never sent to external services (V9 data minimization).
      </div>

      {error && <div style={{ fontSize: 12, color: 'var(--sev-critical)' }}>{error}</div>}

      <table className="t">
        <thead>
          <tr>
            <th>indicator</th>
            <th>type</th>
            <th>status</th>
            <th>provider</th>
            <th>threat</th>
            <th>conf.</th>
            <th>affected rules</th>
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr><td colSpan={7}><div style={{ padding: 24, color: 'var(--fg-3)' }}>Loading indicators…</div></td></tr>
          )}
          {!loading && indicators.length === 0 && (
            <tr><td colSpan={7}>
              <div style={{ padding: 24, color: 'var(--fg-3)', textAlign: 'center' }}>
                No enriched indicators yet — run enrichment to extract & score indicators from firewall objects.
              </div>
            </td></tr>
          )}
          {indicators.map((ind) => {
            const obs = ind.observations[0];
            const rules = [...(rulesByIndicator[ind.value] || [])];
            return (
              <tr key={ind.indicator_id}>
                <td className="mono strong">{ind.value}</td>
                <td className="mono dim" style={{ fontSize: 11 }}>{ind.type}</td>
                <td>
                  {ind.malicious
                    ? <span className={`stat-text ${sevClass(obs?.severity || 'high')}`}><span className="dot" />malicious</span>
                    : <span className="stat-text safe"><span className="dot" />clean</span>}
                </td>
                <td className="mono dim" style={{ fontSize: 11 }}>{obs?.provider || '—'}</td>
                <td className="dim" style={{ fontSize: 11.5 }}>{obs?.threat_type || '—'}</td>
                <td className="num dim">{obs?.confidence != null ? `${Math.round(obs.confidence * 100)}%` : '—'}</td>
                <td>
                  {rules.length
                    ? <span className="row gap-2" style={{ flexWrap: 'wrap' }}>{rules.map((r) => <span key={r} className="chip" style={{ fontSize: 10.5 }}>{r}</span>)}</span>
                    : <span className="muted">—</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
