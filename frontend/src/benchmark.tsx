import React, { useCallback, useEffect, useRef, useState } from 'react';
import { benchmark } from './lib/api';
import type { BenchmarkRunResult, BenchmarkReport, BenchmarkCase } from './lib/api';

/* ─────────────────────────────────────────────────────────────────
 * Benchmark Center (Volume 7) — scores the deterministic anomaly engine
 * against the ground-truth matrix. This is the acceptance gate and the
 * regression guard: precision / recall / F1 / severity-match, with the
 * per-type and per-case breakdown. Pure DB analysis; no firewall touched.
 * ───────────────────────────────────────────────────────────────── */

function pct(x: number | undefined): string {
  return x == null ? '—' : `${(x * 100).toFixed(1)}%`;
}

function scoreColor(x: number | undefined): string {
  if (x == null) return 'var(--fg-1)';
  if (x >= 0.999) return 'var(--sev-safe)';
  if (x >= 0.9) return 'var(--sev-medium)';
  return 'var(--sev-critical)';
}

function Metric({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ background: 'var(--bg-1)', border: '1px solid var(--bd-1)', borderRadius: 6, padding: '12px 16px', minWidth: 120, flex: '1 1 120px' }}>
      <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--fg-3)' }}>{label}</div>
      <div style={{ fontSize: 26, fontFamily: 'var(--f-mono)', fontWeight: 600, color: color || 'var(--fg-0)', marginTop: 2 }}>{value}</div>
    </div>
  );
}

export function BenchmarkCenter() {
  const [run, setRun] = useState<BenchmarkRunResult | null>(null);
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toast = (window as unknown as { toast?: (m: string, o?: unknown) => void }).toast;

  const load = useCallback(async () => {
    // Sequential, not concurrent: run() re-scores (deletes + reinserts the
    // benchmark rows), so reading the per-case report() must wait for it to
    // finish — otherwise report() can read mid-rewrite and 500.
    const r = await benchmark.run();
    setRun(r);
    try {
      const rep = await benchmark.report();
      setReport(rep);
    } catch {
      // per-case detail is supplementary; the headline metrics already rendered.
      setReport(null);
    }
  }, []);

  // Guard against React StrictMode's dev double-invoke (two concurrent re-scores).
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    (async () => {
      try { await load(); }
      catch (e) { setError(e instanceof Error ? e.message : String(e)); }
      finally { setLoading(false); }
    })();
  }, [load]);

  const rerun = async () => {
    setRunning(true);
    setError(null);
    try {
      await load();
      toast?.('Benchmark re-scored', { kind: 'ok', sub: 'engine output vs ground truth' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast?.('Benchmark failed', { kind: 'crit', sub: msg });
    } finally {
      setRunning(false);
    }
  };

  const m = run?.metrics;
  const byType = run?.by_type || {};
  const cases: BenchmarkCase[] = Array.isArray(report?.cases) ? report.cases : [];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Benchmark Center</h1>
          <p className="page-sub">
            Deterministic engine vs ground-truth matrix · acceptance gate &amp; regression guard · run #{run?.analysis_run_id ?? '—'}
          </p>
        </div>
        <button className="btn primary" style={{ marginLeft: 'auto' }} disabled={running || loading} onClick={rerun}>
          {running ? 'scoring…' : 're-run benchmark'}
        </button>
      </div>

      {error && <div style={{ fontSize: 12, color: 'var(--sev-critical)', marginBottom: 10 }}>{error}</div>}
      {loading && <div style={{ padding: 24, color: 'var(--fg-3)' }}>Scoring against ground truth…</div>}

      {!loading && m && (
        <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Headline metrics */}
          <div className="row gap-3" style={{ flexWrap: 'wrap' }}>
            <Metric label="precision" value={pct(m.precision)} color={scoreColor(m.precision)} />
            <Metric label="recall"    value={pct(m.recall)}    color={scoreColor(m.recall)} />
            <Metric label="f1"        value={pct(m.f1)}        color={scoreColor(m.f1)} />
            <Metric label="severity match" value={pct(m.severity_match_rate)} color={scoreColor(m.severity_match_rate)} />
            <Metric label="tp" value={String(m.tp)} color="var(--sev-safe)" />
            <Metric label="fp" value={String(m.fp)} color={m.fp ? 'var(--sev-critical)' : 'var(--fg-1)'} />
            <Metric label="fn" value={String(m.fn)} color={m.fn ? 'var(--sev-critical)' : 'var(--fg-1)'} />
            <Metric label="cases" value={String(m.expected_cases)} />
          </div>

          {/* Per-type coverage */}
          <section>
            <h4 style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--fg-3)', margin: '0 0 10px' }}>
              Coverage by anomaly type
            </h4>
            <table className="t">
              <thead>
                <tr><th>anomaly type</th><th style={{ textAlign: 'right' }}>expected</th><th style={{ textAlign: 'right' }}>detected</th><th style={{ textAlign: 'right' }}>gap</th></tr>
              </thead>
              <tbody>
                {Object.entries(byType).sort((a, b) => b[1].expected - a[1].expected).map(([type, v]) => {
                  const gap = v.expected - v.detected;
                  return (
                    <tr key={type}>
                      <td className="mono strong">{type.replace(/_/g, ' ')}</td>
                      <td className="num dim">{v.expected}</td>
                      <td className="num" style={{ color: v.detected === v.expected ? 'var(--sev-safe)' : 'var(--fg-1)' }}>{v.detected}</td>
                      <td className="num" style={{ color: gap ? 'var(--sev-critical)' : 'var(--fg-3)' }}>{gap ? `-${gap}` : '0'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>

          {/* Per-case detail */}
          <section>
            <h4 style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--fg-3)', margin: '0 0 10px' }}>
              Expected cases ({cases.length})
            </h4>
            <table className="t">
              <thead>
                <tr><th>anomaly type</th><th>case</th><th>expected sev</th><th>result</th><th>severity</th><th>rules</th></tr>
              </thead>
              <tbody>
                {cases.map((c, i) => (
                  <tr key={i}>
                    <td className="mono strong">{c.anomaly_type.replace(/_/g, ' ')}</td>
                    <td className="dim" style={{ fontSize: 11.5 }}>{c.case_type}</td>
                    <td><span className={`chip ${['critical', 'high', 'medium', 'low'].includes(c.expected_severity) ? c.expected_severity : 'safe'}`}>{c.expected_severity}</span></td>
                    <td>
                      {c.detected
                        ? <span className="stat-text safe"><span className="dot" />TP</span>
                        : <span className="stat-text critical"><span className="dot" />FN</span>}
                    </td>
                    <td>
                      <span className="stat-text" style={{ color: c.match_quality === 'exact' ? 'var(--sev-safe)' : 'var(--fg-3)' }}>
                        {c.match_quality}
                      </span>
                    </td>
                    <td className="mono dim" style={{ fontSize: 11 }}>
                      {c.rule_a_id != null ? `POL-${String(c.rule_a_id).padStart(3, '0')}` : '—'}
                      {c.rule_b_id != null ? ` ⇄ POL-${String(c.rule_b_id).padStart(3, '0')}` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      )}
    </div>
  );
}
