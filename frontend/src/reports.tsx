import React, { useCallback, useEffect, useState } from 'react';
import { reports, inventory } from './lib/api';
import type { ReportSummary, ReportDetail, Rule, ReportScope } from './lib/api';

/* ─────────────────────────────────────────────────────────────────
 * SOC Reports — evidence-grounded AI analysis (Volume 10). The LLM
 * EXPLAINS deterministic findings; it never detects. Every report cites
 * the DB record IDs it was grounded on (evidence_refs).
 * ───────────────────────────────────────────────────────────────── */

function statusClass(s: string): string {
  return s === 'complete' ? 'safe' : s === 'partial' ? 'medium' : 'critical';
}

function fmtTime(iso: string | null): string {
  if (!iso) return '—';
  return iso.replace('T', ' ').slice(0, 19) + ' UTC';
}

/* Minimal, dependency-free markdown rendering for the report body. */
function inlineBold(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((p, i) =>
    p.startsWith('**') && p.endsWith('**')
      ? <strong key={i}>{p.slice(2, -2)}</strong>
      : <React.Fragment key={i}>{p}</React.Fragment>);
}

function renderMarkdown(md: string): React.ReactNode {
  const lines = md.split('\n');
  const out: React.ReactNode[] = [];
  let bullets: string[] = [];
  const flush = () => {
    if (bullets.length) {
      out.push(
        <ul key={`ul-${out.length}`} style={{ margin: '4px 0 10px', paddingLeft: 18 }}>
          {bullets.map((b, i) => <li key={i} style={{ marginBottom: 3 }}>{inlineBold(b)}</li>)}
        </ul>);
      bullets = [];
    }
  };
  lines.forEach((raw, i) => {
    const line = raw.trimEnd();
    if (/^#{1,2}\s+/.test(line)) {
      flush();
      out.push(<h3 key={i} style={{ margin: '14px 0 6px', fontSize: 14, color: 'var(--fg-0)' }}>{line.replace(/^#{1,2}\s+/, '')}</h3>);
    } else if (/^#{3,}\s+/.test(line)) {
      flush();
      out.push(<h4 key={i} style={{ margin: '10px 0 4px', fontSize: 12.5, color: 'var(--fg-1)' }}>{line.replace(/^#{3,}\s+/, '')}</h4>);
    } else if (/^\s*[-*]\s+/.test(line)) {
      bullets.push(line.replace(/^\s*[-*]\s+/, ''));
    } else if (line === '') {
      flush();
    } else {
      flush();
      out.push(<p key={i} style={{ margin: '0 0 8px', fontSize: 12.5, lineHeight: 1.6, color: 'var(--fg-1)' }}>{inlineBold(line)}</p>);
    }
  });
  flush();
  return out;
}

function EvidenceRefs({ refs }: { refs: Record<string, unknown> | null }) {
  if (!refs || !Object.keys(refs).length) return null;
  return (
    <div className="row gap-2" style={{ flexWrap: 'wrap', marginTop: 6 }}>
      {Object.entries(refs).map(([k, v]) => (
        <span key={k} className="chip" style={{ fontSize: 10.5 }}>
          {k.replace(/_/g, ' ')}: <span className="mono" style={{ color: 'var(--fg-1)' }}>{Array.isArray(v) ? v.join(', ') : String(v)}</span>
        </span>
      ))}
    </div>
  );
}

export function Reports() {
  const [list, setList] = useState<ReportSummary[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [selected, setSelected] = useState<ReportDetail | null>(null);
  const [scope, setScope] = useState<ReportScope>('executive');
  const [ruleId, setRuleId] = useState<number | ''>('');
  const [generating, setGenerating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const toast = (window as unknown as { toast?: (m: string, o?: unknown) => void }).toast;

  const refresh = useCallback(async () => {
    const res = await reports.list(50);
    setList(res.reports);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [rep, rls] = await Promise.all([reports.list(50), inventory.rules()]);
        if (cancelled) return;
        setList(rep.reports);
        setRules(rls);
        if (rls.length) setRuleId(rls[0].rule_id);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const open = async (id: number) => {
    try { setSelected(await reports.get(id)); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };

  const generate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const sid = scope === 'rule' && ruleId !== '' ? Number(ruleId) : undefined;
      const rep = await reports.generate(scope, sid);
      setSelected(rep);
      await refresh();
      toast?.(`Report ${rep.status}`, { kind: rep.status === 'complete' ? 'ok' : 'warn', sub: `${rep.provider} · ${rep.model}` });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast?.('Report generation failed', { kind: 'crit', sub: msg });
    } finally {
      setGenerating(false);
    }
  };

  const cardStyle: React.CSSProperties = {
    background: 'var(--bg-1)', border: '1px solid var(--bd-1)', borderRadius: 6, padding: '12px 14px',
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">SOC Reports</h1>
          <p className="page-sub">
            Evidence-grounded AI analysis · the LLM explains deterministic findings, it never detects · every claim cites DB record IDs
          </p>
        </div>
      </div>

      <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, minHeight: 0, overflow: 'hidden' }}>
        {/* Left: generate + list */}
        <div className="col" style={{ gap: 14, overflow: 'auto', minHeight: 0 }}>
          <div style={cardStyle}>
            <h4 style={{ margin: '0 0 10px', fontSize: 12, color: 'var(--fg-2)' }}>Generate</h4>
            <div className="row gap-2" style={{ marginBottom: 8 }}>
              {(['executive', 'rule'] as ReportScope[]).map(s => (
                <button
                  key={s}
                  className={`btn ${scope === s ? 'primary' : ''}`}
                  onClick={() => setScope(s)}
                  style={{ flex: 1 }}
                >{s === 'executive' ? 'Executive' : 'Per-rule'}</button>
              ))}
            </div>
            {scope === 'rule' && (
              <select
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value === '' ? '' : Number(e.target.value))}
                style={{
                  width: '100%', marginBottom: 8, padding: '6px 8px', fontSize: 12,
                  background: 'var(--bg-2)', color: 'var(--fg-1)', border: '1px solid var(--bd-1)', borderRadius: 4,
                }}
              >
                {rules.map(r => (
                  <option key={r.rule_id} value={r.rule_id}>
                    POL-{String(r.rule_id).padStart(3, '0')} · {r.rule_name}
                  </option>
                ))}
              </select>
            )}
            <button className="btn primary" disabled={generating} style={{ width: '100%' }} onClick={generate}>
              {generating ? 'generating…' : `Generate ${scope} report`}
            </button>
            {error && <div style={{ marginTop: 8, fontSize: 11, color: 'var(--sev-critical)' }}>{error}</div>}
          </div>

          <div>
            <h4 style={{ margin: '0 0 8px', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--fg-3)' }}>
              Reports ({list.length})
            </h4>
            <div className="col" style={{ gap: 6 }}>
              {loading && <div className="muted" style={{ fontSize: 12 }}>Loading…</div>}
              {!loading && list.length === 0 && <div className="muted" style={{ fontSize: 12 }}>No reports yet — generate one above.</div>}
              {list.map(r => (
                <div
                  key={r.report_id}
                  onClick={() => open(r.report_id)}
                  style={{
                    ...cardStyle, padding: '9px 11px', cursor: 'pointer',
                    borderColor: selected?.report_id === r.report_id ? 'var(--accent)' : 'var(--bd-1)',
                  }}
                >
                  <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className="mono strong" style={{ fontSize: 12 }}>
                      {r.scope_type === 'rule' ? `rule POL-${String(r.scope_id).padStart(3, '0')}` : 'executive'}
                    </span>
                    <span className={`stat-text ${statusClass(r.status)}`} style={{ fontSize: 10.5 }}>
                      <span className="dot" />{r.status}
                    </span>
                  </div>
                  <div className="muted mono" style={{ fontSize: 10.5, marginTop: 3 }}>
                    {r.provider} · {r.model} · {fmtTime(r.created_at)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: detail */}
        <div style={{ ...cardStyle, overflow: 'auto', minHeight: 0 }}>
          {!selected ? (
            <div className="muted" style={{ fontSize: 13, padding: 24, textAlign: 'center' }}>
              Select a report on the left, or generate a new one.
            </div>
          ) : (
            <>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div>
                  <div className="mono strong" style={{ fontSize: 14, color: 'var(--fg-0)' }}>
                    {selected.scope_type === 'rule' ? `Rule report · POL-${String(selected.scope_id).padStart(3, '0')}` : 'Executive summary'}
                  </div>
                  <div className="muted mono" style={{ fontSize: 11, marginTop: 2 }}>
                    {selected.provider} · {selected.model} · {selected.prompt_version} · {fmtTime(selected.created_at)}
                  </div>
                </div>
                <span className={`chip ${statusClass(selected.status)}`}>{selected.status}</span>
              </div>

              <div style={{ borderTop: '1px solid var(--bd-1)', paddingTop: 4 }}>
                <div style={{ fontSize: 10.5, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 6 }}>evidence</div>
                <EvidenceRefs refs={selected.evidence_refs} />
                {selected.confidence_note && (
                  <p style={{ margin: '8px 0 0', fontSize: 11, color: 'var(--fg-3)', fontStyle: 'italic' }}>{selected.confidence_note}</p>
                )}
              </div>

              <div style={{ borderTop: '1px solid var(--bd-1)', marginTop: 12, paddingTop: 10 }}>
                {selected.status === 'failed' && (
                  <div style={{ fontSize: 12, color: 'var(--sev-high)', marginBottom: 8 }}>
                    The LLM provider was unavailable; deterministic evidence above is unaffected (V10 §11).
                  </div>
                )}
                {selected.output ? renderMarkdown(selected.output) : <div className="muted">No output.</div>}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
