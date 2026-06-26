import React, { useCallback, useEffect, useState } from 'react';
import { reports, inventory } from './lib/api';
import type { ReportSummary, ReportDetail, Rule, ReportScope, SocDocument } from './lib/api';

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

function sevClass(s: string): string {
  return ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'safe';
}

const TH: React.CSSProperties = { textAlign: 'left' };

/* Deterministic structured report — DOM tables (renderMarkdown can't render tables). */
function DocumentView({ doc }: { doc: SocDocument }) {
  const t = doc.totals;
  const h: React.CSSProperties = { fontSize: 12.5, color: 'var(--fg-1)', margin: '16px 0 6px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.4 };
  const factors = (fb: Record<string, number> | null) =>
    fb ? Object.entries(fb).filter(([, v]) => typeof v === 'number').map(([k, v]) => `${k.replace(/_/g, ' ')} ${v}`).join(' · ') : '—';
  return (
    <div className="col" style={{ gap: 4 }}>
      <div className="row gap-3" style={{ flexWrap: 'wrap', fontSize: 11.5 }}>
        <span className="muted">findings <strong style={{ color: 'var(--fg-0)' }}>{t.open_findings}</strong></span>
        <span className="muted">rules <strong style={{ color: 'var(--fg-0)' }}>{t.rules_with_findings}</strong></span>
        <span className="muted">devices <strong style={{ color: 'var(--fg-0)' }}>{t.devices}</strong></span>
        {Object.entries(t.tier_counts).sort().map(([k, v]) => (
          <span key={k} className={`stat-text ${sevClass(k)}`}><span className="dot" />{k} {v}</span>
        ))}
      </div>

      <h4 style={h}>Prioritized remediation</h4>
      <table className="t">
        <thead><tr><th style={TH}>#</th><th style={TH}>rule</th><th style={TH}>device</th><th style={TH}>anomalies</th><th style={TH}>sev</th><th style={{ textAlign: 'right' }}>risk</th><th style={TH}>recommendation</th></tr></thead>
        <tbody>
          {doc.remediation.map((r) => (
            <tr key={r.pol}>
              <td className="num dim">{r.priority}</td>
              <td><span className="mono strong">{r.pol}</span> <span className="dim" style={{ fontSize: 11 }}>{r.rule_name}</span></td>
              <td className="mono dim" style={{ fontSize: 11 }}>{r.device}</td>
              <td className="dim" style={{ fontSize: 11 }}>{r.anomaly_types.join(', ')}</td>
              <td><span className={`chip ${sevClass(r.max_severity)}`} style={{ fontSize: 10 }}>{r.max_severity}</span></td>
              <td className="num strong" style={{ textAlign: 'right' }}>{r.risk_score}</td>
              <td style={{ fontSize: 11.5 }}>{r.recommendation}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4 style={h}>Risk posture</h4>
      <table className="t">
        <thead><tr><th style={TH}>device</th><th style={TH}>vendor</th><th style={TH}>firmware</th><th style={{ textAlign: 'right' }}>risk</th><th style={TH}>tier</th><th style={TH}>factors</th></tr></thead>
        <tbody>
          {doc.risk_posture.devices.map((d) => (
            <tr key={d.device}>
              <td className="mono strong">{d.device}</td>
              <td className="dim">{d.vendor_type || '—'}</td>
              <td className="mono dim" style={{ fontSize: 11 }}>{d.firmware || '—'}</td>
              <td className="num strong" style={{ textAlign: 'right' }}>{d.risk_score}</td>
              <td><span className={`stat-text ${sevClass(d.risk_tier)}`}><span className="dot" />{d.risk_tier}</span></td>
              <td className="dim" style={{ fontSize: 11 }}>{factors(d.factor_breakdown)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {doc.firmware_cves.length > 0 && (
        <>
          <h4 style={h}>Firmware vulnerabilities <span className="muted" style={{ textTransform: 'none', fontWeight: 400, fontSize: 10.5 }}>· device axis, excluded from the config benchmark</span></h4>
          {doc.firmware_cves.map((fc) => (
            <div key={fc.device} style={{ marginBottom: 8 }}>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--fg-1)', marginBottom: 3 }}>
                {fc.device} · {fc.vendor_type} {fc.firmware} <span className="chip high" style={{ fontSize: 10 }}>+{fc.firmware_modifier} risk</span>
              </div>
              <table className="t">
                <thead><tr><th style={TH}>CVE</th><th style={TH}>sev</th><th style={TH}>provider</th><th style={TH}>summary</th></tr></thead>
                <tbody>
                  {fc.cves.map((c, i) => (
                    <tr key={i}>
                      <td className="mono">{(c.reference || '').split('/').pop()}</td>
                      <td><span className={`chip ${sevClass(c.severity)}`} style={{ fontSize: 10 }}>{c.severity}</span></td>
                      <td className="dim" style={{ fontSize: 11 }}>{c.provider}</td>
                      <td style={{ fontSize: 11 }}>{c.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </>
      )}

      <h4 style={h}>Per-finding evidence</h4>
      {doc.evidence.map((e) => (
        <div key={e.pol} style={{ marginBottom: 10 }}>
          <div className="mono" style={{ fontSize: 11.5, color: 'var(--fg-1)', marginBottom: 3 }}>
            {e.pol} {e.rule_name} <span className="dim">· risk {e.risk_score} ({e.risk_tier})</span>
          </div>
          <table className="t">
            <thead><tr><th style={TH}>id</th><th style={TH}>type</th><th style={TH}>sev</th><th style={TH}>mode</th><th style={TH}>recommendation</th></tr></thead>
            <tbody>
              {e.findings.map((f) => (
                <tr key={f.anomaly_id}>
                  <td className="num dim">{f.anomaly_id}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{f.anomaly_type}</td>
                  <td><span className={`chip ${sevClass(f.severity)}`} style={{ fontSize: 10 }}>{f.severity}</span></td>
                  <td className="dim" style={{ fontSize: 10.5 }}>{f.detection_mode}</td>
                  <td style={{ fontSize: 11 }}>{f.recommendation || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

/* Standalone, dependency-free print HTML (browser "Save as PDF" handles the rest). */
function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c] as string));
}
function htmlTable(headers: string[], rows: (string | number | null)[][]): string {
  return `<table><thead><tr>${headers.map((x) => `<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function buildPrintHtml(rep: ReportDetail): string {
  const doc = rep.document;
  const summary = rep.executive_summary || rep.output || '';
  let body = '';
  if (doc) {
    body += `<h2>Prioritized Remediation</h2>` + htmlTable(
      ['#', 'Rule', 'Device', 'Anomalies', 'Severity', 'Risk', 'Recommendation'],
      doc.remediation.map((r) => [r.priority, `${r.pol} ${r.rule_name}`, r.device, r.anomaly_types.join(', '), r.max_severity, `${r.risk_score} (${r.risk_tier})`, r.recommendation]));
    body += `<h2>Risk Posture</h2>` + htmlTable(
      ['Device', 'Vendor', 'Firmware', 'Risk', 'Tier'],
      doc.risk_posture.devices.map((d) => [d.device, d.vendor_type || '—', d.firmware || '—', d.risk_score, d.risk_tier]));
    if (doc.firmware_cves.length) {
      body += `<h2>Firmware Vulnerabilities <span class="muted">(device axis · excluded from the config benchmark)</span></h2>`;
      body += doc.firmware_cves.map((fc) => `<h3>${esc(fc.device)} — ${esc(fc.vendor_type)} ${esc(fc.firmware)} (+${fc.firmware_modifier} risk)</h3>` +
        htmlTable(['CVE', 'Severity', 'Provider', 'Summary'], fc.cves.map((c) => [(c.reference || '').split('/').pop() || '', c.severity, c.provider, c.summary]))).join('');
    }
    body += `<h2>Per-Finding Evidence</h2>` + doc.evidence.map((e) => `<h3>${esc(e.pol)} ${esc(e.rule_name)} — risk ${e.risk_score} (${e.risk_tier})</h3>` +
      htmlTable(['anomaly_id', 'type', 'severity', 'mode', 'recommendation'], e.findings.map((f) => [f.anomaly_id, f.anomaly_type, f.severity, f.detection_mode, f.recommendation || '—']))).join('');
  }
  return `<!doctype html><html><head><meta charset="utf-8"><title>SOC Report ${rep.report_id}</title>
<style>body{font-family:system-ui,'Segoe UI',Arial,sans-serif;color:#111;max-width:920px;margin:24px auto;padding:0 16px;font-size:12px;}
h1{font-size:20px;margin-bottom:2px;} h2{font-size:15px;border-bottom:1px solid #ccc;padding-bottom:3px;margin-top:22px;} h3{font-size:12.5px;margin:14px 0 4px;color:#333;}
.muted{color:#888;font-weight:400;font-size:11px;} .meta{color:#666;font-size:11px;margin-bottom:6px;}
table{border-collapse:collapse;width:100%;margin:6px 0 12px;} th,td{border:1px solid #ccc;padding:4px 7px;text-align:left;vertical-align:top;} th{background:#f3f3f3;}
.summary{white-space:pre-wrap;line-height:1.55;}</style></head>
<body><h1>${esc(doc?.title || 'LuminaFPM SOC Report')}</h1>
<div class="meta">${esc(rep.provider)} · ${esc(rep.model)} · ${esc(rep.prompt_version)} · run #${esc(doc?.analysis_run_id ?? '')}</div>
<h2>Executive Summary</h2><div class="summary">${esc(summary)}</div>${body}</body></html>`;
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

  const downloadMd = () => {
    if (!selected?.markdown) return;
    const blob = new Blob([selected.markdown], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `lumina-soc-report-${selected.report_id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const downloadPdf = () => {
    if (!selected) return;
    const w = window.open('', '_blank');
    if (!w) { toast?.('Pop-up blocked', { kind: 'warn', sub: 'Allow pop-ups to export the PDF' }); return; }
    w.document.write(buildPrintHtml(selected));
    w.document.close();
    w.focus();
    setTimeout(() => w.print(), 300);
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
                <div className="row gap-2" style={{ alignItems: 'center' }}>
                  <button className="btn" style={{ fontSize: 11, padding: '3px 9px' }} disabled={!selected.markdown} onClick={downloadMd}>↓ .md</button>
                  <button className="btn" style={{ fontSize: 11, padding: '3px 9px' }} onClick={downloadPdf}>↓ PDF</button>
                  <span className={`chip ${statusClass(selected.status)}`}>{selected.status}</span>
                </div>
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
                    The LLM provider was unavailable; the deterministic report below is unaffected (V10 §11).
                  </div>
                )}
                {(selected.executive_summary || (!selected.document && selected.output)) && (
                  <div style={{ marginBottom: selected.document ? 12 : 0 }}>
                    {renderMarkdown(selected.executive_summary || selected.output || '')}
                  </div>
                )}
                {selected.document
                  ? <DocumentView doc={selected.document} />
                  : (!selected.output && <div className="muted">No output.</div>)}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
