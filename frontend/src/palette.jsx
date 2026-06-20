import React from "react";
import { Icons } from "./icons";
import { useLFPM } from "./context/LFPMContext";
/* ─────────────────────────────────────────────────────────────────
 * Command Palette (⌘K) — global search/jump
 * ───────────────────────────────────────────────────────────────── */

const { useState: useStateP, useEffect: useEffectP, useRef: useRefP, useMemo: useMemoP } = React;

function CommandPalette({ open, onClose, onNavigate, onOpenInspector }) {
  const { data: LFPM } = useLFPM();
  const I = window.Icons;
  const [q, setQ] = useStateP('');
  const [idx, setIdx] = useStateP(0);
  const inputRef = useRefP(null);

  useEffectP(() => {
    if (open) {
      setQ('');
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  /* Compute grouped results */
  const results = useMemoP(() => {
    const term = q.trim().toLowerCase();
    const groups = [];

    /* Quick actions when query is empty */
    if (!term) {
      groups.push({
        title: 'jump to',
        items: [
          { id: 'jump:dashboard', kind:'jump', icon: I.Dashboard, label: 'Overview',           meta: 'go' },
          { id: 'jump:audit',     kind:'jump', icon: I.Audit,     label: 'Policy Audit',       meta: 'go' },
          { id: 'jump:topology',  kind:'jump', icon: I.Network,   label: 'Topology',           meta: 'go' },
          { id: 'jump:threats',   kind:'jump', icon: I.Threat,    label: 'Threat Intelligence',meta: 'go' },
        ],
      });
      groups.push({
        title: 'recent searches',
        items: LFPM.savedSearches.map(s => ({
          id: 'recent:' + s.id, kind:'recent', icon: I.Search, label: s.text, meta: s.owner,
        })),
      });
      return groups;
    }

    /* Filter rules */
    const rules = LFPM.policies.filter(p =>
      p.id.toLowerCase().includes(term) ||
      p.name.toLowerCase().includes(term) ||
      p.srcIp.toLowerCase().includes(term) ||
      p.dstIp.toLowerCase().includes(term) ||
      p.service.toLowerCase().includes(term)
    ).slice(0, 6).map(p => ({
      id: 'rule:' + p.id, kind: 'rule',
      icon: I.Audit, label: p.name, meta: p.id, payload: p,
    }));

    /* Filter firewalls */
    const fws = LFPM.firewalls.filter(f =>
      f.name.toLowerCase().includes(term) ||
      f.display.toLowerCase().includes(term) ||
      f.ip.includes(term) ||
      f.firmware.toLowerCase().includes(term)
    ).slice(0, 4).map(f => ({
      id: 'fw:' + f.id, kind: 'firewall',
      icon: I.Shield, label: f.display, meta: f.ip, payload: f,
    }));

    /* Filter CVEs */
    const cves = LFPM.threats.filter(t =>
      t.id.toLowerCase().includes(term) ||
      t.title.toLowerCase().includes(term)
    ).slice(0, 5).map(t => ({
      id: 'cve:' + t.id, kind: 'cve',
      icon: I.Bug, label: t.title, meta: t.id, payload: t,
    }));

    /* Filter hosts */
    const hosts = LFPM.assets.filter(a =>
      a.name.toLowerCase().includes(term) ||
      a.ip.includes(term)
    ).slice(0, 4).map(a => ({
      id: 'host:' + a.id, kind: 'host',
      icon: I.Server, label: a.name, meta: a.ip, payload: a,
    }));

    if (rules.length) groups.push({ title: 'rules', items: rules });
    if (fws.length)   groups.push({ title: 'firewalls', items: fws });
    if (cves.length)  groups.push({ title: 'cves', items: cves });
    if (hosts.length) groups.push({ title: 'hosts', items: hosts });

    if (!groups.length) groups.push({ title:'no matches', items: [] });
    return groups;
  }, [q, LFPM.policies, LFPM.firewalls, LFPM.threats, LFPM.assets, LFPM.savedSearches]);

  const flat = useMemoP(() => results.flatMap(g => g.items), [results]);

  useEffectP(() => { setIdx(0); }, [q]);

  const onKey = (e) => {
    if (e.key === 'Escape') { onClose(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(flat.length - 1, i + 1)); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setIdx(i => Math.max(0, i - 1)); }
    if (e.key === 'Enter')     {
      const item = flat[idx];
      if (!item) return;
      handlePick(item);
    }
  };

  const handlePick = (item) => {
    if (item.kind === 'jump') {
      onNavigate(item.id.split(':')[1]);
    } else if (item.kind === 'rule') {
      onOpenInspector({ kind:'rule', data: item.payload });
    } else if (item.kind === 'firewall') {
      onOpenInspector({ kind:'firewall', data: item.payload });
    } else if (item.kind === 'cve') {
      onOpenInspector({ kind:'cve', data: item.payload });
    } else if (item.kind === 'host') {
      onOpenInspector({ kind:'host', data: item.payload });
    } else if (item.kind === 'recent') {
      setQ(item.label);
      requestAnimationFrame(() => {
        const el = inputRef.current;
        if (!el) return;
        el.focus();
        const len = item.label.length;
        el.setSelectionRange(len, len);
      });
      return;
    }
    onClose();
  };

  if (!open) return null;
  return (
    <div className="palette-back" onClick={onClose}>
      <div className="palette" onClick={(e) => e.stopPropagation()}>
        <div className="palette-search">
          <I.Search size={15} style={{ color: 'var(--fg-2)' }} />
          <input
            ref={inputRef}
            value={q}
            placeholder="Search rules, firewalls, CVEs, hosts… or type a command"
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
            spellCheck={false}
          />
          <span className="kbd">esc</span>
        </div>
        <div className="palette-body">
          {results.map((g, gi) => (
            <div key={gi}>
              <div className="palette-group-title">{g.title}</div>
              {g.items.length === 0 && (
                <div className="palette-row" style={{ cursor:'default' }}>
                  <span className="muted" style={{ fontSize: 12 }}>no items</span>
                </div>
              )}
              {g.items.map((it) => {
                const Ico = it.icon;
                const flatIdx = flat.findIndex(f => f.id === it.id);
                const active = flatIdx === idx;
                return (
                  <div
                    key={it.id}
                    className={`palette-row ${active ? 'active' : ''}`}
                    onMouseEnter={() => setIdx(flatIdx)}
                    onClick={() => handlePick(it)}
                  >
                    <span className="ico"><Ico size={14} /></span>
                    <span className="label">{it.label}</span>
                    <span className="meta">{it.meta}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
        <div className="palette-footer">
          <span className="group"><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
          <span className="group"><span className="kbd">↵</span> open</span>
          <span className="group"><span className="kbd">esc</span> close</span>
          <div className="tb-spacer" />
          <span className="muted">{flat.length} result{flat.length === 1 ? '' : 's'}</span>
        </div>
      </div>
    </div>
  );
}
export { CommandPalette };
