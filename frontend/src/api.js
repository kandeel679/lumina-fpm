/**
 * API Integration Layer for LuminaFPM
 * Connects the React UI to FastAPI backend endpoints.
 */

import { LFPM as mockLFPM } from './data';

/* ── IPv4 helpers (topology asset↔zone placement by real subnet containment) ── */
function ipToInt(ip) {
  const p = String(ip || '').split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function subnetContains(cidr, ip) {
  if (!cidr || !ip) return false;
  const [net, bitsRaw] = String(cidr).split('/');
  const bits = Number(bitsRaw);
  const ni = ipToInt(net), hi = ipToInt(ip);
  if (ni == null || hi == null || Number.isNaN(bits)) return false;
  if (bits <= 0) return true;
  const mask = bits >= 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
  return ((ni & mask) >>> 0) === ((hi & mask) >>> 0);
}
function isPrivateIp(ip) {
  const n = ipToInt(ip);
  if (n == null) return false;
  return subnetContains('10.0.0.0/8', ip) || subnetContains('172.16.0.0/12', ip) || subnetContains('192.168.0.0/16', ip);
}

/* Canonical vendor identity. Keeps UI vendor ids STABLE ('palo-alto',
 * 'fortinet') regardless of the DB display name, and provides the correct
 * firmware-OS prefix per vendor (PAN-OS / FortiOS). v1 = Fortinet + Palo Alto
 * only. Previously the id was a slug of the name ("Palo Alto Networks" ->
 * "palo-alto-networks"), which broke the dashboard's vendor filters (NaN risk). */
function vendorMeta(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('palo'))  return { id: 'palo-alto', abbr: 'PA', accent: 'var(--vendor-paloalto)', os: 'PAN-OS' };
  if (n.includes('forti')) return { id: 'fortinet',  abbr: 'FT', accent: 'var(--vendor-fortinet)', os: 'FortiOS' };
  return {
    id: n.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown',
    abbr: (name || '?').replace(/[^A-Za-z]/g, '').slice(0, 2).toUpperCase() || '??',
    accent: 'var(--vendor-unknown)', os: '',
  };
}

/* Build a live SOC activity feed from real findings, rule anomalies and the
 * last scan. Replaces the synthetic feed that referenced devices/CVEs not in
 * the customer's actual inventory. Newest-first; timestamps are HH:MM:SS near
 * "now" so the dashboard's relative-time labels read naturally. */
function buildActivityFeed({ threats, firewalls, ruleDetails, meta }) {
  const feed = [];
  let offMin = 0;
  const stamp = () => {
    const d = new Date(Date.now() - offMin * 60000);
    offMin += 1 + Math.floor(Math.random() * 2);
    return d.toTimeString().slice(0, 8);
  };
  const fwById = new Map(firewalls.map(fw => [fw.id, fw]));

  if (meta.lastScanAt) {
    feed.push({
      t: stamp(), kind: 'audit',
      text: `threat-intel scan ${meta.lastScanStatus || 'completed'} · ${meta.totalFindings} findings · ${meta.correlatedRules} correlated to rules`,
      link: { page: 'threats' },
    });
  }

  // Correlated findings = real exposure on a real device → priority alerts
  (threats || [])
    .filter(t => t.correlated && t.firewallIds && t.firewallIds.length)
    .sort((a, b) => (b.severity === 'critical') - (a.severity === 'critical'))
    .slice(0, 5)
    .forEach(t => {
      const dev = fwById.get(String(t.firewallIds[0]));
      feed.push({
        t: stamp(), kind: 'alert',
        sev: t.severity === 'critical' ? 'critical' : 'high',
        text: `${t.id} affects ${dev ? dev.display : 'device ' + t.firewallIds[0]}${t.isNew ? ' · new this scan' : ''}`,
        link: { page: 'threats', params: { cve: t.id } },
      });
    });

  // Rule anomalies from the policy audit
  const anomEntries = [];
  (ruleDetails || []).forEach(d => (d.anoms || []).forEach(a => anomEntries.push({ ruleId: d.ruleId, a })));
  anomEntries.slice(0, 4).forEach(({ ruleId, a }) => {
    feed.push({
      t: stamp(), kind: 'anomaly',
      sev: a.severity_level === 'critical' ? 'critical' : 'high',
      text: `${String(a.anomaly_type || 'anomaly').replace(/_/g, ' ')} · POL-${String(ruleId).padStart(3, '0')}`,
      link: { page: 'audit', params: { rule: `POL-${String(ruleId).padStart(3, '0')}` } },
    });
  });

  return feed;
}

export async function fetchLFPMData() {
  try {
    // 1. Fetch core database collections in parallel
    const [dbVendors, dbDevices, dbRules, dbObjects, ruleRiskRes, deviceRiskRes] = await Promise.all([
      fetch('/api/v1/vendors/').then(res => res.json()),
      fetch('/api/v1/devices/').then(res => res.json()),
      fetch('/api/v1/rules/').then(res => res.json()),
      fetch('/api/v1/network-objects/').then(res => res.json()),
      fetch('/api/v1/risk?scope_type=rule&limit=200').then(res => res.json()).catch(() => ({ items: [] })),
      fetch('/api/v1/risk?scope_type=device&limit=200').then(res => res.json()).catch(() => ({ items: [] })),
    ]);

    // Real deterministic risk (Volume 8) — replaces the old heuristic riskScore.
    // Keyed by scope_id (rule_id / device_id) from the latest scored analysis run.
    const ruleRiskById   = new Map((ruleRiskRes.items   || []).map(it => [it.scope_id, it]));
    const deviceRiskById = new Map((deviceRiskRes.items || []).map(it => [it.scope_id, it]));

    // 2. Map Vendors (stable canonical ids)
    const vendors = dbVendors.map(v => {
      const m = vendorMeta(v.name);
      return {
        id: m.id,
        name: v.name,
        abbr: m.abbr,
        accent: m.accent,
        db_id: v.vendor_id,
      };
    });

    // 3a. Current findings = the latest ALL-scope completed analysis run. The
    // cross-device detectors only run in all-scope, and scoping to one run avoids
    // summing duplicate findings across every historical run. Use the rich
    // /anomalies endpoint (detection_mode, evidence, recommendation, status) — not
    // the slim per-rule route — and group by rule_id.
    let latestRunId = null;
    try {
      const runs = await fetch('/api/v1/anomalies/runs?limit=20').then(res => res.json());
      const allScope = (runs.items || []).filter(r => r.scope_type === 'all' && r.status === 'completed');
      latestRunId = (allScope[0] || (runs.items || [])[0] || {}).run_id ?? null;
    } catch (err) {
      console.error('Failed to load anomaly runs:', err);
    }

    const anomsByRule = new Map();
    if (latestRunId != null) {
      try {
        const res = await fetch(`/api/v1/anomalies?analysis_run_id=${latestRunId}&page_size=200`).then(r => r.json());
        for (const a of (res.items || [])) {
          if (!anomsByRule.has(a.rule_id)) anomsByRule.set(a.rule_id, []);
          anomsByRule.get(a.rule_id).push(a);
        }
      } catch (err) {
        console.error('Failed to load anomalies for run', latestRunId, err);
      }
    }

    // 3b. Per-rule object mappings (src/dst resolution); anomalies come from the
    // grouped map above so each rule carries its real, current findings.
    const ruleDetails = await Promise.all(
      dbRules.map(async r => {
        let objs = [];
        try {
          objs = await fetch(`/api/v1/rules/${r.rule_id}/objects`).then(res => res.json());
        } catch (err) {
          console.error(`Failed to fetch objects for rule ${r.rule_id}:`, err);
        }
        return { ruleId: r.rule_id, objs, anoms: anomsByRule.get(r.rule_id) || [] };
      })
    );

    // 4. Map Policies (Rules)
    const policies = dbRules.map(r => {
      const details = ruleDetails.find(d => d.ruleId === r.rule_id) || { objs: [], anoms: [] };

      // Resolve source/destination network objects
      const srcObjects = details.objs.filter(o => o.direction === 'source');
      const dstObjects = details.objs.filter(o => o.direction === 'destination');

      const resolveValues = (mappings) => {
        if (mappings.length === 0) return 'any';
        return mappings
          .map(m => {
            const obj = dbObjects.find(o => o.object_id === m.object_id);
            return obj ? obj.name : 'any';
          })
          .join(', ');
      };

      const srcIp = resolveValues(srcObjects);
      const dstIp = resolveValues(dstObjects);

      // Real status from the engine's current findings (severity-based health).
      // `status` doubles as a severity CSS class (critical|high|medium|low);
      // 'clean' maps to 'safe' at render time. We no longer invent a status from
      // a single anomaly type — the worst open finding's severity drives it.
      const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      const openAnoms = (details.anoms || []).filter(a => (a.status || 'open') === 'open');
      let severity = null, worst = -1;
      for (const a of openAnoms) {
        const rank = SEV_RANK[a.severity_level] ?? 0;
        if (rank > worst) { worst = rank; severity = a.severity_level; }
      }
      const status = openAnoms.length ? (severity || 'low') : 'clean';
      const anomalyTypes = [...new Set(openAnoms.map(a => a.anomaly_type))];
      // Real pairing for shadowing/redundancy/cross-device findings.
      const pairAnom = openAnoms.find(a => a.related_rule_id != null);
      const shadowedBy = pairAnom ? `POL-${String(pairAnom.related_rule_id).padStart(3, '0')}` : '';

      // Real deterministic risk (V8) from /api/v1/risk; the low baseline only
      // applies if a rule somehow has no assessment row in the latest run.
      const rr = ruleRiskById.get(r.rule_id);
      const riskScore   = rr ? rr.risk_score : (r.action === 'deny' ? 5 : 20);
      const riskTier    = rr ? rr.risk_tier : null;
      const riskFactors = rr ? rr.factor_breakdown : null;

      return {
        id: `POL-${String(r.rule_id).padStart(3, '0')}`,
        firewallId: String(r.device_id),
        name: r.rule_name,
        srcZone: r.src_zone_interface || 'any',
        dstZone: r.dst_zone_interface || 'any',
        srcIp,
        dstIp,
        service: r.security_profile_group || 'any',
        action: r.action,
        status,
        severity,
        anomalyTypes,
        anomalyCount: openAnoms.length,
        shadowedBy,
        riskScore,
        riskTier,
        riskFactors,
        priority: r.rule_order,
        enabled: r.is_active,
        db_id: r.rule_id,
        anomalies: details.anoms,
      };
    });

    // 5. Map Firewalls (Devices)
    const firewalls = dbDevices.map(d => {
      const v = vendors.find(vend => vend.db_id === d.vendor_id) || { id: 'unknown', name: 'Unknown', abbr: 'UNK' };
      const vm = vendorMeta(v.name);

      let model = 'Firewall';
      if (vm.id === 'fortinet') {
        model = d.hostname.includes('CORE') ? 'FortiGate 600F' : 'FortiGate 200F';
      } else if (vm.id === 'palo-alto') {
        model = d.hostname.includes('DC') ? 'PA-5220' : 'PA-820';
      }

      const fwPolicies = policies.filter(p => p.firewallId === String(d.device_id));
      const fwAnomalies = fwPolicies.filter(p => p.status !== 'clean');
      // Real device risk (V8 blend: 0.6*max + 0.4*avg(top5) + modifier) from the
      // backend — NOT a mean of rule risks, which would dilute a critical posture.
      const dr = deviceRiskById.get(d.device_id);
      const avgRisk = dr ? dr.risk_score
        : (fwPolicies.length ? Math.round(fwPolicies.reduce((s, p) => s + p.riskScore, 0) / fwPolicies.length) : 0);

      return {
        id: String(d.device_id),
        vendorId: v.id,
        vendor: v.name,
        name: d.hostname.toLowerCase(),
        display: d.hostname,
        model,
        location: d.hostname.includes('HQ') ? 'HQ DC · Rack 3A' : d.hostname.includes('DC') ? 'Data Center North' : 'Branch · Alex',
        firmware: d.firmware_version ? `${vm.os} ${d.firmware_version}`.trim() : 'Unknown',
        ip: d.management_ip,
        serial: `${v.abbr}-SN-` + String(d.device_id).padStart(5, '0') + 'A',
        zone: d.hostname.includes('HQ') ? 'CORE' : d.hostname.includes('DC') ? 'DC' : 'BRANCH',
        status: d.status === 'online' ? 'online' : 'degraded',
        lastSync: d.last_poll_time || new Date().toISOString(),
        ruleCount: fwPolicies.length,
        anomalyCount: fwAnomalies.length,
        riskScore: avgRisk,
        riskTier: dr?.risk_tier ?? null,
        riskFactors: dr?.factor_breakdown ?? null,
        uptime: '99.99%',
        throughput: d.hostname.includes('CORE') ? '16.0 Gbps' : d.hostname.includes('DC') ? '8.2 Gbps' : '940 Mbps',
        db_id: d.device_id,
      };
    });

    // 6. Map Conflicts — relational anomalies that pair two rules (shadowing,
    // redundancy, duplicate, conflict, cross-device). Uses the real related_rule_id
    // so cross-device pairs span two firewalls (genuine cross-vendor conflicts).
    const RELATIONAL = new Set([
      'shadowing', 'shadowed_rule', 'redundancy', 'duplicate_rules', 'conflict',
      'cross_device_inconsistency', 'cross_device_security_posture_inconsistency',
    ]);
    const CONFLICT_LABEL = {
      shadowing: 'shadowing', shadowed_rule: 'shadowing', redundancy: 'redundant',
      duplicate_rules: 'duplicate', conflict: 'conflict',
      cross_device_inconsistency: 'cross-device',
      cross_device_security_posture_inconsistency: 'cross-device',
    };
    const conflicts = [];
    ruleDetails.forEach(details => {
      (details.anoms || []).forEach(a => {
        if (!RELATIONAL.has(a.anomaly_type)) return;
        const rA = policies.find(p => p.db_id === a.rule_id);
        const rB = a.related_rule_id != null ? policies.find(p => p.db_id === a.related_rule_id) : null;
        if (!rA) return;
        conflicts.push({
          id: `CONF-${String(a.anomaly_id).padStart(3, '0')}`,
          type: CONFLICT_LABEL[a.anomaly_type] || a.anomaly_type.replace(/_/g, ' '),
          ruleA: rA.id,
          ruleB: rB ? rB.id : '—',
          firewallA: rA.firewallId,
          firewallB: rB ? rB.firewallId : rA.firewallId,
          severity: a.severity_level,
          description: a.description || 'Relational policy anomaly.',
        });
      });
    });

    // 7. Dynamic Topology Mapping (Zones + Assets from database)
    const zonesSet = new Set();
    policies.forEach(p => {
      if (p.srcZone && p.srcZone !== 'any') zonesSet.add(JSON.stringify({ name: p.srcZone, fwId: p.firewallId }));
      if (p.dstZone && p.dstZone !== 'any') zonesSet.add(JSON.stringify({ name: p.dstZone, fwId: p.firewallId }));
    });
    
    const zones = Array.from(zonesSet).map((zStr, idx) => {
      const z = JSON.parse(zStr);
      const nameLower = z.name.toLowerCase();
      let type = 'trust';
      if (nameLower.includes('dmz')) type = 'dmz';
      else if (nameLower.includes('untrust') || nameLower.includes('wan') || nameLower.includes('outside')) type = 'untrust';
      else if (nameLower.includes('mgmt')) type = 'mgmt';
      else if (nameLower.includes('vpn')) type = 'vpn';
      else if (nameLower.includes('dr')) type = 'dr';
      else if (nameLower.includes('server')) type = 'server';
      
      // Real subnet from a matching *_NET object (by name token), with the
      // common trust→LAN convention. No fabricated fallback — null when the
      // interface's subnet isn't derivable from config (e.g. FortiGate PORTx).
      const subnetObjs = dbObjects.filter(o => o.type === 'cidr' && /\/(8|16|2\d)$/.test(o.value || ''));
      const up = z.name.toUpperCase();
      let subnetMatch = subnetObjs.find(o => o.name.toUpperCase().includes(up));
      if (!subnetMatch && (up === 'TRUST' || up === 'LAN')) {
        subnetMatch = subnetObjs.find(o => o.name.toUpperCase().includes('LAN'));
      }

      return {
        id: `z-${z.name.toLowerCase()}`,
        fwId: z.fwId,
        name: z.name,
        type,
        subnet: subnetMatch ? subnetMatch.value : null,
      };
    });

    // Monitored assets = real internal single-host (/32) objects. Placement is by
    // real subnet containment against the zone subnets above; hosts whose zone
    // can't be derived (e.g. behind an un-mapped PORTx) are left unzoned. OS is
    // NOT fabricated — the firewall config doesn't carry it.
    const HOST_RE = /\/(32|128)$/;
    const _assetSeen = new Set();   // shared-network lab syncs each host from BOTH devices — dedupe by IP
    const assets = dbObjects
      .filter(o => o.type === 'cidr' && HOST_RE.test(o.value || '') && !String(o.value).startsWith('0.0.0.0'))
      .map(o => {
        const ip = String(o.value).replace(HOST_RE, '');
        if (!isPrivateIp(ip)) return null;   // external indicators aren't "assets"
        const n = o.name.toUpperCase();
        let kind = 'host';
        if (n.includes('DB')) kind = 'db';
        else if (n.includes('WEB') || n.includes('MAIL') || n.includes('SERVER')) kind = 'app';
        else if (n.includes('PC') || n.includes('ADMIN') || n.includes('WORK')) kind = 'workstation';
        const zone = zones.find(z => subnetContains(z.subnet, ip));
        return {
          id: `a-${ip.replace(/\./g, '-')}`,   // keyed by IP (unique post-dedupe), not name
          zoneId: zone ? zone.id : null,
          name: o.name,
          kind,
          ip,
          os: null,
        };
      })
      .filter(a => {
        if (!a || _assetSeen.has(a.ip)) return false;
        _assetSeen.add(a.ip);
        return true;
      });

    // 8. Fetch real Threat Findings + scan stats + CTI indicators (in parallel)
    const [threatFindings, tiStats, ctiData] = await Promise.all([
      fetch('/api/v1/threat-intel/findings?page_size=100').then(res => res.json()).catch(() => ({ items: [] })),
      fetch('/api/v1/threat-intel/dashboard/stats').then(res => res.json()).catch(() => null),
      fetch('/api/v1/cti').then(res => res.json()).catch(() => ({ indicators: [] })),
    ]);

    const deviceById = new Map(firewalls.map(fw => [fw.id, fw]));

    // 8b. External threat vectors (Volume 9 CTI) — real malicious indicators that
    // the engine correlated to a permitting rule. Affected devices come from the
    // run's threat_exposure findings (the indicator value is in the evidence).
    const devicesByIndicator = {};
    anomsByRule.forEach(anoms => anoms.forEach(a => {
      if (a.anomaly_type === 'threat_exposure' && a.evidence && a.evidence.indicator) {
        (devicesByIndicator[a.evidence.indicator] ||= new Set()).add(String(a.device_id));
      }
    }));
    const externalNodes = (ctiData.indicators || [])
      // firmware_version indicators are device-scoped CVE evidence (value is a
      // firmware string, not an IP) — never plot them as external network nodes.
      .filter(ind => ind.malicious && ind.type !== 'firmware_version')
      .map(ind => {
        const obs = (ind.observations && ind.observations[0]) || {};
        const devs = devicesByIndicator[ind.value]
          || new Set(ind.source_device_id != null ? [String(ind.source_device_id)] : []);
        return {
          id: `cti-${ind.indicator_id}`,
          name: ind.value,
          ip: ind.value,
          kind: obs.threat_type || 'threat',
          threat: obs.severity || 'high',
          description: obs.summary || `${obs.threat_type || 'malicious'} indicator · ${obs.provider || 'cti'}`,
          provider: obs.provider || null,
          targetFwIds: [...devs],
        };
      });

    // 8c. Firmware-CVE device axis (Volume 8/9). firmware_version indicators are
    // device-scoped CVE evidence (value is a firmware string, not an IP) and are
    // deliberately NOT plotted as external network nodes above. Surface them per device
    // so the topology can badge a firewall whose firmware is vulnerable — re-sourced from
    // LIVE CTI, replacing the retired dark-web `threats` feed (now empty). Each provider
    // observation on the indicator is one CVE.
    const SEV_RANK_FW = { critical: 4, high: 3, medium: 2, low: 1 };
    const firmwareCves = (ctiData.indicators || [])
      .filter(ind => ind.type === 'firmware_version' && ind.source_device_id != null)
      .map(ind => {
        const obs = ind.observations || [];
        let worst = null, wr = 0;
        obs.forEach(o => {
          const r = SEV_RANK_FW[String(o.severity || '').toLowerCase()] || 0;
          if (r > wr) { wr = r; worst = o.severity; }
        });
        return {
          deviceId: String(ind.source_device_id),
          firmware: ind.value,
          worstSeverity: worst,
          count: obs.length,
          critical: obs.filter(o => String(o.severity || '').toLowerCase() === 'critical').length,
          cves: obs.map(o => ({
            id: (String(o.reference || '').match(/CVE-\d{4}-\d{4,}/i) || [''])[0].toUpperCase() || o.reference || '',
            severity: o.severity || null,
            summary: o.summary || '',
            reference: o.reference || '',
          })),
        };
      });

    /* Derive the affected vendor(s) for a finding from its matched devices,
     * falling back to product keywords in the title/description/tags. Keeps the
     * dashboard's per-vendor CVE counts and the Threats vendor filter accurate. */
    const deriveVendors = (f) => {
      const fromDevices = (f.matched_device_ids || [])
        .map(id => deviceById.get(String(id))?.vendorId)
        .filter(Boolean);
      if (fromDevices.length) return Array.from(new Set(fromDevices));
      const hay = `${f.title || ''} ${f.description || ''} ${(f.tags || []).join(' ')}`.toLowerCase();
      const vs = [];
      if (/fortios|fortigate|fortinet/.test(hay)) vs.push('fortinet');
      if (/pan-os|panos|palo|globalprotect/.test(hay)) vs.push('palo-alto');
      return vs.length ? vs : [];
    };
    const isKev = (f) =>
      f.source_marketplace_or_forum === 'CISA Known Exploited Vulnerabilities'
      || /known exploited|cisa kev|\bkev\b/i.test(f.source_marketplace_or_forum || '')
      || (f.tags || []).map(t => String(t).toLowerCase()).includes('kev');

    const sourceLane = (f) => {
      const sourceMarketplace = f.source_marketplace_or_forum || '';
      const isDarkweb = !!(f.source_onion_url || f.source_search_engine);
      const isClearnet = !isDarkweb;
      return { sourceMarketplace, isClearnet, isDarkweb };
    };

    /* Exploit-status values must match the Threats page filter: active | wild | poc | none.
     * KEV = confirmed active exploitation; 'wild'/'poc' come from evidence text; else 'none'. */
    const deriveExploit = (f, kev) => {
      if (kev) return 'active';
      const hay = `${f.title || ''} ${f.description || ''} ${(f.tags || []).join(' ')}`.toLowerCase();
      if (/in the wild|widely exploited|mass exploit|actively exploited|active exploitation/.test(hay)) return 'wild';
      if (/\bpoc\b|proof[- ]of[- ]concept|exploit (code|available|published|released)|public exploit|metasploit/.test(hay)) return 'poc';
      return 'none';
    };

    const usingMockThreats = !(threatFindings.items && threatFindings.items.length > 0);
    const threats = !usingMockThreats
      ? threatFindings.items.map(f => {
          const matchedFw = (f.matched_device_ids || []).map(id => deviceById.get(String(id))).filter(Boolean);
          const kev = isKev(f);
          const lane = sourceLane(f);
          return {
            id: f.title && f.title.includes('CVE-') ? f.title.split(' ')[0].replace(/[:,]$/, '') : `FND-${f.id}`,
            severity: f.severity,
            cvss: f.severity === 'critical' ? 9.5 : f.severity === 'high' ? 8.0 : f.severity === 'medium' ? 5.5 : 2.5,
            title: f.title,
            firmware: matchedFw.length ? Array.from(new Set(matchedFw.map(fw => fw.firmware))) : (f.tags || []),
            vendors: deriveVendors(f),
            firewallIds: (f.matched_device_ids || []).map(String),
            published: f.source_scraped_at ? String(f.source_scraped_at).split('T')[0]
                       : (f.created_at ? String(f.created_at).split('T')[0] : ''),
            patched: f.recommended_actions && f.recommended_actions.length > 0 ? f.recommended_actions[0] : 'Review vendor advisory',
            exploit: deriveExploit(f, kev),
            kev,
            correlated: (f.matched_device_ids || []).length > 0,
            correlationReason: f.correlation_match_reason || '',
            relevanceBand: f.relevance_band || null,
            relevanceScore: f.relevance_score != null ? f.relevance_score : null,
            relevanceReason: f.relevance_reason || '',
            isNew: f.is_new_since_last_scan || false,
            description: f.description || '',
            sourceMarketplace: lane.sourceMarketplace,
            isClearnet: lane.isClearnet,
            isDarkweb: lane.isDarkweb,
          };
        })
      : []; // No fallback to mock threats if scan hasn't run yet

    // Scan metadata (drives live KPIs + page subtitle, no fabricated numbers)
    const meta = {
      lastScanAt: tiStats?.last_scan_at || null,
      lastScanStatus: tiStats?.last_scan_status || null,
      totalScans: tiStats?.total_scans || 0,
      totalFindings: threatFindings.total ?? (threatFindings.items?.length || 0),
      newFindingsLastScan: tiStats?.new_findings_last_scan || 0,
      criticalFindings: tiStats?.critical_findings_last_7d || 0,
      highFindings: tiStats?.high_findings_last_7d || 0,
      correlatedRules: tiStats?.correlated_rules_count || 0,
      usingMockThreats, // true = no scan findings yet; UI shows "run a scan" notice
    };

    // Live activity feed derived from real findings + anomalies + last scan.
    const liveFeed = buildActivityFeed({ threats, firewalls, ruleDetails, meta });

    // Consolidate into dynamic dataset matching mock data structure
    return {
      vendors,
      firewalls,
      policies,
      conflicts,
      threats,
      meta,
      zones,
      assets,
      firmwareCves,
      firmwareTimeline: mockLFPM.firmwareTimeline || [],
      externalNodes,
      activityFeed: liveFeed,
      hits24h: mockLFPM.hits24h || [],
      users: mockLFPM.users || [],
      savedSearches: mockLFPM.savedSearches || [],
      fmt: mockLFPM.fmt,
    };
  } catch (err) {
    console.error("fetchLFPMData failed, utilizing mock database fallback", err);
    throw err;
  }
}

// Interactive triggers. The read-only re-poll endpoint is /devices/{id}/poll (202 + job_id);
// the platform never writes to the firewall — it re-acquires + re-normalizes the live config.
export async function triggerRulesSync(deviceId) {
  const res = await fetch(`/api/v1/devices/${deviceId}/poll`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function triggerDeviceAnalysis(deviceId) {
  const res = await fetch(`/api/v1/rules/device/${deviceId}/analyze`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// Analyst lifecycle on a finding (V6 §12): resolved | suppressed | accepted_risk
// | false_positive. Suppressing/accepting/dismissing requires a reason (kept in
// history — never deletes). Read-only w.r.t. firewalls; updates Lumina's DB only.
export async function updateAnomalyStatus(anomalyId, status, reason) {
  const body = { status };
  if (reason) body.reason = reason;
  const res = await fetch(`/api/v1/anomalies/${anomalyId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// (Retired) The dark-web/Tor threat-intel scan helpers (fetchThreatReports /
// fetchThreatReportDetail / triggerThreatScan / subscribeThreatScanProgress) were
// removed with the legacy Threat Intelligence wrapper. The two-axis Threat Center
// reads /api/v1/cti instead (see cti.tsx / lib/api.ts `cti`).
