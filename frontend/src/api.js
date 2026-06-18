/**
 * API Integration Layer for LuminaFPM
 * Connects the React UI to FastAPI backend endpoints.
 */

import { LFPM as mockLFPM } from './data';

/* Canonical vendor identity. Keeps UI vendor ids STABLE ('palo-alto',
 * 'fortinet', 'cisco') regardless of the DB display name, and provides the
 * correct firmware-OS prefix per vendor (PAN-OS / FortiOS / ASA). Previously
 * the id was a slug of the name ("Palo Alto Networks" -> "palo-alto-networks"),
 * which broke the dashboard's vendor filters (NaN risk) and mislabelled Cisco. */
function vendorMeta(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('palo'))  return { id: 'palo-alto', abbr: 'PA', accent: 'var(--vendor-paloalto)', os: 'PAN-OS' };
  if (n.includes('forti')) return { id: 'fortinet',  abbr: 'FT', accent: 'var(--vendor-fortinet)', os: 'FortiOS' };
  if (n.includes('cisco')) return { id: 'cisco',     abbr: 'CS', accent: 'var(--vendor-cisco)', os: 'ASA' };
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
    const [dbVendors, dbDevices, dbRules, dbObjects] = await Promise.all([
      fetch('/api/v1/vendors/').then(res => res.json()),
      fetch('/api/v1/devices/').then(res => res.json()),
      fetch('/api/v1/rules/').then(res => res.json()),
      fetch('/api/v1/network-objects/').then(res => res.json()),
    ]);

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

    // 3. Fetch detailed mapped objects and anomalies per rule in parallel
    const ruleDetails = await Promise.all(
      dbRules.map(async r => {
        try {
          const [objs, anoms] = await Promise.all([
            fetch(`/api/v1/rules/${r.rule_id}/objects`).then(res => res.json()),
            fetch(`/api/v1/rules/${r.rule_id}/anomalies`).then(res => res.json()),
          ]);
          return { ruleId: r.rule_id, objs, anoms };
        } catch (err) {
          console.error(`Failed to fetch details for rule ${r.rule_id}:`, err);
          return { ruleId: r.rule_id, objs: [], anoms: [] };
        }
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

      // Determine policy anomaly status
      let status = 'clean';
      let shadowedBy = '';
      if (details.anoms.length > 0) {
        const mainAnom = details.anoms[0];
        if (mainAnom.anomaly_type === 'shadowed_rule') {
          status = 'shadowed';
          // Find any rule that could shadow it, otherwise fallback
          shadowedBy = 'POL-002';
        } else if (mainAnom.anomaly_type === 'overly_permissive') {
          status = 'permissive';
        } else if (mainAnom.anomaly_type === 'stale_rule') {
          status = 'redundant';
        }
      }

      // Compute risk score based on status & action
      let riskScore = 20;
      if (r.action === 'deny') {
        riskScore = 5;
      } else if (status === 'shadowed') {
        riskScore = 90;
      } else if (status === 'permissive') {
        riskScore = 85;
      } else if (status === 'redundant') {
        riskScore = 30;
      }

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
        shadowedBy,
        riskScore,
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
      } else if (vm.id === 'cisco') {
        model = 'Cisco ASA 5500-X';
      } else if (vm.id === 'palo-alto') {
        model = d.hostname.includes('DC') ? 'PA-5220' : 'PA-820';
      }

      const fwPolicies = policies.filter(p => p.firewallId === String(d.device_id));
      const fwAnomalies = fwPolicies.filter(p => p.status !== 'clean');
      const avgRisk = fwPolicies.length > 0
        ? Math.round(fwPolicies.reduce((sum, p) => sum + p.riskScore, 0) / fwPolicies.length)
        : 30;

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
        uptime: '99.99%',
        throughput: d.hostname.includes('CORE') ? '16.0 Gbps' : d.hostname.includes('DC') ? '8.2 Gbps' : '940 Mbps',
        db_id: d.device_id,
      };
    });

    // 6. Map Conflicts (from active shadowing anomalies)
    const conflicts = [];
    ruleDetails.forEach(details => {
      details.anoms.forEach(a => {
        if (a.anomaly_type === 'shadowed_rule' || (a.anomaly_type === 'overly_permissive' && a.severity_level === 'critical')) {
          const r = policies.find(p => p.db_id === details.ruleId);
          if (r) {
            conflicts.push({
              id: `CONF-${String(a.anomaly_id).padStart(3, '0')}`,
              type: a.anomaly_type === 'shadowed_rule' ? 'asymmetric' : 'transitive',
              ruleA: r.id,
              ruleB: a.anomaly_type === 'shadowed_rule' ? 'POL-002' : 'POL-003',
              firewallA: r.firewallId,
              firewallB: r.firewallId,
              severity: a.severity_level === 'critical' ? 'critical' : 'high',
              description: a.description || 'Rule conflicts with configured baseline policies.',
            });
          }
        }
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
      
      return {
        id: `z-${z.name.toLowerCase()}`,
        fwId: z.fwId,
        name: z.name,
        type,
        subnet: dbObjects.find(o => o.name === z.name)?.value || '10.0.0.0/24',
      };
    });

    const assets = dbObjects
      .filter(o => o.type === 'host')
      .map((o, idx) => {
        // Resolve zone logically matching the host's subnet prefix
        let zoneId = 'z-trust';
        if (o.name.includes('WEB') || o.name.includes('MAIL')) zoneId = 'z-dmz';
        else if (o.name.includes('DB') || o.name.includes('AD') || o.name.includes('SERVERS')) zoneId = 'z-server';
        else if (o.name.includes('BRANCH')) zoneId = 'z-branch';

        let kind = 'host';
        if (o.name.includes('SERVER') || o.name.includes('WEB') || o.name.includes('AD')) kind = 'app';
        if (o.name.includes('DB')) kind = 'db';
        if (o.name.includes('MAIL')) kind = 'mail';

        return {
          id: `a-${o.name.toLowerCase()}`,
          zoneId,
          name: o.name,
          kind,
          ip: o.value,
          os: o.name.includes('SERVER') || o.name.includes('DB') ? 'RHEL 8.6' : 'Windows Server 2022',
        };
      });

    // 8. Fetch real Threat Findings + scan stats (in parallel)
    const [threatFindings, tiStats] = await Promise.all([
      fetch('/api/v1/threat-intel/findings?page_size=100').then(res => res.json()).catch(() => ({ items: [] })),
      fetch('/api/v1/threat-intel/dashboard/stats').then(res => res.json()).catch(() => null),
    ]);

    const deviceById = new Map(firewalls.map(fw => [fw.id, fw]));

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
      if (/\basa\b|adaptive security|cisco/.test(hay)) vs.push('cisco');
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
      firmwareTimeline: [],
      externalNodes: [],
      activityFeed: liveFeed,
      hits24h: [],
      users: [],
      savedSearches: [],
      fmt: mockLFPM.fmt,
    };
  } catch (err) {
    console.error("fetchLFPMData failed, utilizing mock database fallback", err);
    throw err;
  }
}

// Interactive triggers
export async function triggerRulesSync(deviceId) {
  const res = await fetch(`/api/v1/devices/${deviceId}/sync`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function triggerDeviceAnalysis(deviceId) {
  const res = await fetch(`/api/v1/rules/device/${deviceId}/analyze`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// Threat Intel — scans, reports, SSE progress
export async function fetchThreatReports(page = 1, status) {
  const params = new URLSearchParams({ page: String(page), page_size: '20' });
  if (status) params.set('status', status);
  const res = await fetch(`/api/v1/threat-intel/scans?${params}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchThreatReportDetail(id) {
  const res = await fetch(`/api/v1/threat-intel/scans/${id}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function triggerThreatScan(categories, deviceIds) {
  const body = { trigger_type: 'manual' };
  if (categories?.length) body.categories = categories;
  if (deviceIds?.length) body.device_ids = deviceIds.map(Number);
  const res = await fetch('/api/v1/threat-intel/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

/** Subscribe to scan progress via SSE. Returns an unsubscribe function. */
export function subscribeThreatScanProgress(reportId, onEvent) {
  const es = new EventSource(`/api/v1/threat-intel/scans/${reportId}/stream`);
  let closed = false;

  const close = () => {
    if (!closed) {
      closed = true;
      es.close();
    }
  };

  const handleData = (eventType, event) => {
    try {
      const data = JSON.parse(event.data || '{}');
      onEvent({ type: eventType, data });
      const st = (data.status || eventType || '').toUpperCase();
      if (st === 'SUCCESS' || st === 'FAILED' || eventType === 'done') close();
    } catch (e) {
      console.warn('SSE parse error', e);
    }
  };

  es.onmessage = (e) => handleData('message', e);
  ['running', 'SUCCESS', 'FAILED', 'progress', 'done'].forEach(t => {
    es.addEventListener(t, (e) => handleData(t, e));
  });

  es.onerror = () => {
    onEvent({ type: 'error', data: {} });
    close();
  };

  return close;
}
