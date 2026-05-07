/*
 * Lumina FPM — API Service Layer
 * Fetches data from the real backend and transforms responses
 * into the shapes the frontend components already expect.
 */

const BASE = '/api/v1';

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}: ${path}`);
  return res.json();
}

// ─── Color / logo helpers ────────────────────────────────────────
function vendorMeta(name) {
  const n = name.toLowerCase();
  if (n.includes('palo alto'))  return { logo: 'PA', color: '#06b6d4' };
  if (n.includes('fortinet'))   return { logo: 'FT', color: '#f97316' };
  if (n.includes('cisco'))      return { logo: 'CS', color: '#10b981' };
  return { logo: name.slice(0, 2).toUpperCase(), color: '#8b5cf6' };
}

// ─── Severity helpers ────────────────────────────────────────────
function severityFromRisk(risk) {
  if (risk >= 9)  return 'Critical';
  if (risk >= 7)  return 'High';
  if (risk >= 4)  return 'Medium';
  return 'Low';
}

// ─── VENDORS ─────────────────────────────────────────────────────
export async function fetchVendors() {
  const raw = await get('/vendors/');
  return raw.map(v => ({
    id: `vendor-${v.vendor_id}`,
    vendorId: v.vendor_id,
    name: v.name,
    ...vendorMeta(v.name),
  }));
}

// ─── DEVICES (firewalls) ─────────────────────────────────────────
export async function fetchDevices(vendors) {
  const raw = await get('/devices/');
  const vendorMap = {};
  vendors.forEach(v => { vendorMap[v.vendorId] = v; });

  return raw.map(d => {
    const v = vendorMap[d.vendor_id] || {};
    return {
      id: `fw-${d.device_id}`,
      deviceId: d.device_id,
      vendorId: v.id || `vendor-${d.vendor_id}`,
      vendor: v.name || 'Unknown',
      name: d.hostname,
      model: d.hostname,
      location: `Management: ${d.management_ip}`,
      firmware: d.firmware_version || 'N/A',
      ip: d.management_ip,
      zone: 'CORE',
      status: d.status || 'unknown',
      lastSync: d.last_poll_time || new Date().toISOString(),
      ruleCount: 0,   // enriched later
      anomalyCount: 0, // enriched later
      riskScore: 0,    // enriched later
      uptime: 'N/A',
      throughput: 'N/A',
    };
  });
}

// ─── RULES → policies shape ──────────────────────────────────────
export async function fetchPolicies(devices, vendors) {
  const raw = await get('/rules/');
  const deviceMap = {};
  devices.forEach(d => { deviceMap[d.deviceId] = d; });

  return raw.map(r => {
    const dev = deviceMap[r.device_id] || {};
    return {
      id: `POL-${String(r.rule_id).padStart(3, '0')}`,
      ruleId: r.rule_id,
      firewallId: dev.id || `fw-${r.device_id}`,
      vendor: dev.vendor || 'Unknown',
      firewall: dev.name || `Device-${r.device_id}`,
      ruleName: r.rule_name,
      srcZone: r.src_zone_interface || 'any',
      dstZone: r.dst_zone_interface || 'any',
      srcIp: 'any',    // populated from network objects when available
      dstIp: 'any',
      service: 'any',
      action: r.action?.toUpperCase() || 'ALLOW',
      status: 'Clean', // overridden by anomalies
      shadowedBy: null,
      riskScore: 0,     // overridden by anomalies
      priority: r.rule_order,
      enabled: r.is_active !== false,
      description: r.description || '',
      tags: r.tags || '',
    };
  });
}

// ─── ANOMALIES — enriches policies and devices ───────────────────
export async function enrichWithAnomalies(policies, devices) {
  // Fetch anomalies for each rule that has policies
  const ruleIds = [...new Set(policies.map(p => p.ruleId))];
  const anomalyMap = {};  // ruleId → anomalies[]

  // Fetch anomalies in batches
  const anomalyPromises = ruleIds.map(async (ruleId) => {
    try {
      const anomalies = await get(`/rules/${ruleId}/anomalies`);
      if (anomalies.length > 0) anomalyMap[ruleId] = anomalies;
    } catch {
      // Rule may not exist anymore, skip
    }
  });
  await Promise.all(anomalyPromises);

  // Status mapping from anomaly_type
  const statusFromAnomaly = {
    overly_permissive: 'Overly Permissive',
    stale_rule: 'Redundant',
    shadowed_rule: 'Shadowed',
    redundant: 'Redundant',
  };

  // Risk score from severity
  const riskFromSeverity = {
    critical: 95,
    high: 80,
    medium: 55,
    low: 25,
  };

  // Enrich policies
  policies.forEach(p => {
    const anomalies = anomalyMap[p.ruleId];
    if (anomalies && anomalies.length > 0) {
      const worst = anomalies.reduce((best, a) => {
        const r = riskFromSeverity[a.severity_level] || 30;
        return r > best.risk ? { risk: r, a } : best;
      }, { risk: 0, a: anomalies[0] });

      p.status = statusFromAnomaly[worst.a.anomaly_type] || worst.a.anomaly_type;
      p.riskScore = worst.risk;
    } else {
      p.riskScore = Math.floor(Math.random() * 25) + 5; // clean rules get low risk
    }
  });

  // Enrich devices with aggregate anomaly counts and risk scores
  const devAnomalies = {};
  policies.forEach(p => {
    if (!devAnomalies[p.firewallId]) devAnomalies[p.firewallId] = { count: 0, maxRisk: 0, ruleCount: 0 };
    devAnomalies[p.firewallId].ruleCount++;
    if (p.status !== 'Clean') {
      devAnomalies[p.firewallId].count++;
    }
    devAnomalies[p.firewallId].maxRisk = Math.max(devAnomalies[p.firewallId].maxRisk, p.riskScore);
  });

  devices.forEach(d => {
    const stats = devAnomalies[d.id] || {};
    d.ruleCount = stats.ruleCount || 0;
    d.anomalyCount = stats.count || 0;
    d.riskScore = stats.maxRisk || 0;
  });

  return { policies, devices };
}

// ─── THREAT INTELLIGENCE ─────────────────────────────────────────
export async function fetchThreats(devices) {
  const raw = await get('/threat-intel/scans');
  const deviceMap = {};
  devices.forEach(d => { deviceMap[d.deviceId] = d; });

  return raw.map(t => {
    const dev = deviceMap[t.device_id] || {};
    const summary = t.intelligence_summary || '';

    // Try to extract CVE ID from summary
    const cveMatch = summary.match(/CVE-\d{4}-\d+/);
    const cveId = cveMatch ? cveMatch[0] : `THREAT-${t.threat_id}`;

    // Extract title (text before the first period)
    const titleMatch = summary.match(/^(?:CVE-\d{4}-\d+:\s*)?(.+?)\./) ;
    const title = titleMatch ? titleMatch[1].trim() : summary.slice(0, 80);

    const risk = t.risk_score || 0;
    const severity = severityFromRisk(risk);

    // Determine exploit status from summary keywords
    let exploitStatus = 'No Known Exploit';
    const lowerSummary = summary.toLowerCase();
    if (lowerSummary.includes('actively exploited') || lowerSummary.includes('active exploitation'))
      exploitStatus = 'Active Exploitation';
    else if (lowerSummary.includes('poc'))
      exploitStatus = 'PoC Available';

    return {
      id: cveId,
      threatId: t.threat_id,
      severity,
      cvss: risk,
      title,
      description: summary,
      affectedFirmware: [t.target_version].filter(Boolean),
      vendors: [dev.vendor].filter(Boolean),
      affectedFirewalls: [dev.name].filter(Boolean),
      publishedDate: new Date().toISOString().split('T')[0],
      patchedIn: 'See vendor advisory',
      exploitStatus,
      references: t.source_url ? [t.source_url] : [],
    };
  });
}

// ─── FIRMWARE TIMELINE ───────────────────────────────────────────
export function buildFirmwareTimeline(devices, threats) {
  const fwMap = {};
  devices.forEach(d => {
    const key = `${d.firmware} (${d.vendor})`;
    if (!fwMap[key]) {
      fwMap[key] = { firmware: d.firmware, vendor: d.vendor, threatCount: 0 };
    }
  });
  threats.forEach(t => {
    t.affectedFirmware.forEach(fw => {
      const entry = Object.values(fwMap).find(f => fw.includes(f.firmware));
      if (entry) entry.threatCount++;
    });
  });
  return Object.values(fwMap).map(f => ({
    firmware: f.firmware,
    vendor: f.vendor,
    releaseDate: 'N/A',
    eolDate: 'N/A',
    threatCount: f.threatCount,
    isEol: false,
  }));
}

// ─── CONFLICTS (empty for now — no backend endpoint) ─────────────
export function fetchConflicts() {
  return [];
}

// ─── ALL-IN-ONE DASHBOARD FETCH ──────────────────────────────────
export async function fetchAllData() {
  const vendors = await fetchVendors();
  const devices = await fetchDevices(vendors);
  let policies = await fetchPolicies(devices, vendors);
  const enriched = await enrichWithAnomalies(policies, devices);
  policies = enriched.policies;
  const enrichedDevices = enriched.devices;
  const threats = await fetchThreats(enrichedDevices);
  const firmwareTimeline = buildFirmwareTimeline(enrichedDevices, threats);
  const conflicts = fetchConflicts();

  return {
    vendors,
    firewalls: enrichedDevices,
    policies,
    threats,
    firmwareTimeline,
    conflicts,
  };
}
