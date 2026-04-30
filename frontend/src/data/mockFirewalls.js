export const vendors = [
  { id: 'palo-alto', name: 'Palo Alto Networks', logo: 'PA', color: '#06b6d4' },
  { id: 'fortinet',  name: 'Fortinet',           logo: 'FT', color: '#f97316' },
];

export const firewalls = [
  // Palo Alto
  {
    id: 'fw-001', vendorId: 'palo-alto', vendor: 'Palo Alto Networks',
    name: 'PA-5220-HQ', model: 'PA-5220', location: 'HQ Data Center – Rack 3A',
    firmware: 'PAN-OS 10.1.6', ip: '192.168.1.1', zone: 'CORE',
    status: 'online', lastSync: '2026-04-13T20:45:00Z',
    ruleCount: 124, anomalyCount: 11, riskScore: 78,
    uptime: '99.97%', throughput: '8.2 Gbps',
  },
  {
    id: 'fw-002', vendorId: 'palo-alto', vendor: 'Palo Alto Networks',
    name: 'PA-3260-DMZ', model: 'PA-3260', location: 'DMZ Segment – Rack 1B',
    firmware: 'PAN-OS 10.1.3', ip: '192.168.1.2', zone: 'DMZ',
    status: 'online', lastSync: '2026-04-13T19:30:00Z',
    ruleCount: 87, anomalyCount: 5, riskScore: 54,
    uptime: '99.91%', throughput: '3.6 Gbps',
  },
  {
    id: 'fw-003', vendorId: 'palo-alto', vendor: 'Palo Alto Networks',
    name: 'PA-820-Branch', model: 'PA-820', location: 'Branch Office – Cairo',
    firmware: 'PAN-OS 9.1.12', ip: '10.20.1.1', zone: 'BRANCH',
    status: 'degraded', lastSync: '2026-04-13T12:00:00Z',
    ruleCount: 52, anomalyCount: 7, riskScore: 65,
    uptime: '98.20%', throughput: '940 Mbps',
  },
  // Fortinet
  {
    id: 'fw-004', vendorId: 'fortinet', vendor: 'Fortinet',
    name: 'FG-600F-CORE', model: 'FortiGate 600F', location: 'HQ Core Switch Stack',
    firmware: 'FortiOS 7.2.4', ip: '10.0.0.1', zone: 'CORE',
    status: 'online', lastSync: '2026-04-13T21:00:00Z',
    ruleCount: 198, anomalyCount: 19, riskScore: 82,
    uptime: '99.99%', throughput: '16.0 Gbps',
  },
  {
    id: 'fw-005', vendorId: 'fortinet', vendor: 'Fortinet',
    name: 'FG-200F-DR', model: 'FortiGate 200F', location: 'Disaster Recovery Site',
    firmware: 'FortiOS 7.0.8', ip: '10.50.0.1', zone: 'DR',
    status: 'online', lastSync: '2026-04-13T18:15:00Z',
    ruleCount: 76, anomalyCount: 3, riskScore: 41,
    uptime: '99.85%', throughput: '2.1 Gbps',
  },
];
