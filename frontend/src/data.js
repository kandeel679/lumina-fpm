/* ─────────────────────────────────────────────────────────────────
 * Lumina FPM · consolidated mock data
 * Cleaned-up version of the original data files. Single source of
 * truth for firewall names, zone references, and threat targeting.
 * ───────────────────────────────────────────────────────────────── */

export const LFPM = {};
window.LFPM = LFPM;

LFPM.vendors = [
  { id: 'palo-alto', name: 'Palo Alto Networks', abbr: 'PA', accent: '#ffb866' },
  { id: 'fortinet',  name: 'Fortinet',           abbr: 'FT', accent: '#ff7a7a' },
];

LFPM.firewalls = [
  { id:'fw-001', vendorId:'palo-alto', vendor:'Palo Alto Networks',
    name:'pa-5220-hq', display:'PA-5220-HQ', model:'PA-5220',
    location:'HQ DC · Rack 3A', firmware:'PAN-OS 10.1.6',
    ip:'192.168.1.1', serial:'PA-SN-00451A', zone:'CORE',
    status:'online', lastSync:'2026-04-13T20:45:00Z',
    ruleCount:124, anomalyCount:11, riskScore:78,
    uptime:'99.97%', throughput:'8.2 Gbps' },
  { id:'fw-002', vendorId:'palo-alto', vendor:'Palo Alto Networks',
    name:'pa-3260-dmz', display:'PA-3260-DMZ', model:'PA-3260',
    location:'DMZ · Rack 1B', firmware:'PAN-OS 10.1.3',
    ip:'192.168.1.2', serial:'PA-SN-00782B', zone:'DMZ',
    status:'online', lastSync:'2026-04-13T19:30:00Z',
    ruleCount:87, anomalyCount:5, riskScore:54,
    uptime:'99.91%', throughput:'3.6 Gbps' },
  { id:'fw-003', vendorId:'palo-alto', vendor:'Palo Alto Networks',
    name:'pa-820-branch', display:'PA-820-Branch', model:'PA-820',
    location:'Branch · Cairo', firmware:'PAN-OS 9.1.12',
    ip:'10.20.1.1', serial:'PA-SN-09124C', zone:'BRANCH',
    status:'degraded', lastSync:'2026-04-13T12:00:00Z',
    ruleCount:52, anomalyCount:7, riskScore:65,
    uptime:'98.20%', throughput:'940 Mbps' },
  { id:'fw-004', vendorId:'fortinet', vendor:'Fortinet',
    name:'fg-600f-core', display:'FG-600F-CORE', model:'FortiGate 600F',
    location:'HQ Core Switch Stack', firmware:'FortiOS 7.2.4',
    ip:'10.0.0.1', serial:'FG-SN-10392C', zone:'CORE',
    status:'online', lastSync:'2026-04-13T21:00:00Z',
    ruleCount:198, anomalyCount:19, riskScore:82,
    uptime:'99.99%', throughput:'16.0 Gbps' },
  { id:'fw-005', vendorId:'fortinet', vendor:'Fortinet',
    name:'fg-200f-dr', display:'FG-200F-DR', model:'FortiGate 200F',
    location:'DR Site', firmware:'FortiOS 7.0.8',
    ip:'10.50.0.1', serial:'FG-SN-20841D', zone:'DR',
    status:'online', lastSync:'2026-04-13T18:15:00Z',
    ruleCount:76, anomalyCount:3, riskScore:41,
    uptime:'99.85%', throughput:'2.1 Gbps' },
];

/* Policies — taken from original mockPolicies.js, names canonicalized */
LFPM.policies = [
  /* fw-001 · PA-5220-HQ */
  { id:'POL-001', firewallId:'fw-001', name:'allow-http-outbound',     srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'10.0.0.0/8',     dstIp:'0.0.0.0/0',      service:'tcp/80',         action:'allow', status:'shadowed',   shadowedBy:'POL-002', riskScore:87, priority:1,  enabled:true },
  { id:'POL-002', firewallId:'fw-001', name:'allow-web-traffic',       srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'10.0.0.0/8',     dstIp:'0.0.0.0/0',      service:'tcp/80,443',     action:'allow', status:'clean',                          riskScore:35, priority:2,  enabled:true },
  { id:'POL-003', firewallId:'fw-001', name:'allow-ssh-admin',         srcZone:'MGMT',   dstZone:'TRUST',   srcIp:'10.10.0.0/24',   dstIp:'10.0.0.0/8',     service:'tcp/22',         action:'allow', status:'permissive',                     riskScore:91, priority:3,  enabled:true },
  { id:'POL-004', firewallId:'fw-001', name:'block-tor-egress',        srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'any',            dstIp:'tor-exit-nodes', service:'any',            action:'deny',  status:'clean',                          riskScore:10, priority:4,  enabled:true },
  { id:'POL-005', firewallId:'fw-001', name:'allow-dns-internal',      srcZone:'TRUST',  dstZone:'TRUST',   srcIp:'any',            dstIp:'10.1.1.53',      service:'udp/53',         action:'allow', status:'redundant',  shadowedBy:'POL-006', riskScore:22, priority:5,  enabled:true },
  { id:'POL-006', firewallId:'fw-001', name:'allow-dns-all',           srcZone:'TRUST',  dstZone:'TRUST',   srcIp:'any',            dstIp:'any',            service:'udp/53',         action:'allow', status:'permissive',                     riskScore:74, priority:6,  enabled:true },
  { id:'POL-007', firewallId:'fw-001', name:'block-smb-external',      srcZone:'UNTRUST',dstZone:'TRUST',   srcIp:'any',            dstIp:'any',            service:'tcp/445',        action:'deny',  status:'clean',                          riskScore:8,  priority:7,  enabled:true },
  { id:'POL-008', firewallId:'fw-001', name:'allow-https-dmz',         srcZone:'DMZ',    dstZone:'UNTRUST', srcIp:'172.16.0.0/16',  dstIp:'0.0.0.0/0',      service:'tcp/443',        action:'allow', status:'clean',                          riskScore:30, priority:8,  enabled:true },
  { id:'POL-009', firewallId:'fw-001', name:'allow-rdp-internal',      srcZone:'MGMT',   dstZone:'TRUST',   srcIp:'10.10.0.0/24',   dstIp:'10.0.0.0/8',     service:'tcp/3389',       action:'allow', status:'permissive',                     riskScore:88, priority:9,  enabled:true },
  { id:'POL-010', firewallId:'fw-001', name:'block-icmp-flood',        srcZone:'UNTRUST',dstZone:'TRUST',   srcIp:'any',            dstIp:'any',            service:'icmp',           action:'deny',  status:'clean',                          riskScore:5,  priority:10, enabled:false },
  { id:'POL-011', firewallId:'fw-001', name:'allow-ntp-sync',          srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'10.0.0.0/8',     dstIp:'pool.ntp.org',   service:'udp/123',        action:'allow', status:'clean',                          riskScore:15, priority:11, enabled:true },
  { id:'POL-012', firewallId:'fw-001', name:'deny-all-default',        srcZone:'any',    dstZone:'any',     srcIp:'any',            dstIp:'any',            service:'any',            action:'deny',  status:'clean',                          riskScore:2,  priority:12, enabled:true },

  /* fw-002 · PA-3260-DMZ */
  { id:'POL-013', firewallId:'fw-002', name:'allow-http-dmz-in',       srcZone:'UNTRUST',dstZone:'DMZ',     srcIp:'0.0.0.0/0',      dstIp:'172.16.10.0/24', service:'tcp/80',         action:'allow', status:'clean',                          riskScore:40, priority:1,  enabled:true },
  { id:'POL-014', firewallId:'fw-002', name:'allow-https-dmz-in',      srcZone:'UNTRUST',dstZone:'DMZ',     srcIp:'0.0.0.0/0',      dstIp:'172.16.10.0/24', service:'tcp/443',        action:'allow', status:'clean',                          riskScore:38, priority:2,  enabled:true },
  { id:'POL-015', firewallId:'fw-002', name:'allow-mail-smtp',         srcZone:'UNTRUST',dstZone:'DMZ',     srcIp:'0.0.0.0/0',      dstIp:'172.16.10.25',   service:'tcp/25',         action:'allow', status:'shadowed',   shadowedBy:'POL-016', riskScore:71, priority:3,  enabled:true },
  { id:'POL-016', firewallId:'fw-002', name:'allow-mail-all',          srcZone:'UNTRUST',dstZone:'DMZ',     srcIp:'any',            dstIp:'any',            service:'tcp/25,587',     action:'allow', status:'permissive',                     riskScore:82, priority:4,  enabled:true },
  { id:'POL-017', firewallId:'fw-002', name:'block-dmz-to-trust',      srcZone:'DMZ',    dstZone:'TRUST',   srcIp:'any',            dstIp:'any',            service:'any',            action:'deny',  status:'clean',                          riskScore:4,  priority:5,  enabled:true },
  { id:'POL-018', firewallId:'fw-002', name:'allow-db-access-old',     srcZone:'DMZ',    dstZone:'TRUST',   srcIp:'172.16.10.0/24', dstIp:'10.5.0.100',     service:'tcp/3306',       action:'allow', status:'shadowed',   shadowedBy:'POL-017', riskScore:93, priority:6,  enabled:true },
  { id:'POL-019', firewallId:'fw-002', name:'allow-waf-health',        srcZone:'DMZ',    dstZone:'DMZ',     srcIp:'172.16.10.20',   dstIp:'172.16.10.0/24', service:'tcp/8080',       action:'allow', status:'clean',                          riskScore:18, priority:7,  enabled:true },

  /* fw-003 · PA-820-Branch */
  { id:'POL-020', firewallId:'fw-003', name:'allow-vpn-users',         srcZone:'VPN',    dstZone:'TRUST',   srcIp:'10.200.0.0/16',  dstIp:'10.0.0.0/8',     service:'any',            action:'allow', status:'permissive',                     riskScore:85, priority:1,  enabled:true },
  { id:'POL-021', firewallId:'fw-003', name:'allow-teams-traffic',     srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'10.20.0.0/16',   dstIp:'52.112.0.0/14',  service:'tcp/443,3478',   action:'allow', status:'clean',                          riskScore:20, priority:2,  enabled:true },
  { id:'POL-022', firewallId:'fw-003', name:'allow-print-old',         srcZone:'TRUST',  dstZone:'TRUST',   srcIp:'10.20.1.0/24',   dstIp:'10.20.2.50',     service:'tcp/9100',       action:'allow', status:'redundant',  shadowedBy:'POL-023', riskScore:30, priority:3,  enabled:true },
  { id:'POL-023', firewallId:'fw-003', name:'allow-print-new',         srcZone:'TRUST',  dstZone:'TRUST',   srcIp:'10.20.0.0/16',   dstIp:'10.20.2.0/24',   service:'tcp/9100,515',   action:'allow', status:'clean',                          riskScore:25, priority:4,  enabled:true },
  { id:'POL-024', firewallId:'fw-003', name:'block-social-media',      srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'any',            dstIp:'social-media-group', service:'tcp/443',    action:'deny',  status:'clean',                          riskScore:7,  priority:5,  enabled:true },
  { id:'POL-025', firewallId:'fw-003', name:'allow-internet-any',      srcZone:'TRUST',  dstZone:'UNTRUST', srcIp:'any',            dstIp:'any',            service:'any',            action:'allow', status:'permissive',                     riskScore:96, priority:6,  enabled:true },

  /* fw-004 · FG-600F-CORE */
  { id:'POL-026', firewallId:'fw-004', name:'lan-to-wan-full',         srcZone:'LAN',    dstZone:'WAN',     srcIp:'192.168.0.0/16', dstIp:'0.0.0.0/0',      service:'any',            action:'allow', status:'permissive',                     riskScore:94, priority:1,  enabled:true },
  { id:'POL-027', firewallId:'fw-004', name:'block-p2p',               srcZone:'LAN',    dstZone:'WAN',     srcIp:'any',            dstIp:'any',            service:'p2p',            action:'deny',  status:'shadowed',   shadowedBy:'POL-026', riskScore:60, priority:2,  enabled:true },
  { id:'POL-028', firewallId:'fw-004', name:'allow-sap-traffic',       srcZone:'LAN',    dstZone:'SERVER',  srcIp:'10.1.0.0/24',    dstIp:'10.2.0.50',      service:'tcp/3200,3300',  action:'allow', status:'clean',                          riskScore:28, priority:3,  enabled:true },
  { id:'POL-029', firewallId:'fw-004', name:'allow-erp-backup',        srcZone:'SERVER', dstZone:'BACKUP',  srcIp:'10.2.0.50',      dstIp:'10.3.0.200',     service:'tcp/22',         action:'allow', status:'clean',                          riskScore:18, priority:4,  enabled:true },
  { id:'POL-030', firewallId:'fw-004', name:'allow-ad-traffic',        srcZone:'LAN',    dstZone:'SERVER',  srcIp:'any',            dstIp:'10.2.0.10',      service:'tcp/389,636,88', action:'allow', status:'redundant',  shadowedBy:'POL-031', riskScore:44, priority:5,  enabled:true },
  { id:'POL-031', firewallId:'fw-004', name:'allow-ad-extended',       srcZone:'LAN',    dstZone:'SERVER',  srcIp:'any',            dstIp:'10.2.0.0/24',    service:'tcp/389,636,88,3268', action:'allow', status:'permissive',               riskScore:67, priority:6,  enabled:true },
  { id:'POL-032', firewallId:'fw-004', name:'block-malware-c2',        srcZone:'any',    dstZone:'WAN',     srcIp:'any',            dstIp:'threat-intel-group', service:'any',        action:'deny',  status:'clean',                          riskScore:3,  priority:7,  enabled:true },
  { id:'POL-033', firewallId:'fw-004', name:'allow-video-conf',        srcZone:'LAN',    dstZone:'WAN',     srcIp:'192.168.10.0/24',dstIp:'0.0.0.0/0',      service:'tcp/443,udp/3478', action:'allow', status:'clean',                        riskScore:22, priority:8,  enabled:true },
  { id:'POL-034', firewallId:'fw-004', name:'allow-ot-net',            srcZone:'OT',     dstZone:'LAN',     srcIp:'10.100.0.0/16',  dstIp:'any',            service:'any',            action:'allow', status:'permissive',                     riskScore:89, priority:9,  enabled:true },
  { id:'POL-035', firewallId:'fw-004', name:'allow-snmp-monitor',      srcZone:'MGMT',   dstZone:'any',     srcIp:'10.10.0.5',      dstIp:'any',            service:'udp/161,162',    action:'allow', status:'clean',                          riskScore:16, priority:10, enabled:true },
  { id:'POL-036', firewallId:'fw-004', name:'allow-backup-ftp',        srcZone:'BACKUP', dstZone:'LAN',     srcIp:'10.3.0.200',     dstIp:'any',            service:'tcp/21',         action:'allow', status:'permissive',                     riskScore:75, priority:11, enabled:true },
  { id:'POL-037', firewallId:'fw-004', name:'allow-vxlan-tunnel',      srcZone:'SERVER', dstZone:'DR',      srcIp:'10.2.0.0/24',    dstIp:'10.50.0.0/24',   service:'udp/4789',       action:'allow', status:'clean',                          riskScore:20, priority:12, enabled:true },
  { id:'POL-038', firewallId:'fw-004', name:'block-telnet',            srcZone:'any',    dstZone:'any',     srcIp:'any',            dstIp:'any',            service:'tcp/23',         action:'deny',  status:'clean',                          riskScore:5,  priority:13, enabled:true },
  { id:'POL-039', firewallId:'fw-004', name:'deny-all-default',        srcZone:'any',    dstZone:'any',     srcIp:'any',            dstIp:'any',            service:'any',            action:'deny',  status:'clean',                          riskScore:1,  priority:14, enabled:true },

  /* fw-005 · FG-200F-DR */
  { id:'POL-040', firewallId:'fw-005', name:'allow-replication',       srcZone:'WAN',    dstZone:'DR',      srcIp:'10.2.0.0/24',    dstIp:'10.50.0.0/24',   service:'tcp/8445',       action:'allow', status:'clean',                          riskScore:32, priority:1,  enabled:true },
  { id:'POL-041', firewallId:'fw-005', name:'allow-https-mgmt',        srcZone:'MGMT',   dstZone:'DR',      srcIp:'10.10.0.0/24',   dstIp:'10.50.0.1',      service:'tcp/443',        action:'allow', status:'clean',                          riskScore:20, priority:2,  enabled:true },
  { id:'POL-042', firewallId:'fw-005', name:'allow-dr-any-out',        srcZone:'DR',     dstZone:'WAN',     srcIp:'any',            dstIp:'any',            service:'any',            action:'allow', status:'permissive',                     riskScore:88, priority:3,  enabled:true },
  { id:'POL-043', firewallId:'fw-005', name:'allow-failover-vip',      srcZone:'WAN',    dstZone:'DR',      srcIp:'0.0.0.0/0',      dstIp:'10.50.100.10',   service:'tcp/80,443',     action:'allow', status:'clean',                          riskScore:38, priority:4,  enabled:true },
  { id:'POL-044', firewallId:'fw-005', name:'block-all-default',       srcZone:'any',    dstZone:'any',     srcIp:'any',            dstIp:'any',            service:'any',            action:'deny',  status:'clean',                          riskScore:1,  priority:5,  enabled:true },
];

LFPM.conflicts = [
  { id:'CONF-001', type:'cross-vendor', ruleA:'POL-026', ruleB:'POL-004', firewallA:'fw-004', firewallB:'fw-001', severity:'critical',
    description:'FG-600F-CORE permits all LAN→WAN traffic, defeating PA-5220-HQ\'s tor-egress block for traffic transiting the core stack.' },
  { id:'CONF-002', type:'transitive',   ruleA:'POL-020', ruleB:'POL-025', firewallA:'fw-003', firewallB:'fw-003', severity:'critical',
    description:'VPN→Trust any/any compounded with Trust→Untrust any/any creates a VPN→Internet path with no inspection.' },
  { id:'CONF-003', type:'asymmetric',   ruleA:'POL-016', ruleB:'POL-015', firewallA:'fw-002', firewallB:'fw-002', severity:'high',
    description:'allow-mail-all shadows the more specific allow-mail-smtp rule, weakening the SMTP-only restriction.' },
];

LFPM.threats = [
  { id:'CVE-2024-3400',  severity:'critical', cvss:10.0, title:'PAN-OS Command Injection in GlobalProtect',
    firmware:['PAN-OS 10.1.6','PAN-OS 10.1.3','PAN-OS 9.1.12'], vendors:['palo-alto'],
    firewallIds:['fw-001','fw-002','fw-003'], published:'2024-04-12', patched:'PAN-OS 11.0.4',
    exploit:'active', kev:true,
    description:'A command injection vulnerability in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.' },
  { id:'CVE-2024-21762', severity:'critical', cvss:9.6, title:'FortiOS Out-of-Bounds Write in sslvpnd',
    firmware:['FortiOS 7.0.8','FortiOS 7.2.4'], vendors:['fortinet'],
    firewallIds:['fw-004','fw-005'], published:'2024-02-08', patched:'FortiOS 7.4.3',
    exploit:'active', kev:true,
    description:'OOB write in FortiOS sslvpnd allows remote unauthenticated attackers to execute arbitrary code via crafted HTTP requests.' },
  { id:'CVE-2023-27997', severity:'critical', cvss:9.8, title:'FortiOS SSL-VPN Heap Buffer Overflow (RCE)',
    firmware:['FortiOS 7.0.8','FortiOS 7.2.4'], vendors:['fortinet'],
    firewallIds:['fw-004','fw-005'], published:'2023-06-11', patched:'FortiOS 7.2.5',
    exploit:'poc',
    description:'Heap-based buffer overflow in FortiOS SSL-VPN enables remote unauthenticated RCE.' },
  { id:'CVE-2024-0012',  severity:'critical', cvss:9.3, title:'PAN-OS Management Interface Authentication Bypass',
    firmware:['PAN-OS 9.1.12','PAN-OS 10.1.3'], vendors:['palo-alto'],
    firewallIds:['fw-003','fw-002'], published:'2024-11-18', patched:'PAN-OS 10.2.12',
    exploit:'active', kev:true,
    description:'Auth bypass in PAN-OS management web interface grants admin privileges to a network-based attacker.' },
  { id:'CVE-2024-23113', severity:'critical', cvss:9.8, title:'FortiOS fgfmd Daemon Format String RCE',
    firmware:['FortiOS 7.2.4','FortiOS 7.0.8'], vendors:['fortinet'],
    firewallIds:['fw-004','fw-005'], published:'2024-02-08', patched:'FortiOS 7.4.3',
    exploit:'poc',
    description:'Externally-controlled format string in FortiOS fgfmd daemon enables remote unauthenticated RCE.' },
  { id:'CVE-2024-9474',  severity:'high', cvss:7.2, title:'PAN-OS Privilege Escalation via Web Interface',
    firmware:['PAN-OS 10.1.6','PAN-OS 10.1.3','PAN-OS 9.1.12'], vendors:['palo-alto'],
    firewallIds:['fw-001','fw-002','fw-003'], published:'2024-11-18', patched:'PAN-OS 10.2.12',
    exploit:'active',
    description:'Privilege escalation allowing admin actions to run with root privileges on the firewall.' },
  { id:'CVE-2024-6387',  severity:'critical', cvss:8.1, title:'OpenSSH regreSSHion Remote Code Execution',
    firmware:['PAN-OS 9.1.12','PAN-OS 10.1.3','FortiOS 7.0.8'], vendors:['palo-alto','fortinet'],
    firewallIds:['fw-003','fw-002','fw-005'], published:'2024-07-01', patched:'OpenSSH 9.8p1',
    exploit:'poc',
    description:'Signal handler race condition in OpenSSH sshd allows unauthenticated RCE as root on any host exposing SSH.' },
  { id:'CVE-2023-44487', severity:'high', cvss:7.5, title:'HTTP/2 Rapid Reset DDoS (Multi-Vendor)',
    firmware:['FortiOS 7.2.4','PAN-OS 10.1.6','PAN-OS 10.1.3'], vendors:['fortinet','palo-alto'],
    firewallIds:['fw-004','fw-001','fw-002'], published:'2023-10-10', patched:'FortiOS 7.4.2, PAN-OS 10.2.5',
    exploit:'wild',
    description:'HTTP/2 protocol flaw enables DoS against HTTP/2-enabled servers via streams of RST_STREAM frames.' },
  { id:'CVE-2022-42475', severity:'critical', cvss:9.3, title:'FortiOS SSL-VPN Heap-based Buffer Overflow',
    firmware:['FortiOS 7.0.8'], vendors:['fortinet'],
    firewallIds:['fw-005'], published:'2022-12-12', patched:'FortiOS 7.2.3',
    exploit:'active', kev:true,
    description:'Heap-based buffer overflow in FortiOS SSL-VPN enables remote unauthenticated RCE via crafted requests.' },
  { id:'CVE-2024-4577',  severity:'critical', cvss:9.8, title:'PHP CGI Argument Injection RCE',
    firmware:['PAN-OS 9.1.12','FortiOS 7.0.8'], vendors:['palo-alto','fortinet'],
    firewallIds:['fw-003','fw-005'], published:'2024-06-06', patched:'PHP 8.3.8',
    exploit:'active',
    description:'PHP CGI argument injection enables RCE on web servers behind permissive HTTP policies.' },
  { id:'CVE-2024-7593',  severity:'critical', cvss:9.8, title:'Ivanti vTM Authentication Bypass',
    firmware:['FortiOS 7.2.4','PAN-OS 10.1.6'], vendors:['fortinet','palo-alto'],
    firewallIds:['fw-004','fw-001'], published:'2024-08-13', patched:'Third-party patch',
    exploit:'poc',
    description:'Auth bypass in Ivanti vTM admin panel; chained policy paths route traffic through affected load balancers.' },
  { id:'CVE-2023-6549',  severity:'high', cvss:8.2, title:'Citrix Bleed — Memory Leak via NetScaler',
    firmware:['FortiOS 7.0.8','PAN-OS 9.1.12'], vendors:['fortinet','palo-alto'],
    firewallIds:['fw-005','fw-003'], published:'2023-11-10', patched:'Vendor advisory',
    exploit:'active',
    description:'Sensitive info disclosure in NetScaler ADC/Gateway leading to session token theft.' },
];

LFPM.firmwareTimeline = [
  { firmware:'PAN-OS 9.1.12', vendor:'palo-alto', released:'2022-08-15', eol:'2025-03-01', cves:4, isEol:true,  installed:1 },
  { firmware:'PAN-OS 10.1.3', vendor:'palo-alto', released:'2022-03-17', eol:'2026-06-30', cves:5, isEol:false, installed:1 },
  { firmware:'PAN-OS 10.1.6', vendor:'palo-alto', released:'2022-09-14', eol:'2026-06-30', cves:4, isEol:false, installed:1 },
  { firmware:'FortiOS 7.0.8', vendor:'fortinet',  released:'2023-03-07', eol:'2025-09-30', cves:6, isEol:false, installed:1 },
  { firmware:'FortiOS 7.2.4', vendor:'fortinet',  released:'2023-05-20', eol:'2027-01-01', cves:5, isEol:false, installed:1 },
];

/* ── Topology nodes ─────────────────────────────────────────── */
LFPM.zones = [
  { id:'z-untrust',  fwId:'fw-001', name:'untrust',  type:'untrust', subnet:'0.0.0.0/0' },
  { id:'z-dmz',      fwId:'fw-002', name:'dmz',      type:'dmz',     subnet:'172.16.10.0/24' },
  { id:'z-trust',    fwId:'fw-001', name:'trust',    type:'trust',   subnet:'10.0.0.0/8' },
  { id:'z-mgmt',     fwId:'fw-001', name:'mgmt',     type:'mgmt',    subnet:'10.10.0.0/24' },
  { id:'z-server',   fwId:'fw-004', name:'server',   type:'server',  subnet:'10.2.0.0/24' },
  { id:'z-lan',      fwId:'fw-004', name:'lan',      type:'trust',   subnet:'192.168.0.0/16' },
  { id:'z-ot',       fwId:'fw-004', name:'ot',       type:'ot',      subnet:'10.100.0.0/16' },
  { id:'z-dr',       fwId:'fw-005', name:'dr',       type:'dr',      subnet:'10.50.0.0/24' },
  { id:'z-branch',   fwId:'fw-003', name:'branch',   type:'trust',   subnet:'10.20.0.0/16' },
  { id:'z-vpn',      fwId:'fw-003', name:'vpn',      type:'vpn',     subnet:'10.200.0.0/16' },
];

LFPM.assets = [
  { id:'a-web-01',   zoneId:'z-dmz',    name:'web-01',     kind:'web',   ip:'172.16.10.10', os:'Ubuntu 22.04 LTS' },
  { id:'a-mail-01',  zoneId:'z-dmz',    name:'mail-01',    kind:'mail',  ip:'172.16.10.25', os:'Exchange 2019' },
  { id:'a-app-01',   zoneId:'z-trust',  name:'app-01',     kind:'app',   ip:'10.1.1.20',    os:'RHEL 8.6' },
  { id:'a-admin-ws', zoneId:'z-mgmt',   name:'admin-ws',   kind:'host',  ip:'10.10.0.50',   os:'Windows 11 Pro' },
  { id:'a-ad-01',    zoneId:'z-server', name:'ad-01',      kind:'app',   ip:'10.2.0.10',    os:'Windows Server 2022' },
  { id:'a-sap-01',   zoneId:'z-server', name:'sap-erp-01', kind:'db',    ip:'10.2.0.50',    os:'SAP S/4HANA' },
  { id:'a-scada',    zoneId:'z-ot',     name:'scada-gw',   kind:'app',   ip:'10.100.0.10',  os:'Siemens S7' },
  { id:'a-dr-db',    zoneId:'z-dr',     name:'dr-db-01',   kind:'db',    ip:'10.50.0.100',  os:'PostgreSQL 15' },
  { id:'a-dr-app',   zoneId:'z-dr',     name:'dr-app-01',  kind:'app',   ip:'10.50.0.20',   os:'RHEL 8.6' },
  { id:'a-branch-ws',zoneId:'z-branch', name:'office-vlan',kind:'host',  ip:'10.20.10.0/24',os:'Mixed' },
];

LFPM.externalNodes = [
  { id:'ext-internet',  name:'internet',           kind:'internet',         ip:'0.0.0.0/0',        threat:'none',     description:'Public Internet gateway' },
  { id:'ext-susp',      name:'185.77.40.12',       kind:'suspicious',       ip:'185.77.40.12',     threat:'high',     description:'Suspicious scanning source · GeoIP: RU' },
  { id:'ext-c2',        name:'cobalt-c2',          kind:'c2',               ip:'91.215.85.209',    threat:'critical', description:'Known Cobalt Strike C2 · active beaconing detected' },
  { id:'ext-tor',       name:'tor-exit',           kind:'threat',           ip:'198.51.100.0/24',  threat:'high',     description:'Tor exit relay · anonymized egress traffic' },
];

/* ── Activity feed (synthetic SOC events for the dashboard) ── */
LFPM.activityFeed = [
  { t:'14:32:08', kind:'sync',    text:'fg-600f-core · ruleset sync complete · 198 rules · 12.4s',
    link:{ page:'topology', params:{ device:'fw-004' } } },
  { t:'14:31:54', kind:'alert',   sev:'critical', text:'CVE-2024-3400 · still unpatched on pa-820-branch',
    link:{ page:'threats',  params:{ cve:'CVE-2024-3400' } } },
  { t:'14:31:12', kind:'audit',   text:'analyst@ali ran audit on fw-004 · 3 anomalies opened',
    link:{ page:'audit',    params:{ firewall:'fw-004', filter:'anomalies' } } },
  { t:'14:30:48', kind:'block',   text:'block-malware-c2 hit · 91.215.85.209 · 6 attempts in 5m',
    link:{ page:'audit',    params:{ rule:'POL-032' } } },
  { t:'14:30:02', kind:'anomaly', sev:'high',     text:'new shadowed rule detected on pa-3260-dmz · POL-018',
    link:{ page:'audit',    params:{ rule:'POL-018' } } },
  { t:'14:29:31', kind:'sync',    text:'pa-5220-hq · ruleset diff · +2 −1 ·  0 conflicts',
    link:{ page:'topology', params:{ device:'fw-001' } } },
  { t:'14:28:55', kind:'login',   text:'hamza@lumina-fpm.local · session opened · 102.43.18.4' },
  { t:'14:28:12', kind:'alert',   sev:'high',     text:'fg-200f-dr · firmware 7.0.8 · 6 open CVEs',
    link:{ page:'threats',  params:{ vendor:'fortinet' } } },
  { t:'14:26:40', kind:'audit',   text:'cross-vendor analysis complete · 3 conflicts surfaced',
    link:{ page:'audit',    params:{ filter:'anomalies' } } },
  { t:'14:25:18', kind:'sync',    text:'fortinet api · auth refresh · ok' },
  { t:'14:24:02', kind:'block',   text:'block-tor-egress hit · 198.51.100.42 · 1 attempt',
    link:{ page:'audit',    params:{ rule:'POL-004' } } },
  { t:'14:22:48', kind:'anomaly', sev:'medium',   text:'redundant rule pair on fw-004 · POL-030 ⇄ POL-031',
    link:{ page:'audit',    params:{ rule:'POL-030' } } },
];

/* ── 24h rule-hit time series (for sparkline) ── */
LFPM.hits24h = Array.from({ length: 48 }, (_, i) => {
  const base = 240 + Math.sin(i / 5) * 80 + Math.cos(i / 3) * 40;
  return Math.round(base + (i === 31 ? 220 : 0) + (Math.random() - 0.5) * 30);
});

/* ── Users (mock) ── */
LFPM.users = [
  { id:'usr-001', name:'Hamza Selim',    email:'hamza@lumina-fpm.local',   role:'admin',    avatar:'HS', dept:'Security Ops' },
  { id:'usr-002', name:'Youssef Hazem',  email:'youssef@lumina-fpm.local', role:'analyst',  avatar:'YH', dept:'Threat Intel' },
  { id:'usr-003', name:'Ali Hesham',     email:'ali@lumina-fpm.local',     role:'viewer',   avatar:'AH', dept:'Network Eng' },
];

/* ── Saved searches (for command palette demo) ── */
LFPM.savedSearches = [
  { id:'s1', text:'status:permissive risk:>=80',          owner:'hamza' },
  { id:'s2', text:'firewall:fw-004 anomalies',            owner:'hamza' },
  { id:'s3', text:'cve:active vendor:fortinet',           owner:'youssef' },
  { id:'s4', text:'shadowed disabled:false',              owner:'ali' },
];

/* ── Helpers ────────────────────────────────────────────────── */
LFPM.fmt = {
  riskColor(v) {
    if (v >= 80) return 'var(--sev-critical)';
    if (v >= 60) return 'var(--sev-high)';
    if (v >= 40) return 'var(--sev-medium)';
    if (v >= 20) return 'var(--sev-low)';
    return 'var(--sev-safe)';
  },
  riskLabel(v) {
    if (v >= 80) return 'critical';
    if (v >= 60) return 'high';
    if (v >= 40) return 'medium';
    if (v >= 20) return 'low';
    return 'safe';
  },
  sevColor(s) {
    return ({
      critical:'var(--sev-critical)', high:'var(--sev-high)',
      medium:'var(--sev-medium)',   low:'var(--sev-low)',
      safe:'var(--sev-safe)', clean:'var(--sev-safe)',
    })[s] || 'var(--fg-muted)';
  },
  exploitLabel(e) {
    return ({ active:'actively exploited', poc:'PoC published', wild:'widely exploited', none:'no known exploit' })[e] || e;
  },
  /* relative time */
  rel(iso) {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400)return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  },
};
