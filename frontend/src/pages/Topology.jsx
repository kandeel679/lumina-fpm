import { useState, useRef, useEffect, useMemo } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { Loader, AlertTriangle } from 'lucide-react';

cytoscape.use(dagre);

import { fetchAllData } from '../api/api';

import TopologyFilters from '../components/topology/TopologyFilters';
import TopologyControls from '../components/topology/TopologyControls';
import TopologyTopStats from '../components/topology/TopologyTopStats';
import TopologyInfoPanel from '../components/topology/TopologyInfoPanel';

/* ── SVG Data URI for Vendor Background (keep this procedural) ──────────────────────────── */
const VENDOR_BG = `data:image/svg+xml;utf8,%3Csvg width='20' height='20' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M0 20L20 0z' stroke='rgba(255,255,255,0.03)' stroke-width='1' fill='none'/%3E%3C/svg%3E`;

/* ── Node Color Helper ──────────────────────────── */
function getNodeColor(score) {
  if (score >= 80) return '#ef4444'; // Malicious (Red)
  if (score >= 40) return '#f97316'; // Suspicious (Orange)
  return '#10b981'; // Normal (Green)
}
function getEdgeStyle(policiesList) {
  const maxRisk = Math.max(...policiesList.map(p => p.riskScore), 0);
  const color = getNodeColor(maxRisk);
  const isMalicious = maxRisk >= 80;
  return {
    color,
    width: isMalicious ? 3 : 2,
    style: isMalicious ? 'solid' : 'dashed',
    opacity: isMalicious ? 0.9 : 0.6
  };
}

/* ── Graph Builder ─────────────────────────── */
function buildGraphData(filters, isExpanded, apiData) {
  const { firewalls = [], vendors = [], policies = [], conflicts = [], threats = [] } = apiData || {};
  const els = [];
  const metrics = { totalNodes: 1, totalEdges: 0, maliciousNodes: 0, conflictEdges: 0, cleanNodes: 0 };

  // Internet node (Global)
  els.push({
    data: { id: 'internet', label: 'Internet', type: 'internet', color: '#475569', ip: 'Global Space' },
  });

  if (filters.showVendors) {
    vendors.forEach(v => {
      els.push({ data: { id: v.id, label: v.name, type: 'vendor', color: v.color } });
    });
  }

  // Nested Firewalls
  firewalls.forEach(fw => {
    // Firewall Compound Node
    els.push({
      data: {
        id: fw.id, label: fw.name,
        type: 'firewall',
        parent: filters.showVendors ? fw.vendorId : undefined,
        vendor: fw.vendor,
        ip: fw.ip,
        color: '#334155'
      }
    });
  });

  // Mine internal zones from policies to create Server Nodes
  const internalNodes = new Set();
  const edgesMap = {}; 

  policies.forEach(p => {
    if (!p.enabled) return;
    const isExtSrc = ['UNTRUST', 'WAN', 'any', 'VPN'].includes(p.srcZone);
    const isExtDst = ['UNTRUST', 'WAN', 'any'].includes(p.dstZone);

    const src = isExtSrc ? 'internet' : `${p.firewallId}-${p.srcZone}`;
    const dst = isExtDst ? 'internet' : `${p.firewallId}-${p.dstZone}`;

    if (!isExtSrc) internalNodes.add(JSON.stringify({ id: src, fw: p.firewallId, zone: p.srcZone, vendor: p.vendor }));
    if (!isExtDst) internalNodes.add(JSON.stringify({ id: dst, fw: p.firewallId, zone: p.dstZone, vendor: p.vendor }));

    if (src !== dst) {
      const key = isExpanded ? `${src}:::${dst}:::${p.id}` : `${src}:::${dst}`;
      if (!edgesMap[key]) {
        edgesMap[key] = { source: src, target: dst, firewallId: p.firewallId, firewallName: p.firewall, policies: [] };
      }
      edgesMap[key].policies.push(p);
    }
  });

  // Adding Server nodes
  internalNodes.forEach(json => {
    const sn = JSON.parse(json);
    const relatedPolicies = policies.filter(p => (p.firewallId === sn.fw) && (p.srcZone === sn.zone || p.dstZone === sn.zone));
    const worstRisk = Math.max(...relatedPolicies.map(p => p.riskScore), 0);
    const nodeColor = getNodeColor(worstRisk);
    
    if (worstRisk >= 80) metrics.maliciousNodes++;
    else if (worstRisk < 40) metrics.cleanNodes++;
    metrics.totalNodes++;

    const isComputer = sn.zone.toUpperCase().includes('LAN') || 
                       sn.zone.toUpperCase().includes('USER') || 
                       sn.zone.toUpperCase().includes('VPN') ||
                       sn.zone.toUpperCase().includes('GUEST');
    
    els.push({
      data: {
        id: sn.id, type: isComputer ? 'computer' : 'server', parent: sn.fw,
        label: filters.showLabels ? `${sn.zone}\n[ ${sn.id.slice(0,8).toUpperCase()} ]` : '',
        color: nodeColor, riskScore: worstRisk,
        ip: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.0/24`,
        vendor: sn.vendor, zoneName: sn.zone,
        threats: threats.filter(t => t.affectedFirewalls.includes(firewalls.find(f => f.id === sn.fw)?.name))
      }
    });
  });

  // Adding Edges
  Object.entries(edgesMap).forEach(([key, edge]) => {
    const estyle = getEdgeStyle(edge.policies);
    const maxRisk = Math.max(...edge.policies.map(p => p.riskScore), 0);
    
    // Check conflicts
    const hasConflict = conflicts.some(c => edge.policies.map(p=>p.id).includes(c.ruleA) || edge.policies.map(p=>p.id).includes(c.ruleB));
    if (hasConflict) metrics.conflictEdges++;

    // Only add if it passes risk filter
    if (filters.riskOnly && maxRisk < 40) return;

    metrics.totalEdges++;

    els.push({
      data: {
        id: `e-${key}`, source: edge.source, target: edge.target,
        type: 'policy', policies: edge.policies,
        firewallId: edge.firewallId, firewallName: edge.firewallName,
        maxRisk, color: estyle.color, 
        hasConflict,
        sourceLabel: edge.source === 'internet' ? 'Internet' : edge.source.split('-').slice(1).join('-') + ' Zone',
        destLabel: edge.target === 'internet' ? 'Internet' : edge.target.split('-').slice(1).join('-') + ' Zone',
      },
      classes: hasConflict ? 'edge-conflict' : (maxRisk >= 80 ? 'edge-malicious' : '')
    });
  });

  return { elements: els, metrics };
}

/* ── Cytoscape Stylesheet ─────────────────────────── */
const stylesheet = [
  {
    selector: 'node[type="internet"]',
    style: {
      label: 'data(label)', 'color': '#cbd5e1', 'font-size': 14,
      'text-valign': 'bottom', 'text-margin-y': 10, 'font-weight': 600,
      'font-family': 'Inter, sans-serif',
      shape: 'ellipse', width: 64, height: 64,
      'background-image': '/icons/world.svg', 'background-fit': 'contain',
      'background-color': '#020617', 'border-width': 1, 'border-color': '#475569'
    }
  },
  {
    selector: 'node[type="vendor"]',
    style: {
      label: 'data(label)', color: 'data(color)', 'font-size': 12,
      'font-family': 'Inter, sans-serif',
      'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -12,
      'font-weight': 700, 'text-transform': 'uppercase', 'letter-spacing': '2px',
      shape: 'roundrectangle', 'background-color': 'rgba(2, 6, 23, 0.7)',
      'background-image': VENDOR_BG,
      'background-repeat': 'repeat',
      'border-width': 1, 'border-color': 'data(color)', 'border-opacity': 0.6,
      padding: '40px', 'border-style': 'solid'
    }
  },
  {
    selector: 'node[type="firewall"]',
    style: {
      label: 'data(label)', color: '#94a3b8', 'font-size': 11,
      'font-family': 'Inter, sans-serif',
      'text-valign': 'top', 'text-halign': 'center', 'text-margin-y': -8,
      'font-weight': 600, 'text-transform': 'uppercase', 'letter-spacing': '1px',
      shape: 'roundrectangle', 'background-color': 'rgba(15, 23, 42, 0.4)',
      'background-image': '/icons/firewall.svg',
      'background-position-x': '10px', 'background-position-y': '10px',
      'background-width': '22px', 'background-height': '22px',
      'background-repeat': 'no-repeat',
      'border-width': 1, 'border-color': '#475569', 'border-style': 'dashed',
      padding: '30px'
    }
  },
  {
    selector: 'node[type="server"], node[type="computer"]',
    style: {
      label: 'data(label)', color: '#e2e8f0', 'font-size': 10,
      'font-family': 'Inter, monospace', 'line-height': 1.4,
      'text-wrap': 'wrap', 'text-valign': 'bottom', 'text-margin-y': 8,
      shape: 'ellipse', width: 44, height: 44,
      'background-color': 'rgba(15, 23, 42, 0.8)', 'border-width': 2, 
      'border-color': 'data(color)',
      'background-fit': 'contain'
    }
  },
  {
    selector: 'node[type="server"]',
    style: { 'background-image': '/icons/server.svg' }
  },
  {
    selector: 'node[type="computer"]',
    style: { 'background-image': '/icons/computer.svg' }
  },
  {
    // Glow and custom threat icon for malicious nodes
    selector: 'node[riskScore >= 80]',
    style: { 
      'background-image': '/icons/threat.svg',
      'border-width': 3, 
      'shadow-blur': 15, 
      'shadow-color': '#ef4444', 
      'shadow-opacity': 0.8 
    }
  },
  {
    // Edges
    selector: 'edge',
    style: {
      width: 'data(maxRisk >= 80 ? 3 : 2)',
      'line-color': 'data(color)', 'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
      opacity: 'data(maxRisk >= 80 ? 0.9 : 0.5)',
      'line-style': 'data(maxRisk >= 80 ? solid : dashed)',
      'arrow-scale': 1.2
    }
  },
  {
    selector: 'edge.edge-conflict',
    style: { 'line-style': 'dotted', 'line-dash-pattern': [4,4], width: 4, 'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b', 'shadow-blur': 10, 'shadow-color': '#f59e0b', 'shadow-opacity': 0.8 }
  },
  {
    selector: '.inactive-focus',
    style: { opacity: 0.15, 'border-opacity': 0.1, 'text-opacity': 0.2 }
  },
  {
    selector: '.animated-edge',
    style: { 'line-style': 'dashed', 'line-dash-pattern': [10, 5] }
  },
  {
    selector: 'node:selected',
    style: { 'border-width': 4, 'border-color': '#38bdf8', 'shadow-blur': 25, 'shadow-color': '#38bdf8', 'shadow-opacity': 0.6 }
  },
  {
    selector: 'edge:selected',
    style: { width: 4, opacity: 1, 'line-color': '#38bdf8', 'target-arrow-color': '#38bdf8', 'shadow-blur': 15, 'shadow-color': '#38bdf8', 'shadow-opacity': 0.8 }
  }
];

export default function Topology() {
  const cyRef = useRef(null);
  const containerRef = useRef(null);
  
  const [apiData, setApiData] = useState(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState(null);

  const [filters, setFilters] = useState({ showVendors: true, showLabels: true, riskOnly: false });
  const [searchTerm, setSearchTerm] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [hoverData, setHoverData] = useState(null);

  useEffect(() => {
    fetchAllData()
      .then(setApiData)
      .catch(e => setDataError(e.message))
      .finally(() => setDataLoading(false));
  }, []);

  const { elements, metrics } = useMemo(() => buildGraphData(filters, isExpanded, apiData), [filters, isExpanded, apiData]);

  const handleTap = (evt) => {
    const target = evt.target;
    if (target === cyRef.current) {
      setSelectedNode(null); setSelectedEdge(null);
    } else if (target.isNode()) {
      if (['server', 'firewall', 'internet'].includes(target.data('type'))) {
        setSelectedNode(target.data()); setSelectedEdge(null);
      }
    } else if (target.isEdge()) {
      setSelectedEdge(target.data()); setSelectedNode(null);
    }
  };

  const handleMouseOver = (evt) => {
    const target = evt.target;
    if (target === cyRef.current) return;
    
    const boundingBox = target.renderedBoundingBox();
    const cyContainerPos = cyRef.current.container().getBoundingClientRect();
    
    const pos = {
      x: cyContainerPos.left + boundingBox.x1 + (boundingBox.w / 2),
      y: cyContainerPos.top + boundingBox.y1 - 10,
    };

    if (target.isNode() && target.data('type') !== 'vendor' && target.data('type') !== 'firewall') {
      setHoverData({ type: 'node', data: target.data(), pos });
    } else if (target.isEdge()) {
      setHoverData({ type: 'edge', data: target.data(), pos });
    }
  };

  const handleMouseOut = () => setHoverData(null);

  // Apply search filtering natively via cytoscape instances
  useEffect(() => {
    if(!cyRef.current) return;
    const cy = cyRef.current;
    if(searchTerm.trim() === '') {
      cy.elements().style('opacity', '');
    } else {
      const term = searchTerm.toLowerCase();
      cy.elements().forEach(ele => {
         const d = ele.data();
         let match = false;
         if(d.label && d.label.toLowerCase().includes(term)) match = true;
         if(d.ip && d.ip.toLowerCase().includes(term)) match = true;
         if(d.vendor && d.vendor.toLowerCase().includes(term)) match = true;
         if(d.type === 'policy' && d.firewallName && d.firewallName.toLowerCase().includes(term)) match = true;
         
         if(ele.isNode() && d.type === 'vendor') match = true; // don't fade out structural containers
         if(ele.isNode() && d.type === 'firewall') match = true;

         ele.style('opacity', match ? 1 : 0.05);
      });
    }
  }, [searchTerm]);

  // Analyst Focus Mode & Directional Traffic Animation
  useEffect(() => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.elements().removeClass('inactive-focus animated-edge');

    const hasFocus = selectedNode || selectedEdge || hoverData;

    if (hasFocus) {
      if (selectedNode || hoverData?.type === 'node') {
        const focusId = selectedNode ? selectedNode.id : hoverData.data.id;
        const node = cy.getElementById(focusId);
        if (node.length > 0) {
           const neighborhood = node.neighborhood();
           cy.elements().difference(neighborhood).difference(node).addClass('inactive-focus');
           
           // Animate risky paths connected to focused asset
           node.connectedEdges('[maxRisk >= 40]').addClass('animated-edge');
        }
      } else if (selectedEdge || hoverData?.type === 'edge') {
        const focusId = selectedEdge ? selectedEdge.id : hoverData.data.id;
        const edge = cy.getElementById(focusId);
        if (edge.length > 0) {
           const connectedNodes = edge.connectedNodes();
           // Un-dim parent compounds to keep geographic structure
           const parentVendors = connectedNodes.parents(); 
           cy.elements().difference(connectedNodes).difference(parentVendors).difference(edge).addClass('inactive-focus');
           
           if (edge.data('maxRisk') >= 40) edge.addClass('animated-edge');
        }
      }
    }
  }, [selectedNode, selectedEdge, hoverData]);

  // RequestAnimationFrame driving dashed line animation for .animated-edge
  useEffect(() => {
    let offset = 0;
    let animationFrame;

    const animateFlow = () => {
      offset = (offset - 0.5) % 100;
      if (cyRef.current) {
        cyRef.current.edges('.animated-edge').style('line-dash-offset', offset);
      }
      animationFrame = requestAnimationFrame(animateFlow);
    };
    
    animationFrame = requestAnimationFrame(animateFlow);
    return () => cancelAnimationFrame(animationFrame);
  }, []);

  if (dataLoading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '80vh', gap: '0.75rem', color: 'var(--text-muted)' }}>
      <Loader size={20} style={{ animation: 'spin 1s linear infinite' }} />
      Loading network topology…
    </div>
  );
  if (dataError) return (
    <div style={{ padding: '2rem', color: 'var(--critical)' }}>
      <AlertTriangle size={20} style={{ marginRight: 8, verticalAlign: 'middle' }} />
      Failed to load topology data: {dataError}
    </div>
  );

  return (
    <div className="flex flex-col h-full overflow-hidden bg-slate-950">
      
      {/* 1. Mini overview / situational awareness Top Strip */}
      <TopologyTopStats metrics={metrics} />

      <div className="flex flex-1 overflow-hidden">
        
        {/* 2. Left Panel: Filters & Layers */}
        <TopologyFilters 
          filters={filters} 
          setFilters={setFilters} 
          searchTerm={searchTerm} 
          setSearchTerm={setSearchTerm} 
        />

        {/* 3. Center Hero Section: Graph */}
        <div className="flex-1 relative bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-slate-900 to-slate-950">
          <CytoscapeComponent
            elements={elements}
            stylesheet={stylesheet}
            layout={{
              name: 'dagre',
              rankDir: 'TB',
              animate: true, 
              padding: 80, 
              nodeSep: 60,
              rankSep: 120,
              fit: true
            }}
            style={{ width: '100%', height: '100%' }}
            cy={cy => {
              cyRef.current = cy;
              cy.removeAllListeners();
              cy.on('tap', handleTap);
              cy.on('mouseover', handleMouseOver);
              cy.on('mouseout', handleMouseOut);
            }}
          />

          {/* Floating Graph Controls */}
          <TopologyControls cyRef={cyRef} toggleExpandRules={() => setIsExpanded(!isExpanded)} isExpanded={isExpanded} />

          {/* Render Contextual Hover Tooltips */}
          {hoverData && (
            <div style={{
              position: 'fixed', left: hoverData.pos.x, top: hoverData.pos.y,
              transform: 'translate(-50%, -100%)', zIndex: 50, pointerEvents: 'none'
            }} className="bg-slate-900/95 backdrop-blur border border-slate-700 shadow-2xl rounded-lg p-3 min-w-[200px]">
              {hoverData.type === 'node' && (
                <>
                  <div className="font-bold text-sm text-slate-100 mb-1">{hoverData.data.label ? hoverData.data.label.split('\n')[0] : hoverData.data.id}</div>
                  <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-xs mt-2">
                    <span className="text-slate-500">IP:</span><span className="text-slate-300 font-mono">{hoverData.data.ip}</span>
                    <span className="text-slate-500">Risk:</span><span className="font-bold" style={{color: getNodeColor(hoverData.data.riskScore)}}>{hoverData.data.riskScore}</span>
                  </div>
                </>
              )}
              {hoverData.type === 'edge' && (
                <>
                  <div className="font-bold text-sm text-slate-100 mb-1 leading-tight">
                    {hoverData.data.sourceLabel} → {hoverData.data.destLabel}
                  </div>
                  <div className="text-xs text-slate-400 mb-2">via {hoverData.data.firewallName}</div>
                  <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-xs">
                    <span className="text-slate-500">Total Policies:</span><span className="text-slate-300 font-bold">{hoverData.data.policies?.length}</span>
                    <span className="text-slate-500">Max Risk:</span><span className="font-bold" style={{color: getNodeColor(hoverData.data.maxRisk)}}>{hoverData.data.maxRisk}</span>
                    <span className="text-slate-500">Conflicts:</span><span className={hoverData.data.hasConflict ? 'text-amber-400 font-bold' : 'text-slate-300'}>{hoverData.data.hasConflict ? 'Detected' : 'None'}</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        {/* 4. Right Panel: Intelligence Details */}
        <TopologyInfoPanel 
          selectedNode={selectedNode} 
          selectedEdge={selectedEdge} 
          onClose={() => { setSelectedNode(null); setSelectedEdge(null); }} 
        />
      </div>
    </div>
  );
}
