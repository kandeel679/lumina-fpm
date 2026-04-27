import { X, Activity, Server, Shield, Network, AlertTriangle, Bug } from 'lucide-react';
import { Badge } from '../ui/Badge';
import { policies } from '../../data/mockPolicies';
import { threats } from '../../data/mockThreats';

function getNodeColor(score) {
  if (score >= 80) return 'var(--critical)'; 
  if (score >= 40) return 'var(--high)';
  return 'var(--safe)';
}

export default function TopologyInfoPanel({ selectedNode, selectedEdge, onClose }) {
  if (!selectedNode && !selectedEdge) return null;

  return (
    <div className="w-80 shrink-0 bg-slate-950/80 backdrop-blur-3xl border-l border-slate-800/80 flex flex-col overflow-y-auto z-20 transition-all shadow-[-8px_0_32px_rgba(0,0,0,0.3)]">
      {/* Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between sticky top-0 bg-transparent z-10">
        <div className="flex items-center gap-2">
          {selectedNode ? <Activity size={16} className="text-indigo-400" /> : <Network size={16} className="text-cyan-400" />}
          <h3 className="font-semibold text-slate-100 text-sm uppercase tracking-wider">
            {selectedNode ? 'Asset Intelligence' : 'Connection Intelligence'}
          </h3>
        </div>
        <button className="text-slate-400 hover:text-white transition-colors" onClick={onClose}>
          <X size={18} />
        </button>
      </div>

      <div className="p-4 flex flex-col gap-6">
        {selectedNode && <NodeDetails node={selectedNode} />}
        {selectedEdge && <EdgeDetails edge={selectedEdge} />}
      </div>
    </div>
  );
}

function NodeDetails({ node }) {
  // If it's a zone/server, show its connection to the firewall.
  // We can derive risk and policy counts. Note: some logic is handled in Topology state to pass `sidePanelFw` but we'll re-calculate or receive it securely here.
  const isServer = node.type === 'server';
  const isFirewall = node.type === 'firewall';
  
  return (
    <div className="flex flex-col gap-5">
      <div>
        <div className="flex items-center gap-2 mb-1">
           {isFirewall ? <Shield size={16} className="text-slate-400"/> : isServer ? <Server size={16} className="text-slate-400"/> : null}
           <h2 className="text-lg font-bold text-slate-100 leading-tight">
             {node.label ? node.label.split('\n')[0] : node.id}
           </h2>
        </div>
        {node.label && node.label.includes('\n') && (
           <p className="font-mono text-xs text-slate-500 mt-1">{node.label.split('\n')[1]}</p>
        )}
      </div>

      <div className="bg-slate-950 rounded-lg p-3 border border-slate-800">
        <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Asset Identity</div>
        <div className="grid grid-cols-2 gap-y-3 gap-x-2 text-sm">
          <div>
            <span className="block text-[10px] uppercase text-slate-500 mb-0.5">IP Address</span>
            <span className="font-mono text-slate-200">{node.ip || 'N/A'}</span>
          </div>
          <div>
            <span className="block text-[10px] uppercase text-slate-500 mb-0.5">Vendor</span>
            <span className="text-slate-200">{node.vendor || 'N/A'}</span>
          </div>
          {node.riskScore !== undefined && (
            <div>
              <span className="block text-[10px] uppercase text-slate-500 mb-0.5">Max Risk</span>
              <span className="font-bold" style={{ color: getNodeColor(node.riskScore) }}>{node.riskScore}</span>
            </div>
          )}
          {node.zoneName && (
             <div>
              <span className="block text-[10px] uppercase text-slate-500 mb-0.5">Network Zone</span>
              <span className="text-slate-200">{node.zoneName}</span>
            </div>
          )}
        </div>
      </div>

      {node.threats && node.threats.length > 0 && (
         <div>
           <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5"><Bug size={14}/> Identifed Threats</div>
           <div className="flex flex-col gap-2">
             {node.threats.map(t => (
               <div key={t.id} className="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col gap-1.5">
                  <div className="flex justify-between items-center">
                    <span className="font-bold text-sm text-slate-200">{t.id}</span>
                    <Badge label={t.severity} />
                  </div>
                  <span className="text-xs text-slate-400 font-mono">CVSS: {t.cvss}</span>
               </div>
             ))}
           </div>
         </div>
      )}
    </div>
  );
}

function EdgeDetails({ edge }) {
  // Edge represents policies.
  const policiesList = edge.policies || [];
  
  if (policiesList.length === 0) {
    return <div className="text-sm text-slate-400">Structural connection only. No explicit policy rules mapped.</div>;
  }

  const worstRisk = Math.max(...policiesList.map(p => p.riskScore), 0);
  const anomaliesCount = policiesList.filter(p => ['Shadowed', 'Redundant', 'Overly Permissive'].includes(p.status)).length;

  return (
    <div className="flex flex-col gap-6">
      
      <div>
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
          {edge.sourceLabel.split('\n')[0]} <span className="text-slate-500">→</span> {edge.destLabel.split('\n')[0]}
        </h2>
        <div className="text-xs text-slate-400 mt-1">Routed via: <span className="font-semibold text-slate-300">{edge.firewallName}</span></div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-950 rounded p-3 border border-slate-800 flex flex-col items-center justify-center">
          <span className="text-[10px] uppercase font-semibold text-slate-500">Total Rules</span>
          <span className="text-xl font-bold text-slate-100">{policiesList.length}</span>
        </div>
        <div className={"bg-slate-950 rounded p-3 border flex flex-col items-center justify-center " + (anomaliesCount > 0 ? "border-orange-500/50" : "border-emerald-500/50")}>
          <span className="text-[10px] uppercase font-semibold text-slate-500">Anomalies</span>
          <span className={`text-xl font-bold ${anomaliesCount > 0 ? 'text-orange-400' : 'text-emerald-400'}`}>{anomaliesCount}</span>
        </div>
      </div>

      <div>
        <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Enforcing Policies</div>
        <div className="flex flex-col gap-3">
          {policiesList.sort((a,b) => b.riskScore - a.riskScore).map(pol => (
            <div key={pol.id} className="bg-slate-950 border border-slate-800 rounded p-3 transition-colors hover:border-slate-700">
               <div className="flex justify-between items-start mb-2">
                 <span className="font-semibold text-sm text-slate-200">{pol.ruleName}</span>
                 <Badge label={pol.status} />
               </div>
               
               <div className="grid grid-cols-2 gap-y-2 text-xs">
                 <div><span className="text-slate-500">Action:</span> <span className={pol.action === 'ALLOW' ? 'text-emerald-400' : 'text-red-400'}>{pol.action}</span></div>
                 <div><span className="text-slate-500">Service:</span> <span className="font-mono text-slate-300">{pol.service}</span></div>
                 <div><span className="text-slate-500">Risk Score:</span> <span className="font-bold flex items-center gap-1" style={{ color: getNodeColor(pol.riskScore) }}>{pol.riskScore} {pol.riskScore > 60 && <AlertTriangle size={12}/>}</span></div>
               </div>
               
               {pol.status !== 'Clean' && (
                 <div className="mt-3 text-xs bg-orange-950/30 text-orange-200/80 p-2 rounded border border-orange-900/50">
                    {pol.status === 'Shadowed' && `Shadowed by: ${pol.shadowedBy || 'Unknown'}`}
                    {pol.status === 'Redundant' && `Redundant to: ${pol.shadowedBy || 'Unknown'}`}
                    {pol.status === 'Overly Permissive' && `Rule is overly broad and exposes assets unnecessarily.`}
                 </div>
               )}
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
