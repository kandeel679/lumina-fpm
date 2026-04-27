import { ShieldAlert, Activity, GitCommit, Search, Shield, Zap } from 'lucide-react';

export default function TopologyTopStats({ metrics }) {
  return (
    <div className="flex bg-slate-900 border-b border-slate-800 p-2 text-xs font-semibold items-center gap-6 justify-around overflow-hidden shadow-sm">
      <div className="flex items-center gap-2 text-slate-300">
        <Activity size={14} className="text-blue-400" />
        Total Nodes: <span className="text-slate-100">{metrics.totalNodes}</span>
      </div>
      <div className="flex items-center gap-2 text-slate-300">
        <GitCommit size={14} className="text-slate-400" />
        Connections: <span className="text-slate-100">{metrics.totalEdges}</span>
      </div>
      <div className="flex items-center gap-2 text-slate-300">
        <ShieldAlert size={14} className="text-red-400" />
        Malicious Assets: <span className="text-red-400">{metrics.maliciousNodes}</span>
      </div>
      <div className="flex items-center gap-2 text-slate-300">
        <Zap size={14} className="text-orange-400" />
        Conflict Paths: <span className="text-orange-400">{metrics.conflictEdges}</span>
      </div>
      <div className="flex items-center gap-2 text-slate-300">
        <Search size={14} className="text-emerald-400" />
        Clean Assets: <span className="text-emerald-400">{metrics.cleanNodes}</span>
      </div>
    </div>
  );
}
