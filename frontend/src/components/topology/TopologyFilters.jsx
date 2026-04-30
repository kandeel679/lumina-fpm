import { Filter, Search, Globe, Shield, Server as ServerIcon } from 'lucide-react';

export default function TopologyFilters({ filters, setFilters, searchTerm, setSearchTerm }) {
  
  const handleFeatureToggle = (feature) => {
    setFilters(prev => ({...prev, [feature]: !prev[feature]}));
  };

  return (
    <div className="w-64 shrink-0 bg-slate-950/60 backdrop-blur-2xl border-r border-slate-800/80 flex flex-col overflow-y-auto z-10 shadow-[4px_0_24px_rgba(0,0,0,0.2)]">
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-slate-400" />
          <h3 className="font-semibold text-slate-200 text-[11px] tracking-[0.15em] uppercase">Filters & Layers</h3>
        </div>
      </div>
      
      <div className="p-5 flex flex-col gap-6">
        
        {/* Search */}
        <div>
          <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 block">Search Assets</label>
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
            <input 
              type="text" 
              placeholder="IP, Name, Vendor..." 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md py-2 pl-9 pr-3 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>
        </div>

        {/* Visibility Toggles */}
        <div>
          <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 block">Visibility Layers</label>
          <div className="flex flex-col gap-2">
            {[
              { id: 'showVendors', label: 'Vendor Grouping' },
              { id: 'showLabels', label: 'Node Labels' },
              { id: 'riskOnly', label: 'Risk & Threats Only' }
            ].map(ft => (
              <label key={ft.id} className="flex items-center gap-2 cursor-pointer group">
                <div className={`w-4 h-4 rounded flex items-center justify-center border transition-colors ${filters[ft.id] ? 'bg-indigo-600 border-indigo-600' : 'bg-slate-950 border-slate-700 group-hover:border-slate-500'}`}>
                  {filters[ft.id] && <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" /></svg>}
                </div>
                <span className="text-sm text-slate-300 group-hover:text-slate-100 transition-colors">{ft.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="h-px bg-slate-800 w-full"></div>

        {/* Static Legends within Filter Panel to clean up the graph */}
        <div>
           <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 block">Node Types</label>
           <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Globe size={15} className="text-slate-400" /> Internet
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <Shield size={15} className="text-slate-400" /> Firewall
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <ServerIcon size={15} className="text-slate-400" /> Server / Zone
              </div>
           </div>
        </div>

        <div>
           <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 block">Risk & Threat Colors</label>
           <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]"></div> Malicious (&gt;80)
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <div className="w-2.5 h-2.5 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.5)]"></div> Suspicious (40-79)
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-300">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div> Normal (&lt;40)
              </div>
           </div>
        </div>

      </div>
    </div>
  );
}
