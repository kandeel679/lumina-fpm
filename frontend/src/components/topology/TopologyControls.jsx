import { ZoomIn, ZoomOut, Maximize, RotateCcw, Eye, Settings, Waypoints } from 'lucide-react';

export default function TopologyControls({ cyRef, toggleExpandRules, isExpanded }) {
  
  const handleZoom = (direction) => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    const currentZoom = cy.zoom();
    cy.zoom(direction === 'in' ? currentZoom * 1.2 : currentZoom / 1.2);
  };

  const handleFit = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(null, 50);
  };

  const handleReset = () => {
    if (!cyRef.current) return;
    cyRef.current.fit(null, 50);
    // cyRef.current.layout({ name: 'cose-bilkent' }).run();
  };

  return (
    <div className="absolute bottom-4 right-4 bg-slate-900/90 border border-slate-700 backdrop-blur-md rounded-lg p-1.5 flex gap-1 shadow-xl">
      <button className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white" onClick={() => handleZoom('in')} title="Zoom In">
        <ZoomIn size={16} />
      </button>
      <button className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white" onClick={() => handleZoom('out')} title="Zoom Out">
        <ZoomOut size={16} />
      </button>
      <button className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white" onClick={handleFit} title="Fit to Screen">
        <Maximize size={16} />
      </button>
      <div className="w-px bg-slate-700 mx-1 my-1"></div>
      <button className="p-1.5 hover:bg-slate-800 rounded text-slate-300 hover:text-white" onClick={handleReset} title="Reset View">
        <RotateCcw size={16} />
      </button>
      <div className="w-px bg-slate-700 mx-1 my-1"></div>
      <button 
        className={`p-1.5 rounded flex items-center gap-1.5 text-xs font-semibold ${isExpanded ? 'bg-indigo-600 text-white' : 'hover:bg-slate-800 text-slate-300 hover:text-white'}`}
        onClick={toggleExpandRules}
        title="Toggle between Grouped Unified Edges and Separate Rule Edges"
      >
        <Waypoints size={16} />
        {isExpanded ? 'Group Edges' : 'Expand Rules'}
      </button>
    </div>
  );
}
