import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { fetchLFPMData } from '../api';
import { LFPM as mockLFPM } from '../data';

const LFPMContext = createContext();

export function useLFPM() {
  const context = useContext(LFPMContext);
  if (!context) {
    throw new Error('useLFPM must be used within an LFPMProvider');
  }
  return context;
}

export function LFPMProvider({ children }) {
  const [data, setData] = useState({
    vendors: mockLFPM.vendors || [],
    firewalls: mockLFPM.firewalls || [],
    policies: mockLFPM.policies || [],
    conflicts: mockLFPM.conflicts || [],
    threats: mockLFPM.threats || [],
    firmwareTimeline: mockLFPM.firmwareTimeline || [],
    zones: mockLFPM.zones || [],
    assets: mockLFPM.assets || [],
    externalNodes: mockLFPM.externalNodes || [],
    activityFeed: mockLFPM.activityFeed || [],
    hits24h: mockLFPM.hits24h || [],
    users: mockLFPM.users || [],
    savedSearches: mockLFPM.savedSearches || [],
    meta: {
      lastScanAt: null,
      lastScanStatus: null,
      totalScans: 0,
      totalFindings: 0,
      newFindingsLastScan: 0,
      criticalFindings: 0,
      highFindings: 0,
      correlatedRules: 0,
      usingMockThreats: true
    },
    fmt: mockLFPM.fmt || {}
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refreshData = useCallback(async () => {
    try {
      setLoading(true);
      const fetchedData = await fetchLFPMData();
      setData(fetchedData);
      setError(null);
    } catch (err) {
      console.error('Failed to load data, using fallback data.', err);
      // Fallback already in initial state, but we could handle it here too
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  return (
    <LFPMContext.Provider value={{ data, loading, error, refreshData }}>
      {children}
    </LFPMContext.Provider>
  );
}
