/* ─────────────────────────────────────────────────────────────────
 * Lumina FPM · consolidated data schema & helpers
 * ───────────────────────────────────────────────────────────────── */

export const LFPM = {};
window.LFPM = LFPM;

LFPM.vendors = [];
LFPM.firewalls = [];
LFPM.policies = [];
LFPM.conflicts = [];
LFPM.threats = [];
LFPM.firmwareTimeline = [];
LFPM.zones = [];
LFPM.assets = [];
LFPM.externalNodes = [];
LFPM.activityFeed = [];
LFPM.hits24h = [];
LFPM.users = [];
LFPM.savedSearches = [];

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
    if (!iso) return '';
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400)return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  },
};
