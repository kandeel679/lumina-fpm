import React from "react";
import { CtiCenter } from "./cti";

/* ─────────────────────────────────────────────────────────────────
 * Threat Intelligence — the two-axis Threat Center.
 *
 * The legacy dark-web/Tor scan wrapper (latest-scan / advisories tabs, KEV +
 * "dark web" KPIs, "run threat scan") was retired together with the dark-web
 * engine — its endpoints (/api/v1/threat-intel/*) are gated off by default and
 * the page rendered dead zeros. This page now renders the live two-axis Threat
 * Center directly:
 *   • rule axis  — CTI indicators correlated to permitting allow rules
 *   • device axis — firmware CVEs matched to each device's installed firmware
 * CtiCenter is self-contained (owns its own data load), so this is a thin shell
 * that just provides the page-head chrome.
 * ───────────────────────────────────────────────────────────────── */
export function ThreatIntelligence() {
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-sub">
            Two axes · rule exposure (indicators on allow rules) + device firmware CVEs
          </p>
        </div>
      </div>
      <CtiCenter />
    </div>
  );
}
