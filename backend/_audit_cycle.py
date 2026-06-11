"""Post-scan audit: dump everything needed to judge the full cycle."""
import json
import os

from sqlalchemy import create_engine, text

eng = create_engine(os.environ["DATABASE_URL"])
with eng.connect() as c:
    r = c.execute(text(
        "SELECT id, status, scan_duration_seconds, queries_generated_count, "
        "onion_pages_scraped_count, clean, narrative_summary, coverage_note, "
        "llm_model_name, input_keywords, error_log "
        "FROM threat_intel_reports ORDER BY id DESC LIMIT 1")).fetchone()
    rid = r[0]
    print("REPORT", rid, "| status:", r[1], "| duration:", r[2], "s | queries:", r[3],
          "| onion pages:", r[4], "| clean:", r[5], "| model:", r[8])
    print("\n=== INPUT KEYWORDS (what extraction saw) ===")
    print(json.dumps(r[9], indent=1) if r[9] else None)
    print("\n=== ERROR LOG ===")
    print(json.dumps(r[10], indent=1) if r[10] else "none")
    print("\n=== COVERAGE NOTE ===")
    print(r[7])
    print("\n=== NARRATIVE ===")
    print(r[6])

    print("\n=== FINDINGS BY SOURCE / BAND ===")
    for row in c.execute(text(
            "SELECT source_page_title, relevance_band, count(*), "
            "count(*) FILTER (WHERE matched_rule_ids::text <> '[]' "
            "  OR matched_device_ids::text <> '[]') AS correlated "
            "FROM threat_intel_findings WHERE report_id=:i "
            "GROUP BY 1,2 ORDER BY 1,2"), {"i": rid}):
        print(f"  {row[0] or 'dark-web'} | {row[1]} | n={row[2]} | correlated={row[3]}")

    print("\n=== LEAK-SITE FINDINGS (ransomware.live) ===")
    for row in c.execute(text(
            "SELECT title, relevance_band, relevance_score, relevance_reason, "
            "recommended_actions, tags FROM threat_intel_findings "
            "WHERE report_id=:i AND source_page_title='Ransomware.live'"), {"i": rid}):
        print(" ", row[0])
        print("   band:", row[1], row[2], "|", row[3][:160])
        print("   actions:", row[4])
        print("   tags:", row[5])

    print("\n=== TOP CORRELATED FINDINGS (high band) ===")
    for row in c.execute(text(
            "SELECT title, source_page_title, relevance_score, "
            "correlation_match_reason, recommended_actions "
            "FROM threat_intel_findings WHERE report_id=:i AND relevance_band='high' "
            "ORDER BY relevance_score DESC LIMIT 5"), {"i": rid}):
        print(" ", row[0][:90], "|", row[1], "| score", row[2])
        print("   why:", (row[3] or "")[:200])
        print("   actions:", row[4])

    print("\n=== ACTION FORMAT COMPLIANCE ===")
    total = bad = 0
    for (acts,) in c.execute(text(
            "SELECT recommended_actions FROM threat_intel_findings "
            "WHERE report_id=:i AND recommended_actions IS NOT NULL"), {"i": rid}):
        for a in acts or []:
            total += 1
            if not (a.startswith("[IMMEDIATE]") or a.startswith("[24H]")
                    or a.startswith("[SCHEDULED]")):
                bad += 1
                print("   non-compliant:", a[:120])
    print(f"  {total - bad}/{total} actions follow the urgency-prefix format")

    print("\n=== EPSS TAG COVERAGE ===")
    row = c.execute(text(
        "SELECT count(*) FILTER (WHERE tags::text LIKE '%epss:%'), "
        "count(*) FILTER (WHERE tags::text LIKE '%likely-exploited%'), count(*) "
        "FROM threat_intel_findings WHERE report_id=:i "
        "AND source_page_title IN ('CISA KEV','NVD')"), {"i": rid}).fetchone()
    print(f"  epss-tagged: {row[0]} | likely-exploited: {row[1]} | clearnet total: {row[2]}")
