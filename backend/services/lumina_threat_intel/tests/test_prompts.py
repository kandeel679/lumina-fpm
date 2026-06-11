"""Tests for prompt construction and anti-hallucination validator."""
import pytest
from services.lumina_threat_intel.prompts.query_generator import QUERY_GENERATOR_PROMPT
from services.lumina_threat_intel.prompts.refiners import build_refiner_prompt, CATEGORY_GUIDANCE_MAP
from services.lumina_threat_intel.prompts.shared import SHARED_PREAMBLE
from services.lumina_threat_intel.orchestrator import _validate_iocs_in_source


class TestSharedPreamble:
    def test_contains_prompt_injection_rule(self):
        assert "UNTRUSTED_SCRAPED_DATA" in SHARED_PREAMBLE
        assert "ignore" in SHARED_PREAMBLE.lower()

    def test_contains_no_invent_rule(self):
        assert "NEVER invent" in SHARED_PREAMBLE

    def test_json_only_rule(self):
        assert "valid JSON" in SHARED_PREAMBLE


class TestQueryGeneratorPrompt:
    def test_no_corpus_rules_in_query_prompt(self):
        # Query generation has no scraped corpus; the data-handling rules
        # (IOC grounding / injection resistance) must NOT be included.
        prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json="{}")
        assert "UNTRUSTED_SCRAPED_DATA" not in prompt

    def test_query_cap_present(self):
        prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json="{}")
        assert "AT MOST 12" in prompt

    def test_interpolates_keywords(self):
        kw_json = '{"firmwares": ["PAN-OS 10.2.3"], "vendors_models": [], "cves": [], "org_domains": []}'
        prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json=kw_json)
        assert "PAN-OS 10.2.3" in prompt

    def test_lists_all_five_categories(self):
        prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json="{}")
        for cat in ("exploit", "credential", "c2", "ransomware", "iab"):
            assert cat in prompt

    def test_output_schema_present(self):
        prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json="{}")
        assert '"queries"' in prompt


class TestRefinerPromptBuilder:
    def test_all_categories_have_guidance(self):
        for cat in ("exploit", "credential", "c2", "ransomware", "iab"):
            assert cat in CATEGORY_GUIDANCE_MAP

    def test_category_injected_in_prompt(self):
        prompt = build_refiner_prompt("exploit", "{}", "scraped text here")
        assert "exploit" in prompt

    def test_scraped_text_wrapped_in_untrusted_tag(self):
        prompt = build_refiner_prompt("c2", "{}", "malicious content")
        assert "<UNTRUSTED_SCRAPED_DATA>" in prompt
        assert "malicious content" in prompt

    def test_keywords_injected(self):
        kw = '{"firmwares": ["FortiOS 7.4.1"]}'
        prompt = build_refiner_prompt("ransomware", kw, "some text")
        assert "FortiOS 7.4.1" in prompt

    def test_credential_guidance_no_plaintext_passwords(self):
        assert "NOT include actual passwords" in CATEGORY_GUIDANCE_MAP["credential"]

    def test_iab_guidance_mentions_severity_tiers(self):
        assert "critical" in CATEGORY_GUIDANCE_MAP["iab"].lower()
        assert "high" in CATEGORY_GUIDANCE_MAP["iab"].lower()


class TestFindingsPrompt:
    def test_findings_prompt_renders_with_all_blocks(self):
        from services.lumina_threat_intel.prompts.findings import build_findings_prompt
        prompt = build_findings_prompt('{"firmwares": ["FortiOS 7.4.3"]}',
                                       ["exploit"], "corpus text")
        assert "FortiOS 7.4.3" in prompt
        assert "<UNTRUSTED_SCRAPED_DATA>" in prompt
        # coverage_note must be demanded on every scan, not only when clean
        assert "ALWAYS REQUIRED" in prompt
        # confidence rubric is inlined (no dangling reference)
        assert "Start at 50" in prompt
        # urgency-prefixed action format
        assert "[IMMEDIATE|24H|SCHEDULED]" in prompt
        # structured admin narrative
        assert "BOTTOM LINE" in prompt and "PRIORITISED NEXT STEPS" in prompt


class TestExternalContextInPrompt:
    def test_parallel_channel_summary_injected(self):
        from services.lumina_threat_intel.prompts.findings import build_findings_prompt
        prompt = build_findings_prompt(
            "{}", ["exploit"], "corpus",
            external_context="- Clearnet: 58 findings, 43 at medium+ relevance.")
        assert "PARALLEL CHANNELS" in prompt
        assert "43 at medium+ relevance" in prompt
        # bottom line must speak for the whole report
        assert "WHOLE report" in prompt

    def test_defaults_to_none_marker(self):
        from services.lumina_threat_intel.prompts.findings import build_findings_prompt
        assert "(none)" in build_findings_prompt("{}", ["exploit"], "corpus")


class TestClearnetHelpers:
    def test_psirt_urgency_mapping(self):
        from services.lumina_threat_intel.clearnet_intel import _psirt_urgency
        assert _psirt_urgency("critical") == "IMMEDIATE"
        assert _psirt_urgency("high") == "24H"
        assert _psirt_urgency("medium") == "SCHEDULED"


class TestKeywordExtractorHelpers:
    def test_ip_regex_and_private_prefixes(self):
        from services.lumina_threat_intel.keyword_extractor import _IP_RE, _PRIVATE_PREFIXES
        assert _IP_RE.match("203.0.113.50")
        assert _IP_RE.match("203.0.113.0/24")
        assert not _IP_RE.match("novatech.com")
        assert "172.16." in _PRIVATE_PREFIXES and "172.31." in _PRIVATE_PREFIXES

    def test_cve_regex(self):
        from services.lumina_threat_intel.keyword_extractor import _CVE_RE
        found = _CVE_RE.findall("see cve-2024-3400 and CVE-2025-0136; not CVE-12")
        assert sorted(c.upper() for c in found) == ["CVE-2024-3400", "CVE-2025-0136"]


class TestDarkwebAggregators:
    def test_victim_to_finding_shape(self):
        from services.lumina_threat_intel.darkweb_aggregators import _victim_to_finding
        f = _victim_to_finding(
            {"victim": "NovaTech Inc", "group": "akira",
             "discovered": "2026-06-01", "post_url": "http://x.onion/post"},
            "novatech.com",
        )
        assert f["category"] == "ransomware"
        assert f["relevance_band"] == "high" and f["relevance_score"] == 95
        assert f["iocs"] == [{"type": "domain", "value": "novatech.com"}]
        assert f["source"]["onion_url"] == "http://x.onion/post"
        assert all(a.startswith("[IMMEDIATE]") for a in f["recommended_actions"])
        assert "dark-web" in f["tags"] and "akira" in f["tags"]

    def test_unconfirmed_victim_is_possible_match(self):
        from services.lumina_threat_intel.darkweb_aggregators import _victim_to_finding
        f = _victim_to_finding(
            {"victim": "Novatech EngineeringConsultants", "group": "akira"},
            "novatech.com", confirmed=False,
        )
        assert f["relevance_band"] == "medium" and f["relevance_score"] == 50
        assert "POSSIBLE match" in f["relevance_reason"]
        assert "possible-match" in f["tags"]
        assert all(a.startswith("[24H]") for a in f["recommended_actions"])


class TestValidateIocsInSource:
    """Tests for the post-LLM anti-hallucination IOC validator."""

    def _finding(self, excerpt: str, iocs: list) -> dict:
        return {
            "source": {"raw_excerpt": excerpt},
            "iocs": iocs,
        }

    def test_ioc_present_in_excerpt_kept(self):
        finding = self._finding(
            excerpt="CVE-2024-3400 exploit available",
            iocs=[{"type": "cve", "value": "CVE-2024-3400"}],
        )
        result = _validate_iocs_in_source([finding])
        assert len(result[0]["iocs"]) == 1

    def test_ioc_absent_from_excerpt_dropped(self):
        finding = self._finding(
            excerpt="some random dark web post",
            iocs=[{"type": "ipv4", "value": "1.2.3.4"}],  # not in excerpt
        )
        result = _validate_iocs_in_source([finding])
        assert result[0]["iocs"] == []

    def test_case_insensitive_match(self):
        finding = self._finding(
            excerpt="cve-2024-3400 is being exploited",
            iocs=[{"type": "cve", "value": "CVE-2024-3400"}],
        )
        result = _validate_iocs_in_source([finding])
        assert len(result[0]["iocs"]) == 1

    def test_empty_excerpt_skips_validation(self):
        finding = self._finding(
            excerpt="",
            iocs=[{"type": "ipv4", "value": "1.2.3.4"}],
        )
        result = _validate_iocs_in_source([finding])
        # Empty excerpt — no validation possible, IOC is kept as-is
        assert len(result[0]["iocs"]) == 1

    def test_mixed_iocs_partial_drop(self):
        finding = self._finding(
            excerpt="domain evil.com found in traffic",
            iocs=[
                {"type": "domain", "value": "evil.com"},   # present
                {"type": "ipv4", "value": "9.9.9.9"},      # absent
            ],
        )
        result = _validate_iocs_in_source([finding])
        assert len(result[0]["iocs"]) == 1
        assert result[0]["iocs"][0]["value"] == "evil.com"
