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
