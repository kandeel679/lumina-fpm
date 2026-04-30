"""Tests for llm_client — JSON extraction, retry logic, schema validation."""
import json
import pytest
from unittest.mock import patch, MagicMock
from pydantic import BaseModel

from services.lumina_threat_intel.llm_client import _extract_json, call_llm_structured
from services.lumina_threat_intel.exceptions import LLMValidationError, LLMProviderError
from services.lumina_threat_intel.schemas import QueryGenerationOutput, CategoryRefinementOutput


class TestExtractJson:
    def test_plain_json_unchanged(self):
        raw = '{"queries": []}'
        assert _extract_json(raw) == '{"queries": []}'

    def test_strips_json_fence(self):
        raw = '```json\n{"queries": []}\n```'
        result = _extract_json(raw)
        assert result.strip() == '{"queries": []}'

    def test_strips_plain_fence(self):
        raw = '```\n{"queries": []}\n```'
        result = _extract_json(raw)
        assert result.strip() == '{"queries": []}'

    def test_strips_whitespace(self):
        raw = '  \n  {"key": "value"}  \n  '
        assert _extract_json(raw).strip() == '{"key": "value"}'


class TestCallLlmStructured:
    VALID_QUERY_OUTPUT = json.dumps({
        "queries": [
            {"query": "Palo Alto PA-3220 exploit", "category": "exploit"}
        ]
    })

    INVALID_JSON = "not json at all"

    # queries is present but category is not a valid ThreatCategory enum value
    WRONG_SCHEMA = json.dumps({"queries": [{"query": "test", "category": "not_a_real_category"}]})

    def _patch_raw(self, return_value: str):
        return patch(
            "services.lumina_threat_intel.llm_client._call_llm_raw",
            return_value=return_value,
        )

    def test_valid_output_returns_model(self):
        with self._patch_raw(self.VALID_QUERY_OUTPUT):
            result = call_llm_structured("prompt", QueryGenerationOutput)
        assert isinstance(result, QueryGenerationOutput)
        assert len(result.queries) == 1
        assert result.queries[0].query == "Palo Alto PA-3220 exploit"

    def test_invalid_json_raises_after_retries(self):
        with self._patch_raw(self.INVALID_JSON):
            with pytest.raises(LLMValidationError):
                call_llm_structured("prompt", QueryGenerationOutput, max_retries=2)

    def test_wrong_schema_raises_after_retries(self):
        with self._patch_raw(self.WRONG_SCHEMA):
            with pytest.raises(LLMValidationError):
                call_llm_structured("prompt", QueryGenerationOutput, max_retries=2)

    def test_provider_error_propagates(self):
        with patch(
            "services.lumina_threat_intel.llm_client._call_llm_raw",
            side_effect=Exception("API key invalid"),
        ):
            with pytest.raises(LLMProviderError):
                call_llm_structured("prompt", QueryGenerationOutput)

    def test_succeeds_on_second_attempt(self):
        call_count = {"n": 0}

        def flaky(_prompt):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return "bad json"
            return self.VALID_QUERY_OUTPUT

        with patch("services.lumina_threat_intel.llm_client._call_llm_raw", side_effect=flaky):
            result = call_llm_structured("prompt", QueryGenerationOutput, max_retries=3)
        assert call_count["n"] == 2
        assert isinstance(result, QueryGenerationOutput)


class TestCategoryRefinementSchema:
    def test_empty_findings_valid(self):
        raw = json.dumps({"category": "exploit", "findings": []})
        data = json.loads(raw)
        result = CategoryRefinementOutput.model_validate(data)
        assert result.findings == []

    def test_finding_with_ioc_valid(self):
        raw = {
            "category": "exploit",
            "findings": [{
                "category": "exploit",
                "severity": "high",
                "confidence": 75,
                "title": "CVE-2024-3400 PoC",
                "description": "Remote code execution PoC circulating",
                "iocs": [{"type": "cve", "value": "CVE-2024-3400"}],
                "source": {
                    "onion_url": None,
                    "search_engine": "Ahmia",
                    "scraped_at": None,
                    "raw_excerpt": "CVE-2024-3400 PoC available on exploit.in",
                    "page_title": None,
                    "marketplace_or_forum": "exploit.in",
                },
                "recommended_actions": ["Patch PAN-OS immediately"],
                "tags": ["pan-os", "rce"],
            }]
        }
        result = CategoryRefinementOutput.model_validate(raw)
        assert result.findings[0].confidence == 75
        assert result.findings[0].iocs[0].value == "CVE-2024-3400"

    def test_invalid_severity_rejected(self):
        from pydantic import ValidationError
        raw = {
            "category": "exploit",
            "findings": [{
                "category": "exploit",
                "severity": "extreme",  # not a valid enum value
                "confidence": 50,
                "title": "Test",
                "description": "desc",
                "iocs": [],
                "source": {"raw_excerpt": "test"},
                "recommended_actions": [],
                "tags": [],
            }]
        }
        with pytest.raises(ValidationError):
            CategoryRefinementOutput.model_validate(raw)

    def test_confidence_out_of_range_rejected(self):
        from pydantic import ValidationError
        raw = {
            "category": "exploit",
            "findings": [{
                "category": "exploit",
                "severity": "high",
                "confidence": 150,  # > 100
                "title": "Test",
                "description": "desc",
                "iocs": [],
                "source": {"raw_excerpt": "test"},
                "recommended_actions": [],
                "tags": [],
            }]
        }
        with pytest.raises(ValidationError):
            CategoryRefinementOutput.model_validate(raw)
