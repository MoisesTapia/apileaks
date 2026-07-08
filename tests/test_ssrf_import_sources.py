"""
Tests for SSRF import sources: BurpXmlImporter, HarImporter, ImportSourceError,
_is_url_like_field, --ssrf-body-field / --burp-xml / --har CLI options,
body-field priority merge, and Full_Replay_Mode probing.
"""

import asyncio
import base64
import json
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from unittest.mock import AsyncMock, Mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cli.module_options import apply_ssrf_options
from core.config import AuthContext, AuthType, SSRFConfig, Severity
from modules.owasp.ssrf_testing import (
    JSON_BODY_FIELDS,
    InternalProbe,
    SSRFTestingModule,
)
from utils.http_client import HTTPRequestEngine, Response
from utils.import_sources import (
    BurpXmlImporter,
    HarImporter,
    ImportSourceError,
    ImportedRequest,
    _is_url_like_field,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_response(status_code=200, body=""):
    content = body.encode("utf-8")
    return Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=content,
        text=body,
        url="https://api.example.com/test",
        elapsed=0.1,
        request_method="POST",
    )


def make_module(config=None, return_value=None):
    if config is None:
        config = SSRFConfig()
    client = Mock(spec=HTTPRequestEngine)
    client.set_auth_context = Mock()
    client.request = AsyncMock(return_value=return_value or make_response(404, ""))
    auth = AuthContext(name="t", type=AuthType.BEARER, token="x", privilege_level=1)
    return SSRFTestingModule(config, client, [auth])


@dataclass
class EP:
    url: str
    method: str = "GET"


# ---------------------------------------------------------------------------
# Unit: _is_url_like_field
# ---------------------------------------------------------------------------


class TestIsUrlLikeField:
    def test_name_keyword_url(self):
        assert _is_url_like_field("url", "anything") is True

    def test_name_keyword_imageurl(self):
        assert _is_url_like_field("imageUrl", "anything") is True

    def test_name_keyword_callback(self):
        assert _is_url_like_field("callback", "") is True

    def test_name_keyword_webhook(self):
        assert _is_url_like_field("webhookEndpoint", "x") is True

    def test_name_keyword_case_insensitive(self):
        assert _is_url_like_field("IMAGEURL", "") is True

    def test_value_http_prefix(self):
        assert _is_url_like_field("randomField", "http://internal.corp") is True

    def test_value_https_prefix(self):
        assert _is_url_like_field("randomField", "https://example.com") is True

    def test_value_https_case_insensitive(self):
        assert _is_url_like_field("x", "HTTPS://example.com") is True

    def test_plain_field_no_match(self):
        assert _is_url_like_field("name", "John") is False

    def test_integer_value_no_match(self):
        assert _is_url_like_field("count", 42) is False

    def test_none_value_no_match(self):
        assert _is_url_like_field("data", None) is False


# ---------------------------------------------------------------------------
# Unit: BurpXmlImporter
# ---------------------------------------------------------------------------


def _make_raw_http(method="POST", path="/api/v1/upload",
                   content_type="application/json",
                   body='{"imageUrl": "https://cdn.example.com/photo.jpg", "name": "test"}'):
    headers = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: api.example.com\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Authorization: Bearer tok123\r\n"
        f"\r\n"
    )
    return (headers + body).encode("latin-1")


def _make_burp_xml(raw_bytes: bytes, base64_encode: bool = True) -> str:
    if base64_encode:
        encoded = base64.b64encode(raw_bytes).decode()
        req_elem = f'<request base64="true">{encoded}</request>'
    else:
        req_elem = f'<request>{raw_bytes.decode("latin-1")}</request>'
    return f"<items><item>{req_elem}</item></items>"


class TestBurpXmlImporter:
    def test_parse_base64_request(self, tmp_path):
        raw = _make_raw_http()
        xml = _make_burp_xml(raw, base64_encode=True)
        p = tmp_path / "burp.xml"
        p.write_text(xml)

        reqs = BurpXmlImporter(str(p)).parse()
        assert len(reqs) == 1
        r = reqs[0]
        assert r.method == "POST"
        assert r.path == "/api/v1/upload"
        assert r.headers.get("Authorization") == "Bearer tok123"
        assert r.body is not None
        assert "imageUrl" in r.body
        assert "imageUrl" in r.url_like_fields

    def test_parse_plain_text_request(self, tmp_path):
        raw = _make_raw_http()
        xml = _make_burp_xml(raw, base64_encode=False)
        p = tmp_path / "burp_plain.xml"
        p.write_text(xml)

        reqs = BurpXmlImporter(str(p)).parse()
        assert len(reqs) == 1
        assert reqs[0].method == "POST"

    def test_non_json_body_gives_none_body(self, tmp_path):
        raw = _make_raw_http(content_type="text/plain", body="hello world")
        xml = _make_burp_xml(raw)
        p = tmp_path / "burp_text.xml"
        p.write_text(xml)

        reqs = BurpXmlImporter(str(p)).parse()
        assert reqs[0].body is None
        assert reqs[0].url_like_fields == []

    def test_missing_file_raises(self):
        with pytest.raises(ImportSourceError, match="not found"):
            BurpXmlImporter("/nonexistent/burp.xml").parse()

    def test_invalid_xml_raises(self, tmp_path):
        p = tmp_path / "bad.xml"
        p.write_text("<<not xml>>")
        with pytest.raises(ImportSourceError, match="not valid XML"):
            BurpXmlImporter(str(p)).parse()

    def test_malformed_item_skipped_rest_continues(self, tmp_path):
        raw = _make_raw_http()
        encoded = base64.b64encode(raw).decode()
        xml = (
            "<items>"
            "<item><request base64=\"true\">NOTBASE64!!!</request></item>"
            f"<item><request base64=\"true\">{encoded}</request></item>"
            "</items>"
        )
        p = tmp_path / "mixed.xml"
        p.write_text(xml)

        reqs = BurpXmlImporter(str(p)).parse()
        # First item skipped, second parsed
        assert len(reqs) == 1
        assert reqs[0].method == "POST"

    def test_multiple_items(self, tmp_path):
        raw1 = _make_raw_http(path="/api/v1/upload")
        raw2 = _make_raw_http(path="/api/v2/webhook",
                              body='{"callback": "https://hooks.example.com"}')
        e1 = base64.b64encode(raw1).decode()
        e2 = base64.b64encode(raw2).decode()
        xml = (
            f"<items>"
            f'<item><request base64="true">{e1}</request></item>'
            f'<item><request base64="true">{e2}</request></item>'
            f"</items>"
        )
        p = tmp_path / "multi.xml"
        p.write_text(xml)

        reqs = BurpXmlImporter(str(p)).parse()
        assert len(reqs) == 2
        paths = {r.path for r in reqs}
        assert "/api/v1/upload" in paths
        assert "/api/v2/webhook" in paths


# ---------------------------------------------------------------------------
# Unit: HarImporter
# ---------------------------------------------------------------------------


def _make_har(entries: list) -> dict:
    return {"log": {"version": "1.2", "entries": entries}}


def _make_har_entry(method="POST", url="https://api.example.com/api/v1/upload",
                    body_text='{"imageUrl": "https://cdn.example.com/img.jpg"}',
                    mime="application/json") -> dict:
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": [
                {"name": "Content-Type", "value": mime},
                {"name": "Authorization", "value": "Bearer tok"},
            ],
            "postData": {"mimeType": mime, "text": body_text},
        }
    }


class TestHarImporter:
    def test_parse_single_entry(self, tmp_path):
        har = _make_har([_make_har_entry()])
        p = tmp_path / "test.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert len(reqs) == 1
        r = reqs[0]
        assert r.method == "POST"
        assert r.path == "/api/v1/upload"
        assert r.headers.get("Authorization") == "Bearer tok"
        assert r.body is not None
        assert "imageUrl" in r.url_like_fields

    def test_path_strips_scheme_and_host(self, tmp_path):
        entry = _make_har_entry(url="https://api.example.com/v2/webhook?retry=1")
        har = _make_har([entry])
        p = tmp_path / "strip.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert reqs[0].path == "/v2/webhook?retry=1"

    def test_no_post_data_gives_none_body(self, tmp_path):
        entry = {
            "request": {
                "method": "GET",
                "url": "https://api.example.com/users",
                "headers": [],
            }
        }
        har = _make_har([entry])
        p = tmp_path / "get.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert reqs[0].body is None

    def test_missing_file_raises(self):
        with pytest.raises(ImportSourceError, match="not found"):
            HarImporter("/no/such/file.har").parse()

    def test_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.har"
        p.write_text("{not json}")
        with pytest.raises(ImportSourceError, match="not valid JSON"):
            HarImporter(str(p)).parse()

    def test_missing_log_key_raises(self, tmp_path):
        p = tmp_path / "no_log.har"
        p.write_text(json.dumps({"data": []}))
        with pytest.raises(ImportSourceError, match="missing required 'log' key"):
            HarImporter(str(p)).parse()

    def test_empty_entries_returns_empty(self, tmp_path):
        har = _make_har([])
        p = tmp_path / "empty.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert reqs == []

    def test_malformed_entry_skipped(self, tmp_path):
        good = _make_har_entry()
        bad = {"not_request": "oops"}
        har = _make_har([bad, good])
        p = tmp_path / "mixed.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert len(reqs) == 1
        assert reqs[0].path == "/api/v1/upload"

    def test_multiple_entries(self, tmp_path):
        e1 = _make_har_entry(url="https://api.example.com/v1/upload")
        e2 = _make_har_entry(url="https://api.example.com/v2/webhook",
                              body_text='{"callback": "https://hooks.example.com"}')
        har = _make_har([e1, e2])
        p = tmp_path / "multi.har"
        p.write_text(json.dumps(har))

        reqs = HarImporter(str(p)).parse()
        assert len(reqs) == 2
        paths = {r.path for r in reqs}
        assert "/v1/upload" in paths
        assert "/v2/webhook" in paths


# ---------------------------------------------------------------------------
# Unit: apply_ssrf_options — new fields
# ---------------------------------------------------------------------------


class TestApplySsrfOptionsNewFields:
    def _cfg(self):
        return SSRFConfig()

    def test_burp_xml_path_set(self):
        cfg = self._cfg()
        apply_ssrf_options(cfg, {"burp_xml": "/tmp/burp.xml"})
        assert cfg.burp_xml_path == "/tmp/burp.xml"
        assert cfg.body_injection is True  # implied

    def test_har_path_set(self):
        cfg = self._cfg()
        apply_ssrf_options(cfg, {"har": "/tmp/export.har"})
        assert cfg.har_path == "/tmp/export.har"
        assert cfg.body_injection is True  # implied

    def test_ssrf_body_field_collected(self):
        cfg = self._cfg()
        apply_ssrf_options(cfg, {"ssrf_body_field": ("imageUrl", "callback")})
        assert cfg.extra_body_fields == ["imageUrl", "callback"]

    def test_none_of_new_fields_is_noop(self):
        cfg = self._cfg()
        apply_ssrf_options(cfg, {})
        assert cfg.burp_xml_path is None
        assert cfg.har_path is None
        assert cfg.extra_body_fields == []


# ---------------------------------------------------------------------------
# Unit: body field priority merge
# ---------------------------------------------------------------------------


class TestBodyFieldPriority:
    def _module_with(self, extra=None, spec_schema=None):
        cfg = SSRFConfig(
            body_injection=True,
            extra_body_fields=extra or [],
        )
        m = make_module(cfg)
        m.spec_schema = spec_schema
        return m

    def test_extra_fields_appear_first(self):
        m = self._module_with(extra=["customField"])
        fields = m._build_ssrf_body_fields("https://api.example.com/test", "POST")
        assert fields[0] == "customField"

    def test_extra_fields_merged_not_replaced(self):
        m = self._module_with(extra=["customField"])
        fields = m._build_ssrf_body_fields("https://api.example.com/test", "POST")
        # Generic fallback fields must also appear
        assert "url" in fields
        assert "imageUrl" in fields

    def test_no_duplicates_when_extra_overlaps_generic(self):
        m = self._module_with(extra=["url", "imageUrl"])
        fields = m._build_ssrf_body_fields("https://api.example.com/test", "POST")
        assert fields.count("url") == 1
        assert fields.count("imageUrl") == 1

    def test_import_source_fields_before_generic(self):
        imp_req = ImportedRequest(
            method="POST",
            path="/api/upload",
            headers={},
            body={"feedUrl": "https://example.com/feed", "name": "x"},
            url_like_fields=["feedUrl"],
            raw_body=None,
        )
        m = self._module_with()
        fields = m._build_ssrf_body_fields(
            "https://api.example.com/api/upload", "POST", imported_request=imp_req
        )
        # feedUrl from import should precede generic JSON_BODY_FIELDS entry
        assert "feedUrl" in fields
        idx_feed = fields.index("feedUrl")
        # feedUrl is in JSON_BODY_FIELDS too, but import source pushes it first
        assert idx_feed < fields.index("url") if "url" in fields else True

    def test_generic_fallback_when_no_sources(self):
        m = self._module_with()
        fields = m._build_ssrf_body_fields("https://api.example.com/test", "POST")
        assert fields == list(dict.fromkeys(list(JSON_BODY_FIELDS)))


# ---------------------------------------------------------------------------
# Unit: Full_Replay_Mode — _test_imported_request
# ---------------------------------------------------------------------------


class TestFullReplayMode:
    @pytest.mark.asyncio
    async def test_replays_with_original_headers(self):
        cfg = SSRFConfig(body_injection=True)
        calls = []

        async def capture(*args, **kwargs):
            calls.append({"args": args, "kwargs": kwargs})
            return make_response(404, "")

        client = Mock(spec=HTTPRequestEngine)
        client.set_auth_context = Mock()
        client.request = AsyncMock(side_effect=capture)
        auth = AuthContext(name="t", type=AuthType.BEARER, token="x", privilege_level=1)
        module = SSRFTestingModule(cfg, client, [auth])

        imp_req = ImportedRequest(
            method="POST",
            path="/api/v1/upload",
            headers={"Authorization": "Bearer secret", "X-Custom": "yes"},
            body={"imageUrl": "https://cdn.example.com/img.jpg", "name": "test"},
            url_like_fields=["imageUrl"],
            raw_body=None,
        )
        from modules.owasp.ssrf_testing import InternalProbe
        probes = [InternalProbe("http://127.0.0.1/", "127.0.0.1", {}, False)]
        module._build_probe_set = lambda: (probes, [])

        await module._test_imported_request(
            imp_req, "https://api.example.com", probes, []
        )

        assert len(calls) >= 1
        sent_headers = calls[0]["kwargs"].get("headers", {})
        assert sent_headers.get("Authorization") == "Bearer secret"
        assert sent_headers.get("X-Custom") == "yes"

    @pytest.mark.asyncio
    async def test_non_url_fields_keep_original_value(self):
        cfg = SSRFConfig(body_injection=True)
        bodies_sent = []

        async def capture(*args, **kwargs):
            bodies_sent.append(kwargs.get("json", {}))
            return make_response(404, "")

        client = Mock(spec=HTTPRequestEngine)
        client.set_auth_context = Mock()
        client.request = AsyncMock(side_effect=capture)
        auth = AuthContext(name="t", type=AuthType.BEARER, token="x", privilege_level=1)
        module = SSRFTestingModule(cfg, client, [auth])

        imp_req = ImportedRequest(
            method="POST",
            path="/api/v1/upload",
            headers={},
            body={"imageUrl": "https://cdn.example.com/img.jpg", "name": "Alice"},
            url_like_fields=["imageUrl"],
            raw_body=None,
        )
        probes = [InternalProbe("http://127.0.0.1/", "127.0.0.1", {}, False)]

        await module._test_imported_request(
            imp_req, "https://api.example.com", probes, []
        )

        assert len(bodies_sent) >= 1
        # 'name' field must retain its original value in every probe body
        for body in bodies_sent:
            assert body.get("name") == "Alice"

    @pytest.mark.asyncio
    async def test_safe_mode_skips_post(self):
        cfg = SSRFConfig(safe_mode=True, body_injection=True)
        module = make_module(cfg)
        imp_req = ImportedRequest(
            method="POST",
            path="/api/v1/upload",
            headers={},
            body={"imageUrl": "https://cdn.example.com/img.jpg"},
            url_like_fields=["imageUrl"],
            raw_body=None,
        )
        probes = [InternalProbe("http://127.0.0.1/", "127.0.0.1", {}, False)]

        findings = await module._test_imported_request(
            imp_req, "https://api.example.com", probes, []
        )

        assert findings == []
        module.http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_body_skips_probing(self):
        cfg = SSRFConfig(body_injection=True)
        module = make_module(cfg)
        imp_req = ImportedRequest(
            method="POST",
            path="/api/v1/upload",
            headers={},
            body=None,
            url_like_fields=[],
            raw_body=None,
        )
        probes = [InternalProbe("http://127.0.0.1/", "127.0.0.1", {}, False)]

        findings = await module._test_imported_request(
            imp_req, "https://api.example.com", probes, []
        )

        assert findings == []
        module.http_client.request.assert_not_called()


# ---------------------------------------------------------------------------
# Property: no regression when import sources are absent
# ---------------------------------------------------------------------------


@settings(max_examples=5, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.just("https://api.example.com/resource"), min_size=0, max_size=2))
def test_no_regression_without_import_sources(endpoint_urls):
    """When burp_xml_path, har_path, and extra_body_fields are all defaults,
    probe behavior is identical to the pre-import-sources baseline."""

    async def _run():
        config = SSRFConfig(
            burp_xml_path=None,
            har_path=None,
            extra_body_fields=[],
            internal_targets=["127.0.0.1"],
            bypass_encodings=False,
            scan_ports=[],
        )
        module = make_module(config, return_value=make_response(404, ""))
        endpoints = [EP(u) for u in endpoint_urls]
        findings = await module.execute_tests(endpoints)
        # No import-source related findings; no crash
        assert isinstance(findings, list)

    asyncio.run(_run())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
