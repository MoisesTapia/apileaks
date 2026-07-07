"""
tests/test_bola_tester.py
Tests for ci-cd/scripts/bola_tester.py

Requirements: 4.1–4.6
"""

import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Import path
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from bola_tester import BOLATester, BOLATesterConfig  # noqa: E402
from openapi_discoverer import DiscoveredEndpoint, EndpointParameter  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    owner_id: str = "100",
    user_ids: list = None,
    jwt_token: str = "test.jwt.token",
    roles: list = None,
    role_tokens: list = None,
    safe_mode: bool = False,
    pipeline_id: str = "test-pipeline",
    target_url: str = None,
    output_dir: str = "reports",
) -> BOLATesterConfig:
    return BOLATesterConfig(
        owner_id=owner_id,
        user_ids=user_ids if user_ids is not None else ["200", "300"],
        jwt_token=jwt_token,
        roles=roles if roles is not None else [],
        role_tokens=role_tokens if role_tokens is not None else [],
        safe_mode=safe_mode,
        pipeline_id=pipeline_id,
        target_url=target_url,
        output_dir=output_dir,
    )


def _make_endpoint(
    path: str = "/api/users/{user_id}",
    methods: list = None,
    id_parameters: list = None,
    is_authenticated: bool = True,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(
        path=path,
        methods=methods if methods is not None else ["GET"],
        security_schemes=["bearerAuth"],
        is_authenticated=is_authenticated,
        parameters=[],
        id_parameters=id_parameters if id_parameters is not None else ["user_id"],
    )


def _mock_response(status_code: int, json_data: dict = None, text: str = "") -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    if json_data is not None:
        resp.text = json.dumps(json_data)
    else:
        resp.text = text
    return resp


# ---------------------------------------------------------------------------
# 1. test_get_id_endpoints_returns_only_id_param_endpoints
# ---------------------------------------------------------------------------


def test_get_id_endpoints_returns_only_id_param_endpoints():
    """From a mix of endpoints with/without id_parameters, only those with id_parameters are returned."""
    config = _make_config()
    tester = BOLATester(config)

    ep_with_id = _make_endpoint(path="/api/users/{user_id}", id_parameters=["user_id"])
    ep_without_id = _make_endpoint(path="/api/health", id_parameters=[])
    ep_with_multiple = _make_endpoint(
        path="/api/orders/{order_id}/items/{item_id}",
        id_parameters=["order_id", "item_id"],
    )

    result = tester._get_id_endpoints([ep_with_id, ep_without_id, ep_with_multiple])

    assert len(result) == 2
    paths = [ep.path for ep in result]
    assert "/api/users/{user_id}" in paths
    assert "/api/orders/{order_id}/items/{item_id}" in paths
    assert "/api/health" not in paths


# ---------------------------------------------------------------------------
# 2. test_apply_safe_mode_filters_to_get_only
# ---------------------------------------------------------------------------


def test_apply_safe_mode_filters_to_get_only():
    """Endpoints with GET+POST: after safe_mode, only GET method. Endpoints without GET: excluded."""
    config = _make_config(safe_mode=True)
    tester = BOLATester(config)

    ep_get_post = _make_endpoint(
        path="/api/users/{user_id}", methods=["GET", "POST"], id_parameters=["user_id"]
    )
    ep_post_only = _make_endpoint(
        path="/api/items/{item_id}", methods=["POST", "DELETE"], id_parameters=["item_id"]
    )
    ep_get_only = _make_endpoint(
        path="/api/orders/{order_id}", methods=["GET"], id_parameters=["order_id"]
    )

    result = tester._apply_safe_mode([ep_get_post, ep_post_only, ep_get_only])

    # ep_post_only should be excluded
    assert len(result) == 2
    paths = [ep.path for ep in result]
    assert "/api/users/{user_id}" in paths
    assert "/api/orders/{order_id}" in paths
    assert "/api/items/{item_id}" not in paths

    # ep_get_post should only have GET
    get_post_result = next(ep for ep in result if ep.path == "/api/users/{user_id}")
    assert get_post_result.methods == ["GET"]


# ---------------------------------------------------------------------------
# 3. test_check_id_in_response_finds_field
# ---------------------------------------------------------------------------


def test_check_id_in_response_finds_field():
    """JSON body with matching substitute_id returns the field name."""
    config = _make_config()
    tester = BOLATester(config)

    body = json.dumps({"user_id": "999", "name": "Alice"})
    result = tester._check_id_in_response(body, "999")
    assert result == "user_id"


# ---------------------------------------------------------------------------
# 4. test_check_id_in_response_no_match
# ---------------------------------------------------------------------------


def test_check_id_in_response_no_match():
    """substitute_id not present in response body returns None."""
    config = _make_config()
    tester = BOLATester(config)

    body = json.dumps({"user_id": "111", "name": "Bob"})
    result = tester._check_id_in_response(body, "999")
    assert result is None


# ---------------------------------------------------------------------------
# 5. test_test_endpoint_200_with_id_in_body_is_critical
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_endpoint_200_with_id_in_body_is_critical():
    """Mock HTTP returns 200 with body containing substitute_id → finding with severity CRITICAL."""
    config = _make_config(owner_id="100", target_url="https://api.example.com")
    tester = BOLATester(config)
    endpoint = _make_endpoint(path="/api/users/{user_id}", id_parameters=["user_id"])

    mock_resp = _mock_response(200, {"user_id": "200", "name": "Alice"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        finding = await tester._test_endpoint(
            endpoint,
            param_name="user_id",
            substitute_id="200",
            jwt_token="test.token",
        )

    assert finding is not None
    assert finding["severity"] == "CRITICAL"
    assert finding["owasp_category"] == "API1:2023"
    assert finding["parameter"] == "user_id"
    assert finding["evidence"] == "user_id"
    assert finding["status_code"] == 200


# ---------------------------------------------------------------------------
# 6. test_test_endpoint_200_without_id_in_body_no_finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_endpoint_200_without_id_in_body_no_finding():
    """Mock HTTP returns 200 but body does NOT contain the substitute_id → no finding."""
    config = _make_config(owner_id="100", target_url="https://api.example.com")
    tester = BOLATester(config)
    endpoint = _make_endpoint(path="/api/users/{user_id}", id_parameters=["user_id"])

    mock_resp = _mock_response(200, {"user_id": "999", "name": "Carol"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        finding = await tester._test_endpoint(
            endpoint,
            param_name="user_id",
            substitute_id="200",  # NOT in response body
            jwt_token="test.token",
        )

    assert finding is None


# ---------------------------------------------------------------------------
# 7. test_test_endpoint_404_no_finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_endpoint_404_no_finding():
    """Mock HTTP returns 404 → no finding."""
    config = _make_config(owner_id="100", target_url="https://api.example.com")
    tester = BOLATester(config)
    endpoint = _make_endpoint(path="/api/users/{user_id}", id_parameters=["user_id"])

    mock_resp = _mock_response(404, text="Not Found")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        finding = await tester._test_endpoint(
            endpoint,
            param_name="user_id",
            substitute_id="200",
            jwt_token="test.token",
        )

    assert finding is None


# ---------------------------------------------------------------------------
# 8. test_roles_tokens_mismatch_exits_1
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roles_tokens_mismatch_exits_1():
    """Config with 2 roles but 3 tokens → sys.exit(1)."""
    config = _make_config(
        roles=["admin", "user"],
        role_tokens=["token_a", "token_b", "token_c"],  # 3 tokens — mismatch
    )
    tester = BOLATester(config)
    endpoint = _make_endpoint()

    with pytest.raises(SystemExit) as exc_info:
        await tester.run([endpoint])

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# 9. test_roles_tokens_match_tests_run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roles_tokens_match_tests_run():
    """Config with 2 roles and 2 tokens → tests run twice (once per role)."""
    config = _make_config(
        owner_id="100",
        user_ids=["200"],
        target_url="https://api.example.com",
        roles=["admin", "user"],
        role_tokens=["token_admin", "token_user"],
    )
    tester = BOLATester(config)
    endpoint = _make_endpoint(path="/api/users/{user_id}", id_parameters=["user_id"])

    call_args_list = []

    async def mock_request(method, url, headers=None, **kwargs):
        call_args_list.append((method, url, headers))
        return _mock_response(404)  # no findings, just count calls

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = mock_request

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await tester.run([endpoint])

    # 1 substitute_id × 2 roles = 2 HTTP calls
    assert len(call_args_list) == 2

    # Verify each role's token was used
    tokens_used = {h.get("Authorization") for _, _, h in call_args_list if h}
    assert "Bearer token_admin" in tokens_used
    assert "Bearer token_user" in tokens_used

    assert findings == []


# ---------------------------------------------------------------------------
# 10. test_fuzzing_fallback_no_target_exits_1
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fuzzing_fallback_no_target_exits_1():
    """No endpoints + no APILEAK_TARGET → sys.exit(1)."""
    config = _make_config(target_url=None)
    tester = BOLATester(config)

    with pytest.raises(SystemExit) as exc_info:
        await tester.run(endpoints=None)

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# 11. test_fuzzing_fallback_with_target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fuzzing_fallback_with_target():
    """No endpoints + APILEAK_TARGET set → runs fuzzing (does not exit 1)."""
    config = _make_config(
        owner_id="100",
        user_ids=["200"],
        target_url="https://api.example.com",
    )
    tester = BOLATester(config)

    mock_resp = _mock_response(404)  # no findings
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        # Should not raise SystemExit
        findings = await tester.run(endpoints=None)

    assert isinstance(findings, list)
    # No 200 responses so no findings
    assert findings == []
    # HTTP calls were made (fuzzing happened)
    assert mock_client.request.call_count > 0


# ---------------------------------------------------------------------------
# 12. test_safe_mode_no_post_requests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_mode_no_post_requests():
    """Endpoints have POST method only + safe_mode=True → no HTTP requests issued."""
    config = _make_config(
        safe_mode=True,
        target_url="https://api.example.com",
    )
    tester = BOLATester(config)

    # POST-only endpoint
    endpoint = _make_endpoint(
        path="/api/users/{user_id}",
        methods=["POST"],
        id_parameters=["user_id"],
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=_mock_response(200, {"user_id": "200"}))

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await tester.run([endpoint])

    # Safe mode should have filtered out the POST-only endpoint
    # So no HTTP requests should have been made
    assert mock_client.request.call_count == 0
    assert findings == []


# ---------------------------------------------------------------------------
# 13. test_write_output_creates_file
# ---------------------------------------------------------------------------


def test_write_output_creates_file(tmp_path):
    """write_output() creates the expected file path with correct format."""
    config = _make_config(pipeline_id="pipe-001", output_dir=str(tmp_path))
    tester = BOLATester(config)

    findings = [
        {
            "finding_id": "abc-123",
            "severity": "CRITICAL",
            "owasp_category": "API1:2023",
            "endpoint": "https://api.example.com/api/users/200",
            "method": "GET",
            "status_code": 200,
            "parameter": "user_id",
            "evidence": "user_id",
            "recommendation": "Fix authorization.",
            "scan_timestamp": "2024-01-01T00:00:00+00:00",
        }
    ]

    output_path = tester.write_output(findings)

    expected_path = str(tmp_path / "apileak-bola-pipe-001.json")
    assert output_path == expected_path
    assert os.path.exists(output_path)

    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    assert "findings" in data
    assert "scan_meta" in data
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["scan_meta"]["pipeline_id"] == "pipe-001"


# ---------------------------------------------------------------------------
# 14. test_run_end_to_end_finds_critical
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_end_to_end_finds_critical():
    """Integration: endpoint with id_parameter, mock HTTP returns 200 with substitute_id in body → CRITICAL finding."""
    config = _make_config(
        owner_id="100",
        user_ids=["200"],
        jwt_token="valid.jwt.token",
        target_url="https://api.example.com",
    )
    tester = BOLATester(config)

    endpoint = _make_endpoint(
        path="/api/users/{user_id}",
        methods=["GET"],
        id_parameters=["user_id"],
    )

    mock_resp = _mock_response(200, {"user_id": "200", "name": "Alice", "email": "alice@example.com"})
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=mock_resp)

    with patch("bola_tester.httpx.AsyncClient", return_value=mock_client):
        findings = await tester.run([endpoint])

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "CRITICAL"
    assert finding["owasp_category"] == "API1:2023"
    assert finding["parameter"] == "user_id"
    assert finding["evidence"] == "user_id"
    assert finding["status_code"] == 200
    assert "200" in finding["endpoint"]  # substitute_id in URL
    assert "finding_id" in finding
    assert "scan_timestamp" in finding
    assert "recommendation" in finding
