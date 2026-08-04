"""
Tests for Function Level Authorization Module (OWASP API5 — BFLA)

Coverage:
  - Module basics (name, empty endpoints)
  - Level 1: multi-token matrix replay (anon + low-priv)
  - Level 2a: verb tampering
  - Level 2b: X-HTTP-Method-Override
  - Level 3: mass-assignment role injection
  - Level 4: API version downgrade
  - Safe mode gates
"""

import pytest
from dataclasses import dataclass
from unittest.mock import Mock, AsyncMock, patch

from modules.owasp.function_level_auth import FunctionLevelAuthModule
from utils.http_client import HTTPRequestEngine, Response
from core.config import FunctionAuthConfig, AuthContext, AuthType, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class MockEndpoint:
    url: str
    method: str = "GET"


def make_response(status_code=200, body="", headers=None, url="", method="GET"):
    content = body.encode("utf-8")
    return Response(
        status_code=status_code,
        headers=headers if headers is not None else {"content-type": "application/json"},
        content=content,
        text=body,
        url=url or "https://api.example.com",
        elapsed=0.05,
        request_method=method,
    )


def make_auth_contexts(high_token="admin_tok", low_token="user_tok"):
    return [
        AuthContext(name="admin", type=AuthType.BEARER,
                    token=high_token, privilege_level=100),
        AuthContext(name="user",  type=AuthType.BEARER,
                    token=low_token,  privilege_level=1),
    ]


def make_module(config, mock_client, auth_contexts):
    return FunctionLevelAuthModule(config, mock_client, auth_contexts)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_contexts():
    return make_auth_contexts()


@pytest.fixture
def mock_http_client():
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    client.current_auth_context = None
    return client


# ---------------------------------------------------------------------------
# Basics
# ---------------------------------------------------------------------------

class TestModuleBasics:

    def test_module_name(self, mock_http_client, auth_contexts):
        cfg = FunctionAuthConfig()
        module = make_module(cfg, mock_http_client, auth_contexts)
        assert module.get_module_name() == "function_auth"

    @pytest.mark.asyncio
    async def test_empty_endpoints_no_contexts_returns_empty(self, mock_http_client):
        """No auth contexts → skip immediately, return []."""
        cfg = FunctionAuthConfig()
        module = make_module(cfg, mock_http_client, [])
        findings = await module.execute_tests([])
        assert findings == []
        mock_http_client.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_endpoints_with_contexts_returns_informational_only(
            self, mock_http_client, auth_contexts):
        """No endpoints → no admin records → only empty list."""
        cfg = FunctionAuthConfig()
        module = make_module(cfg, mock_http_client, auth_contexts)
        findings = await module.execute_tests([])
        # No endpoints to map → nothing to replay → empty
        assert findings == []



# ---------------------------------------------------------------------------
# Level 1 — Multi-token matrix replay
# ---------------------------------------------------------------------------

class TestLevel1MultiTokenReplay:

    @pytest.mark.asyncio
    async def test_anon_access_emits_critical_finding(self, mock_http_client,
                                                      auth_contexts):
        """Anonymous GET on an admin endpoint → BFLA_ANONYMOUS_ADMIN_ACCESS CRITICAL."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=["DELETE"],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # All requests return 200 so: admin map succeeds AND anon replay succeeds.
        mock_http_client.request.return_value = make_response(
            status_code=200,
            url="https://api.example.com/admin/users",
        )

        endpoints = [MockEndpoint("https://api.example.com/admin/users")]
        findings = await module.execute_tests(endpoints)

        anon_findings = [f for f in findings
                         if f.category == "BFLA_ANONYMOUS_ADMIN_ACCESS"]
        assert len(anon_findings) >= 1
        assert anon_findings[0].severity == Severity.CRITICAL
        assert anon_findings[0].owasp_category == "API5"

    @pytest.mark.asyncio
    async def test_low_priv_access_emits_critical_finding(self, mock_http_client,
                                                          auth_contexts):
        """Low-privilege token reaching admin endpoint → BFLA_LOW_PRIV_ACCESS CRITICAL."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(
            status_code=200,
            url="https://api.example.com/admin/export",
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/export")]
        )

        low_priv = [f for f in findings if f.category == "BFLA_LOW_PRIV_ACCESS"]
        assert len(low_priv) >= 1
        assert low_priv[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_admin_endpoint_exposed_always_emitted(self, mock_http_client,
                                                         auth_contexts):
        """BFLA_ADMIN_ENDPOINT_EXPOSED is emitted for every mapped admin endpoint
        regardless of whether low-priv access succeeds."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # Admin map: 200.  Low-priv replay: 403 (blocked).
        mock_http_client.request.side_effect = [
            make_response(200, url="https://api.example.com/admin/config"),  # admin map
            make_response(403, url="https://api.example.com/admin/config"),  # low-priv
            make_response(403, url="https://api.example.com/admin/config"),  # anon
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/config")]
        )

        exposed = [f for f in findings if f.category == "BFLA_ADMIN_ENDPOINT_EXPOSED"]
        assert len(exposed) >= 1
        assert exposed[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_non_admin_endpoint_not_mapped(self, mock_http_client, auth_contexts):
        """Regular endpoints (no admin keyword, low score) are not mapped."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(200)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/api/v1/products")]
        )
        # No admin indicators → nothing mapped → only informational findings at most
        bfla_crit = [f for f in findings
                     if f.category in ("BFLA_LOW_PRIV_ACCESS",
                                       "BFLA_ANONYMOUS_ADMIN_ACCESS")]
        assert bfla_crit == []



# ---------------------------------------------------------------------------
# Level 2a — Verb tampering
# ---------------------------------------------------------------------------

class TestLevel2VerbTampering:

    @pytest.mark.asyncio
    async def test_verb_tamper_emits_high_finding(self, mock_http_client,
                                                  auth_contexts):
        """A low-priv DELETE on an admin-mapped GET endpoint → BFLA_VERB_TAMPERING HIGH."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=["DELETE"],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # call sequence: admin-map GET (200), L1 low-priv replay (403), L1 anon (403),
        # L2 verb-tamper DELETE (200) → confirmed
        mock_http_client.request.side_effect = [
            make_response(200),   # admin map
            make_response(403),   # L1 low-priv
            make_response(403),   # L1 anon
            make_response(200),   # L2 verb tamper DELETE
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="GET")]
        )

        vt = [f for f in findings if f.category == "BFLA_VERB_TAMPERING"]
        assert len(vt) >= 1
        assert vt[0].severity == Severity.HIGH
        assert vt[0].owasp_category == "API5"

    @pytest.mark.asyncio
    async def test_verb_tamper_skipped_when_safe_mode(self, mock_http_client,
                                                      auth_contexts):
        """In safe mode state-changing verb tamper probes are suppressed."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=["DELETE"],
            role_fields=[], role_values=[],
            api_versions=[],
            safe_mode=True,
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(200)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="GET")]
        )

        vt = [f for f in findings if f.category == "BFLA_VERB_TAMPERING"]
        assert vt == []

    @pytest.mark.asyncio
    async def test_verb_tamper_no_finding_when_403(self, mock_http_client,
                                                   auth_contexts):
        """Verb tamper attempt returning 403 → no finding."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=["DELETE"],
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        mock_http_client.request.side_effect = [
            make_response(200),   # admin map
            make_response(403),   # L1 low-priv
            make_response(403),   # L1 anon
            make_response(403),   # L2 DELETE tamper → blocked
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="GET")]
        )
        assert not any(f.category == "BFLA_VERB_TAMPERING" for f in findings)



# ---------------------------------------------------------------------------
# Level 2b — X-HTTP-Method-Override
# ---------------------------------------------------------------------------

class TestLevel2MethodOverride:

    @pytest.mark.asyncio
    async def test_method_override_emits_high_finding(self, mock_http_client,
                                                      auth_contexts):
        """GET + X-HTTP-Method-Override: DELETE returning 200 → BFLA_METHOD_OVERRIDE HIGH."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],    # disable verb tamper so only override fires
            role_fields=[], role_values=[],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # admin map (200), L1 low-priv (403), L1 anon (403),
        # override GET+X-HTTP-Method-Override:DELETE (200)
        mock_http_client.request.side_effect = [
            make_response(200),   # admin map
            make_response(403),   # L1 low-priv
            make_response(403),   # L1 anon
            make_response(200),   # override bypass
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="GET")]
        )

        mo = [f for f in findings if f.category == "BFLA_METHOD_OVERRIDE"]
        assert len(mo) >= 1
        assert mo[0].severity == Severity.HIGH
        assert mo[0].owasp_category == "API5"

    @pytest.mark.asyncio
    async def test_method_override_skipped_when_safe_mode(self, mock_http_client,
                                                          auth_contexts):
        """Safe mode suppresses all method-override probes."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=[],
            safe_mode=True,
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(200)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="GET")]
        )
        assert not any(f.category == "BFLA_METHOD_OVERRIDE" for f in findings)



# ---------------------------------------------------------------------------
# Level 3 — Mass-assignment role injection
# ---------------------------------------------------------------------------

class TestLevel3MassAssignment:

    @pytest.mark.asyncio
    async def test_mass_assign_role_emits_critical_finding(self, mock_http_client,
                                                            auth_contexts):
        """Role echoed back in 2xx response → BFLA_MASS_ASSIGNMENT_ROLE CRITICAL.

        Use a URL-aware side_effect so we can control what each phase gets
        regardless of how many calls L1/L2 consume before L3 runs.
        """
        cfg = FunctionAuthConfig(
            admin_endpoints=[],
            dangerous_methods=[],
            role_fields=["role"],
            role_values=["admin"],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # Track call count per URL to distinguish baseline vs injection
        call_counts: dict = {}

        async def smart_request(method, url, json=None, **kwargs):
            call_counts[url] = call_counts.get(url, 0) + 1
            n = call_counts[url]
            # L3: first call is baseline (no role field in body), second is injection
            if method == "POST" and "register" in url:
                if n == 1:
                    return make_response(201, body='{"username":"probe","id":1}', url=url)
                else:
                    return make_response(201, body='{"username":"probe","role":"admin"}', url=url)
            return make_response(201, body='{"id":1}', url=url)

        mock_http_client.request = AsyncMock(side_effect=smart_request)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/register", method="POST")]
        )

        mass = [f for f in findings if f.category == "BFLA_MASS_ASSIGNMENT_ROLE"]
        assert len(mass) >= 1
        assert mass[0].severity == Severity.CRITICAL
        assert mass[0].owasp_category == "API5"

    @pytest.mark.asyncio
    async def test_mass_assign_no_finding_when_role_not_echoed(self,
                                                                mock_http_client,
                                                                auth_contexts):
        """Role injection returning 201 but role NOT echoed → no finding."""
        cfg = FunctionAuthConfig(
            admin_endpoints=[],
            dangerous_methods=[],
            role_fields=["role"],
            role_values=["admin"],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # Both baseline and injection return identical body without role
        mock_http_client.request.return_value = make_response(
            201, body='{"username":"probe","id":1}'
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/register", method="POST")]
        )
        assert not any(f.category == "BFLA_MASS_ASSIGNMENT_ROLE" for f in findings)

    @pytest.mark.asyncio
    async def test_mass_assign_skipped_in_safe_mode(self, mock_http_client,
                                                     auth_contexts):
        """Safe mode prevents all mass-assignment probes."""
        cfg = FunctionAuthConfig(
            admin_endpoints=[],
            dangerous_methods=[],
            role_fields=["role"],
            role_values=["admin"],
            api_versions=[],
            safe_mode=True,
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(
            201, body='{"role":"admin"}'
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/register", method="POST")]
        )
        assert not any(f.category == "BFLA_MASS_ASSIGNMENT_ROLE" for f in findings)

    @pytest.mark.asyncio
    async def test_mass_assign_non_registration_endpoint_skipped(self,
                                                                   mock_http_client,
                                                                   auth_contexts):
        """Endpoints that don't match the registration pattern are skipped."""
        cfg = FunctionAuthConfig(
            admin_endpoints=[],
            dangerous_methods=[],
            role_fields=["role"],
            role_values=["admin"],
            api_versions=[],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(
            200, body='{"role":"admin"}'
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/api/v1/products", method="POST")]
        )
        assert not any(f.category == "BFLA_MASS_ASSIGNMENT_ROLE" for f in findings)



# ---------------------------------------------------------------------------
# Level 4 — API version downgrade
# ---------------------------------------------------------------------------

class TestLevel4VersionDowngrade:

    @pytest.mark.asyncio
    async def test_version_downgrade_emits_high_finding(self, mock_http_client,
                                                         auth_contexts):
        """v3 admin endpoint returns 403 for low-priv; v1 returns 200 → BFLA_VERSION_DOWNGRADE HIGH.

        dangerous_methods=[] disables verb-tamper so L2a produces zero calls.
        The method-override (L2b) fires regardless on the first 20 admin records —
        use return_value so it always gets a response without exhausting side_effect.
        Then override side_effect just for the version downgrade probes.
        """
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],       # no verb tamper
            role_fields=[], role_values=[],
            api_versions=["v1", "v2", "v3"],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        # Give every call a default 403 response, then override specific positions.
        # We use return_value as the default and side_effect only for the calls
        # we care about by setting return_value to 403 and adding a smarter side_effect.

        call_log = []

        async def smart_request(method, url, **kwargs):
            call_log.append((method, url))
            # admin map probe (first call, url contains v3/admin)
            if "v3/admin" in url and len(call_log) == 1:
                return make_response(200, url=url)
            # downgrade to v1 → confirmed
            if "/v1/admin" in url:
                return make_response(200, url=url)
            # everything else → 403
            return make_response(403, url=url)

        mock_http_client.request = AsyncMock(side_effect=smart_request)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/api/v3/admin/users")]
        )

        vd = [f for f in findings if f.category == "BFLA_VERSION_DOWNGRADE"]
        assert len(vd) >= 1
        assert vd[0].severity == Severity.HIGH
        assert vd[0].owasp_category == "API5"

    @pytest.mark.asyncio
    async def test_version_downgrade_no_finding_when_all_blocked(self,
                                                                   mock_http_client,
                                                                   auth_contexts):
        """All older versions return 403 → no downgrade finding."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=["v1", "v2", "v3"],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)

        mock_http_client.request.side_effect = [
            make_response(200),   # admin map v3
            make_response(403),   # L1 low-priv
            make_response(403),   # L1 anon
            make_response(403),   # L4 v1
            make_response(403),   # L4 v2
        ]

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/api/v3/admin/users")]
        )
        assert not any(f.category == "BFLA_VERSION_DOWNGRADE" for f in findings)

    @pytest.mark.asyncio
    async def test_version_downgrade_non_versioned_url_skipped(self,
                                                                 mock_http_client,
                                                                 auth_contexts):
        """URLs without a /vN/ segment are not considered for version downgrade."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=["v1"],
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(200)

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users")]
        )
        assert not any(f.category == "BFLA_VERSION_DOWNGRADE" for f in findings)



# ---------------------------------------------------------------------------
# Safe mode global gate
# ---------------------------------------------------------------------------

class TestSafeMode:

    @pytest.mark.asyncio
    async def test_safe_mode_downgrade_to_get_for_admin_map(self, mock_http_client,
                                                              auth_contexts):
        """In safe mode, DELETE admin endpoints are probed as GET during mapping."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=[],
            role_fields=[], role_values=[],
            api_versions=[],
            safe_mode=True,
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(
            200, url="https://api.example.com/admin/users"
        )

        await module.execute_tests(
            [MockEndpoint("https://api.example.com/admin/users", method="DELETE")]
        )

        # All calls must be GET — safe mode must have downgraded DELETE
        for call in mock_http_client.request.call_args_list:
            assert call.args[0].upper() == "GET", \
                f"Expected GET in safe mode but got {call.args[0]}"

    @pytest.mark.asyncio
    async def test_safe_mode_no_state_changing_findings(self, mock_http_client,
                                                         auth_contexts):
        """In safe mode the module returns no state-changing BFLA findings."""
        cfg = FunctionAuthConfig(
            admin_endpoints=["/admin"],
            dangerous_methods=["DELETE", "PUT", "PATCH"],
            role_fields=["role"],
            role_values=["admin"],
            api_versions=["v1", "v3"],
            safe_mode=True,
        )
        module = make_module(cfg, mock_http_client, auth_contexts)
        mock_http_client.request.return_value = make_response(
            200, url="https://api.example.com/admin/users",
            body='{"role":"admin"}'
        )

        findings = await module.execute_tests(
            [MockEndpoint("https://api.example.com/api/v3/admin/users", method="DELETE")]
        )

        # Verb tampering, method override, and mass-assignment must all be absent
        state_changing_cats = {
            "BFLA_VERB_TAMPERING", "BFLA_METHOD_OVERRIDE", "BFLA_MASS_ASSIGNMENT_ROLE"
        }
        for f in findings:
            assert f.category not in state_changing_cats, \
                f"Safe mode should not emit {f.category}"


# ---------------------------------------------------------------------------
# Privilege helper unit tests
# ---------------------------------------------------------------------------

class TestPrivilegeLevelHelper:

    def test_privilege_level_uses_attribute(self):
        from modules.owasp.function_level_auth import _privilege_level
        ctx = AuthContext(name="x", type=AuthType.BEARER, token="t",
                          privilege_level=75)
        assert _privilege_level(ctx) == 75

    def test_privilege_level_heuristic_admin(self):
        from modules.owasp.function_level_auth import _privilege_level
        ctx = AuthContext(name="admin_user", type=AuthType.BEARER, token="t",
                          privilege_level=None)
        assert _privilege_level(ctx) == 100

    def test_privilege_level_heuristic_user(self):
        from modules.owasp.function_level_auth import _privilege_level
        ctx = AuthContext(name="regular_user", type=AuthType.BEARER, token="t",
                          privilege_level=None)
        assert _privilege_level(ctx) == 30

    def test_is_anonymous_no_token(self):
        from modules.owasp.function_level_auth import _is_anonymous
        ctx = AuthContext(name="anon", type=AuthType.BEARER, token="",
                          privilege_level=0)
        assert _is_anonymous(ctx) is True

    def test_is_anonymous_with_token(self):
        from modules.owasp.function_level_auth import _is_anonymous
        ctx = AuthContext(name="user", type=AuthType.BEARER, token="tok",
                          privilege_level=1)
        assert _is_anonymous(ctx) is False


if __name__ == "__main__":
    import pytest as _pytest
    _pytest.main([__file__, "-v"])
