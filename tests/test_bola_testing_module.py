"""
Tests for BOLA Testing Module
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from modules.owasp.bola_testing import BOLATestingModule, ObjectIdentifier
from utils.http_client import HTTPRequestEngine, Response
from core.config import BOLAConfig, AuthContext, AuthType
from core.logging import get_logger


@dataclass
class MockEndpoint:
    """Mock endpoint for testing"""
    url: str
    method: str = "GET"


class TestBOLATestingModule:
    """Test cases for BOLA Testing Module"""
    
    @pytest.fixture
    def bola_config(self):
        """Create BOLA configuration for testing"""
        return BOLAConfig(
            enabled=True,
            id_patterns=["sequential", "guid", "uuid"],
            test_contexts=["anonymous", "user", "admin"]
        )
    
    @pytest.fixture
    def auth_contexts(self):
        """Create auth contexts for testing"""
        return [
            AuthContext(
                name="user1",
                type=AuthType.BEARER,
                token="user1_token",
                privilege_level=1
            ),
            AuthContext(
                name="user2", 
                type=AuthType.BEARER,
                token="user2_token",
                privilege_level=1
            ),
            AuthContext(
                name="admin",
                type=AuthType.BEARER,
                token="admin_token",
                privilege_level=3
            )
        ]
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client"""
        client = Mock(spec=HTTPRequestEngine)
        client.request = AsyncMock()
        client.set_auth_context = Mock()
        return client
    
    @pytest.fixture
    def bola_module(self, bola_config, auth_contexts, mock_http_client):
        """Create BOLA testing module"""
        return BOLATestingModule(bola_config, mock_http_client, auth_contexts)
    
    def test_module_initialization(self, bola_module, auth_contexts):
        """Test BOLA module initialization"""
        assert bola_module.get_module_name() == "bola_testing"
        assert len(bola_module.auth_contexts) == len(auth_contexts)
        assert "anonymous" in bola_module.auth_context_map
    
    def test_substitute_identifier_path_and_query(self, bola_module):
        """Identifier substitution targets the right path segment / query param.

        Corrected behavior (Requirement 1): the former no-op
        (``replace(value, value)``) is fixed - a candidate id is substituted at
        the exact path position or query parameter while all else is preserved.
        """
        path_id = ObjectIdentifier(
            value="123", type="sequential",
            endpoint="https://api.example.com/users/123/orders",
            parameter_name="user_id", location="path",
        )
        assert (bola_module._substitute_identifier(path_id, "999")
                == "https://api.example.com/users/999/orders")
        # Equal candidate leaves the URL unchanged.
        assert (bola_module._substitute_identifier(path_id, "123")
                == "https://api.example.com/users/123/orders")

        query_id = ObjectIdentifier(
            value="123", type="sequential",
            endpoint="https://api.example.com/users?user_id=123&sort=asc",
            parameter_name="user_id", location="query",
        )
        substituted = bola_module._substitute_identifier(query_id, "999")
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(substituted).query)
        assert q["user_id"] == ["999"]
        assert q["sort"] == ["asc"]

    @pytest.mark.asyncio
    async def test_object_access_issues_candidate_url(self, bola_module, mock_http_client):
        """_test_object_access issues the request against the substituted candidate URL.

        Corrected behavior (Requirement 1.4): a candidate that differs from the
        original id produces a request URL that differs from the original
        endpoint (the old code requested the original object every time).
        """
        identifier = ObjectIdentifier(
            value="123", type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id", location="path",
        )

        ok = Response(
            status_code=200, headers={}, content=b'{}', text='{}',
            url="https://api.example.com/users/777", elapsed=0.1, request_method="GET",
        )
        mock_http_client.request.return_value = ok

        await bola_module._test_object_access(identifier, "ctx", candidate_id="777")

        called_method, called_url = mock_http_client.request.call_args[0][:2]
        assert called_method == "GET"
        assert called_url == "https://api.example.com/users/777"
        assert called_url != identifier.endpoint

    def test_extract_ids_from_response_ignores_plain_integers(self, bola_module):
        """Response id extraction is restricted to recognized field names (Requirement 4.4).

        Plain integers in the body that are not associated with a recognized
        Identifying_Field name are no longer extracted as identifiers.
        """
        response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"count": 42, "total": 100, "user_id": 7}',
            text='{"count": 42, "total": 100, "user_id": 7}',
            url="https://api.example.com/users",
            elapsed=0.1,
            request_method="GET",
        )

        ids = bola_module._extract_ids_from_response(response, "https://api.example.com/users")
        values = {i.value for i in ids}

        # Only the recognized identifying field (user_id=7) is extracted; the
        # plain integers 42 and 100 are ignored.
        assert "7" in values
        assert "42" not in values
        assert "100" not in values

    def test_extract_ids_from_path(self, bola_module):
        """Test ID extraction from URL paths"""
        test_urls = [
            "https://api.example.com/users/123",
            "https://api.example.com/accounts/550e8400-e29b-41d4-a716-446655440000",
            "https://api.example.com/orders/456/items/789"
        ]
        
        for url in test_urls:
            identifiers = bola_module._extract_ids_from_path(url)
            assert len(identifiers) > 0
            assert all(isinstance(id, ObjectIdentifier) for id in identifiers)
    
    def test_determine_id_type(self, bola_module):
        """Test ID type determination"""
        test_cases = [
            ("123", "sequential"),
            ("550e8400-e29b-41d4-a716-446655440000", "guid"),
            ("abc123def", None)
        ]
        
        for value, expected_type in test_cases:
            result = bola_module._determine_id_type(value)
            assert result == expected_type
    
    def test_is_object_accessible(self, bola_module):
        """Test object accessibility determination"""
        # Accessible response
        accessible_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "test object", "data": "some content"}',
            text='{"id": 123, "name": "test object", "data": "some content"}',
            url="https://api.example.com/objects/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Not accessible response (error)
        error_response = Response(
            status_code=404,
            headers={"content-type": "application/json"},
            content=b'{"error": "not found"}',
            text='{"error": "not found"}',
            url="https://api.example.com/objects/999",
            elapsed=0.1,
            request_method="GET"
        )
        
        # Unauthorized response
        unauthorized_response = Response(
            status_code=401,
            headers={"content-type": "application/json"},
            content=b'{"error": "unauthorized"}',
            text='{"error": "unauthorized"}',
            url="https://api.example.com/objects/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        assert bola_module._is_object_accessible(accessible_response) == True
        assert bola_module._is_object_accessible(error_response) == False
        assert bola_module._is_object_accessible(unauthorized_response) == False

    def test_is_object_accessible_uses_negative_control_baseline(self, bola_module):
        """Accessibility is calibrated against the negative-control baseline.

        Corrected behavior (Requirement 3): the fixed 50-byte response-size
        threshold is removed. A short body distinct from the baseline is
        accessible; a body equivalent to the baseline is not; and a
        non-discriminating baseline suppresses accessibility entirely.
        """
        from utils.authz_baseline import NegativeControlBaseline

        # Baseline: invalid id returned a 404 with no identifying fields.
        baseline = NegativeControlBaseline(
            status_code=404,
            identifying_fields={},
            content_length=20,
            is_success=False,
            non_discriminating=False,
        )

        # A SMALL (<50 byte) but distinct, real object is accessible despite the
        # removed byte threshold.
        small_distinct = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 7}',
            text='{"id": 7}',
            url="https://api.example.com/objects/7",
            elapsed=0.1,
            request_method="GET",
        )
        assert bola_module._is_object_accessible(small_distinct, baseline) == True

        # A candidate equivalent to the baseline (same status class, no distinct
        # identifying data) is NOT accessible.
        equivalent_to_baseline = Response(
            status_code=404,
            headers={"content-type": "application/json"},
            content=b'{"error": "not found"}',
            text='{"error": "not found"}',
            url="https://api.example.com/objects/8",
            elapsed=0.1,
            request_method="GET",
        )
        assert bola_module._is_object_accessible(equivalent_to_baseline, baseline) == False

        # A non-discriminating baseline (endpoint returns success for any input)
        # suppresses accessibility regardless of the candidate response.
        non_discriminating = NegativeControlBaseline(
            status_code=200,
            identifying_fields={},
            content_length=100,
            is_success=True,
            non_discriminating=True,
        )
        assert bola_module._is_object_accessible(small_distinct, non_discriminating) == False
    
    def test_responses_indicate_same_object(self, bola_module):
        """Same-object detection is identity-based, not size/word similarity.

        Corrected behavior (Requirement 2): two responses are the same object
        only when they share an equal Identifying_Field value. Response size and
        word similarity are never used.
        """
        # Same identifying value (id=123) => same object, even though the bodies
        # are not byte-identical.
        response1 = Response(
            status_code=200,
            headers={},
            content=b'{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            text='{"id": 123, "name": "John Doe", "email": "john@example.com"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        response2 = Response(
            status_code=200,
            headers={},
            content=b'{"id": 123, "name": "Johnathan Doe"}',
            text='{"id": 123, "name": "Johnathan Doe"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )

        # Same SIZE but DIFFERENT id => different objects. Under the old
        # size-similarity heuristic these near-identical-length bodies would have
        # been judged "same"; identity comparison correctly rejects them.
        response_same_size_diff_id_a = Response(
            status_code=200,
            headers={},
            content=b'{"id": 111, "name": "Alice"}',
            text='{"id": 111, "name": "Alice"}',
            url="https://api.example.com/users/111",
            elapsed=0.1,
            request_method="GET"
        )
        response_same_size_diff_id_b = Response(
            status_code=200,
            headers={},
            content=b'{"id": 222, "name": "Brian"}',
            text='{"id": 222, "name": "Brian"}',
            url="https://api.example.com/users/222",
            elapsed=0.1,
            request_method="GET"
        )

        # No identifying field extractable => never "same object" (Requirement 2.4).
        response_no_id_a = Response(
            status_code=200,
            headers={},
            content=b'{"name": "no id here"}',
            text='{"name": "no id here"}',
            url="https://api.example.com/users/x",
            elapsed=0.1,
            request_method="GET"
        )
        response_no_id_b = Response(
            status_code=200,
            headers={},
            content=b'{"name": "no id here"}',
            text='{"name": "no id here"}',
            url="https://api.example.com/users/y",
            elapsed=0.1,
            request_method="GET"
        )

        assert bola_module._responses_indicate_same_object(response1, response2) == True
        assert bola_module._responses_indicate_same_object(
            response_same_size_diff_id_a, response_same_size_diff_id_b) == False
        assert bola_module._responses_indicate_same_object(
            response_no_id_a, response_no_id_b) == False
    
    @pytest.mark.asyncio
    async def test_discover_object_identifiers(self, bola_module, mock_http_client):
        """Test object identifier discovery"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users/123"),
            MockEndpoint("https://api.example.com/orders/456")
        ]
        
        # Mock response with JSON containing IDs
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"user_id": 789, "account_id": "550e8400-e29b-41d4-a716-446655440000"}',
            text='{"user_id": 789, "account_id": "550e8400-e29b-41d4-a716-446655440000"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        identifiers = await bola_module._discover_object_identifiers(endpoints)
        
        assert len(identifiers) > 0
        assert all(isinstance(id, ObjectIdentifier) for id in identifiers)
        
        # Should have found IDs from both path and response
        path_ids = [id for id in identifiers if id.location == 'path']
        response_ids = [id for id in identifiers if id.location == 'response']
        
        assert len(path_ids) > 0
        assert len(response_ids) > 0
    
    @pytest.mark.asyncio
    async def test_anonymous_access_detection(self, bola_module, mock_http_client):
        """Anonymous access detected against a discriminating baseline.

        Corrected behavior (Requirement 3): the invalid-id baseline (id 0)
        returns 404 so the endpoint is discriminating; the real object (id 123)
        is genuinely accessible without authentication, raising a finding.
        """
        identifier = ObjectIdentifier(
            value="123",
            type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id",
            location="path"
        )

        def side_effect(method, url):
            last = url.rstrip('/').split('/')[-1]
            if last == "123":
                body = '{"id": 123, "name": "John Doe", "email": "john@example.com"}'
                return Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=body.encode(),
                    text=body,
                    url=url,
                    elapsed=0.1,
                    request_method=method,
                )
            return Response(
                status_code=404,
                headers={"content-type": "application/json"},
                content=b'{"error": "not found"}',
                text='{"error": "not found"}',
                url=url,
                elapsed=0.1,
                request_method=method,
            )

        mock_http_client.request.side_effect = side_effect

        findings = await bola_module._test_anonymous_access([identifier])

        assert len(findings) == 1
        assert findings[0].category == "BOLA_ANONYMOUS_ACCESS"
        assert findings[0].severity.value == "CRITICAL"
        assert findings[0].owasp_category == "API1"

    @pytest.mark.asyncio
    async def test_anonymous_access_suppressed_when_non_discriminating(
            self, bola_module, mock_http_client):
        """Non-discriminating endpoints suppress anonymous-access findings (Requirement 25.3).

        When the invalid-id baseline itself returns success, the endpoint answers
        successfully for any input and no accessibility finding is raised.
        """
        identifier = ObjectIdentifier(
            value="123",
            type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id",
            location="path"
        )

        always_ok = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "John Doe"}',
            text='{"id": 123, "name": "John Doe"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET",
        )
        mock_http_client.request.return_value = always_ok

        findings = await bola_module._test_anonymous_access([identifier])

        assert findings == []
    
    @pytest.mark.asyncio
    async def test_horizontal_privilege_escalation(self, bola_module, mock_http_client):
        """Horizontal escalation detected via identity-aware comparison.

        Corrected behavior (Requirements 2, 3, 5): the invalid-id baseline
        returns 404 (discriminating), both users receive the same object
        (matching ``id``), so a BOLA_HORIZONTAL_ESCALATION finding is raised
        with the matching identifying field embedded in the evidence.
        """
        identifier = ObjectIdentifier(
            value="123",
            type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id",
            location="path"
        )

        def side_effect(method, url):
            last = url.rstrip('/').split('/')[-1]
            if last == "123":
                body = '{"id": 123, "owner_id": 5, "name": "John Doe"}'
                return Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=body.encode(),
                    text=body,
                    url=url,
                    elapsed=0.1,
                    request_method=method,
                )
            # Invalid-id baseline and everything else: not found.
            return Response(
                status_code=404,
                headers={"content-type": "application/json"},
                content=b'{"error": "not found"}',
                text='{"error": "not found"}',
                url=url,
                elapsed=0.1,
                request_method=method,
            )

        mock_http_client.request.side_effect = side_effect

        findings = await bola_module._test_horizontal_privilege_escalation([identifier])

        assert len(findings) == 1
        assert findings[0].category == "BOLA_HORIZONTAL_ESCALATION"
        assert findings[0].severity.value == "CRITICAL"
        assert findings[0].owasp_category == "API1"
        # Evidence embeds the matching Identifying_Field (Requirement 2.3).
        assert "id" in findings[0].evidence

    @pytest.mark.asyncio
    @pytest.mark.parametrize("user_count,should_run", [(0, False), (1, False), (2, True), (3, True)])
    async def test_horizontal_escalation_reachability_gating(
            self, bola_config, mock_http_client, user_count, should_run):
        """Reachability gating on the number of user-level contexts (Requirement 5.1/5.2).

        With fewer than two privilege-level-1 contexts the test is skipped and no
        HTTP request is issued; with two or more it runs (issues requests).
        """
        contexts = [
            AuthContext(name=f"user{i}", type=AuthType.BEARER,
                        token=f"user{i}_token", privilege_level=1)
            for i in range(user_count)
        ]
        # An admin (privilege 3) must never count toward the user-level total.
        contexts.append(AuthContext(name="admin", type=AuthType.BEARER,
                                    token="admin_token", privilege_level=3))

        # Baseline/probe requests always return 404 so no finding is produced;
        # we only assert on whether requests were attempted (gating).
        not_found = Response(
            status_code=404,
            headers={"content-type": "application/json"},
            content=b'{"error": "not found"}',
            text='{"error": "not found"}',
            url="https://api.example.com/users/0",
            elapsed=0.1,
            request_method="GET",
        )
        mock_http_client.request.return_value = not_found

        module = BOLATestingModule(bola_config, mock_http_client, contexts)
        identifier = ObjectIdentifier(
            value="123", type="sequential",
            endpoint="https://api.example.com/users/123",
            parameter_name="user_id", location="path",
        )

        findings = await module._test_horizontal_privilege_escalation([identifier])

        assert findings == []
        if should_run:
            assert mock_http_client.request.call_count > 0
        else:
            assert mock_http_client.request.call_count == 0
    
    @pytest.mark.asyncio
    async def test_sequential_id_enumeration(self, bola_module, mock_http_client):
        """Ownership-aware sequential enumeration raises a finding for foreign objects.

        Corrected behavior (Requirement 4): a finding is raised only when
        accessed objects' Identifying_Field shows they do NOT belong to the
        requesting context. Here the requester owns object 100 (owner_id=100);
        neighbouring objects belong to other owners and are accessible.
        """
        identifier = ObjectIdentifier(
            value="100",
            type="sequential",
            endpoint="https://api.example.com/users/100",
            parameter_name="user_id",
            location="path"
        )

        def mock_request_side_effect(method, url):
            path_parts = url.rstrip('/').split('/')
            try:
                id_num = int(path_parts[-1])
            except (ValueError, IndexError):
                id_num = None

            # Own object (100) plus foreign objects are accessible; each carries
            # its own owner_id so ownership can be compared.
            if id_num in [98, 99, 100, 101, 102]:
                owner_id = 100 if id_num == 100 else id_num
                body = f'{{"id": {id_num}, "owner_id": {owner_id}, "name": "User {id_num}"}}'
                return Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=body.encode(),
                    text=body,
                    url=url,
                    elapsed=0.1,
                    request_method=method
                )

            # Invalid-id baseline (id 0) and out-of-range ids: not found.
            return Response(
                status_code=404,
                headers={"content-type": "application/json"},
                content=b'{"error": "not found"}',
                text='{"error": "not found"}',
                url=url,
                elapsed=0.1,
                request_method=method
            )

        mock_http_client.request.side_effect = mock_request_side_effect

        findings = await bola_module._test_sequential_enumeration([identifier])

        assert len(findings) == 1
        assert findings[0].category == "BOLA_ID_ENUMERATION"
        assert findings[0].severity.value == "HIGH"
        assert findings[0].owasp_category == "API1"

    @pytest.mark.asyncio
    async def test_sequential_enumeration_no_finding_when_objects_owned(
            self, bola_module, mock_http_client):
        """No enumeration finding when accessible objects belong to the requester.

        When every accessible neighbouring object shares the requester's
        owner_id, the objects belong to the requesting context, so no
        BOLA_ID_ENUMERATION finding is raised (Requirement 4.1).
        """
        identifier = ObjectIdentifier(
            value="100",
            type="sequential",
            endpoint="https://api.example.com/users/100",
            parameter_name="user_id",
            location="path"
        )

        def mock_request_side_effect(method, url):
            path_parts = url.rstrip('/').split('/')
            try:
                id_num = int(path_parts[-1])
            except (ValueError, IndexError):
                id_num = None

            if id_num in [98, 99, 100, 101, 102]:
                # All owned by the requesting context (owner_id == 100).
                body = f'{{"id": {id_num}, "owner_id": 100}}'
                return Response(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    content=body.encode(),
                    text=body,
                    url=url,
                    elapsed=0.1,
                    request_method=method
                )

            return Response(
                status_code=404,
                headers={"content-type": "application/json"},
                content=b'{"error": "not found"}',
                text='{"error": "not found"}',
                url=url,
                elapsed=0.1,
                request_method=method
            )

        mock_http_client.request.side_effect = mock_request_side_effect

        findings = await bola_module._test_sequential_enumeration([identifier])

        assert findings == []

    @pytest.mark.asyncio
    async def test_sequential_enumeration_skips_non_sequential(
            self, bola_module, mock_http_client):
        """Non-sequential (GUID) identifiers are skipped without requests (Requirement 4.3)."""
        identifier = ObjectIdentifier(
            value="550e8400-e29b-41d4-a716-446655440000",
            type="guid",
            endpoint="https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000",
            parameter_name="user_id",
            location="path"
        )

        findings = await bola_module._test_sequential_enumeration([identifier])

        assert findings == []
        assert mock_http_client.request.call_count == 0

    @pytest.mark.asyncio
    async def test_guid_enumeration_is_skipped(self, bola_module, mock_http_client):
        """GUID enumeration no longer probes random GUIDs (Requirement 4.3)."""
        identifier = ObjectIdentifier(
            value="550e8400-e29b-41d4-a716-446655440000",
            type="guid",
            endpoint="https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000",
            parameter_name="user_id",
            location="path"
        )

        findings = await bola_module._test_guid_enumeration([identifier])

        assert findings == []
        assert mock_http_client.request.call_count == 0
    
    @pytest.mark.asyncio
    async def test_execute_tests_integration(self, bola_module, mock_http_client):
        """Test full BOLA testing execution"""
        # Mock endpoints
        endpoints = [
            MockEndpoint("https://api.example.com/users/123"),
            MockEndpoint("https://api.example.com/orders/456")
        ]
        
        # Mock successful response
        mock_response = Response(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"id": 123, "name": "Test User"}',
            text='{"id": 123, "name": "Test User"}',
            url="https://api.example.com/users/123",
            elapsed=0.1,
            request_method="GET"
        )
        
        mock_http_client.request.return_value = mock_response
        
        findings = await bola_module.execute_tests(endpoints)
        
        # Should return list of findings (may be empty if no vulnerabilities detected)
        assert isinstance(findings, list)
        assert all(hasattr(f, 'category') for f in findings)
        assert all(hasattr(f, 'severity') for f in findings)
        assert all(hasattr(f, 'owasp_category') for f in findings)


if __name__ == "__main__":
    pytest.main([__file__])


# ===========================================================================
# Task 22.3 - Example-based unit tests for advanced BOLA finding evidence,
# dry-run record-without-issuing, and config/CLI safe defaults.
#
# These cover each advanced finding type's Evidence_Chain content and
# confidence (Reqs 27.6, 29.3, 29.4, 30.2, 30.3, 32.4, 32.5, 33.1, 33.2), the
# dry-run records-without-issuing behavior (Reqs 28.5, 28.6), and the
# BOLAConfig / CLI safe defaults + legacy-YAML loading (Reqs 34.1-34.5, 36.1).
# ===========================================================================

import json as _json

from modules.owasp.bola_testing import (
    CompositeIdentifier,
    CompositeIdentifierSlot,
    EvidenceChain,
)
from utils.safe_mode import SAFE_METHODS, STATE_CHANGING_METHODS


def _json_response(status_code, url, body, method="GET"):
    """Build a JSON Response with the fields the module expects."""
    text = body if isinstance(body, str) else _json.dumps(body)
    return Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        content=text.encode(),
        text=text,
        url=url,
        elapsed=0.01,
        request_method=method,
    )


class StatefulHTTPEngine:
    """A tiny in-memory object store that records every issued request.

    GET/HEAD/OPTIONS return the stored object (200) or 404 when the URL is
    absent. State-changing methods (POST/PUT/PATCH/DELETE) merge the JSON body
    into the stored object and return 200, so a subsequent safe GET re-read
    reflects the mutation (the persistence-verification path the module relies
    on). Every ``(method, url, json)`` tuple is captured in ``self.calls`` so a
    test can assert exactly which methods were issued.
    """

    def __init__(self, store=None):
        self.store = dict(store or {})
        self.calls = []
        self.current_auth_context = None

    def set_auth_context(self, ctx):
        self.current_auth_context = ctx

    @property
    def issued_methods(self):
        return [m for (m, _u, _b) in self.calls]

    async def request(self, method, url, json=None, **kwargs):
        self.calls.append((method.upper(), url, json))
        m = method.upper()
        if m in SAFE_METHODS:
            obj = self.store.get(url)
            if obj is None:
                return _json_response(404, url, {"error": "not found"}, m)
            return _json_response(200, url, obj, m)
        # State-changing method: merge the body into the stored object.
        obj = self.store.get(url)
        if obj is None:
            return _json_response(404, url, {"error": "not found"}, m)
        if isinstance(json, dict):
            obj.update(json)
        return _json_response(200, url, obj, m)


def _write_config(**overrides):
    """A BOLAConfig authorizing destructive writes (Safe_Mode off, opt-in on)."""
    cfg = BOLAConfig(
        enabled=True,
        id_patterns=["sequential", "guid", "uuid"],
        test_contexts=["user"],
    )
    cfg.allow_destructive = overrides.get("allow_destructive", True)
    cfg.destructive_methods = overrides.get("destructive_methods", {"PATCH", "PUT"})
    cfg.dry_run = overrides.get("dry_run", False)
    cfg.safe_mode = overrides.get("safe_mode", False)
    cfg.enable_composite = overrides.get("enable_composite", False)
    cfg.enable_id_leakage = overrides.get("enable_id_leakage", False)
    return cfg


class TestAdvancedBOLAEvidence:
    """Evidence-chain / confidence content for each advanced finding type."""

    @pytest.fixture
    def user1(self):
        return AuthContext(name="user1", type=AuthType.BEARER,
                           token="user1_token", privilege_level=1)

    @pytest.mark.asyncio
    async def test_write_escalation_evidence(self, user1):
        """Persisted non-credential foreign mutation -> BOLA_WRITE_ESCALATION (Req 27.5, 27.6)."""
        endpoint = "https://api.example.com/users/1"
        store = {
            "https://api.example.com/users/1": {"id": 1, "nickname": "me"},
            "https://api.example.com/users/2": {"id": 2, "nickname": "victim"},
        }
        engine = StatefulHTTPEngine(store)
        module = BOLATestingModule(_write_config(), engine, [user1])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_write_bola(identifier, "2", [user1])

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_WRITE_ESCALATION"
        assert f.owasp_category == "API1"
        assert f.severity.value == "HIGH"
        # Req 27.6: evidence names the mutated field + original/substituted ids
        # + persistence evidence.
        assert "nickname" in f.evidence
        assert "'1'" in f.evidence and "'2'" in f.evidence
        assert "persist" in f.evidence.lower()
        # Req 33.1/33.2: a redacted Evidence_Chain and Confidence_Score attach.
        assert isinstance(f.evidence_chain, EvidenceChain)
        assert f.evidence_chain.method == "PATCH"
        assert f.evidence_chain.original_id == "1"
        assert f.evidence_chain.substituted_id == "2"
        assert f.evidence_chain.auth_context == "user1"  # name only, never token
        assert "user1_token" not in f.evidence_chain.auth_context
        assert f.confidence in ("high", "medium", "low")
        assert f.evidence_chain.confidence == f.confidence

    @pytest.mark.asyncio
    async def test_account_takeover_evidence(self, user1):
        """Persisted credential-field foreign mutation -> BOLA_ACCOUNT_TAKEOVER (Req 27.4, 27.6)."""
        endpoint = "https://api.example.com/users/1"
        store = {
            "https://api.example.com/users/1": {"id": 1, "email": "me@example.com"},
            "https://api.example.com/users/2": {"id": 2, "email": "victim@example.com"},
        }
        engine = StatefulHTTPEngine(store)
        module = BOLATestingModule(_write_config(), engine, [user1])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_write_bola(identifier, "2", [user1])

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_ACCOUNT_TAKEOVER"
        assert f.owasp_category == "API1"
        assert f.severity.value == "CRITICAL"
        assert "email" in f.evidence
        # Req 33.3: the submitted credential value is redacted in the evidence,
        # never echoed verbatim.
        assert "<redacted>" in f.evidence
        assert "attacker.bola@evil.example" not in f.evidence
        assert isinstance(f.evidence_chain, EvidenceChain)
        assert f.evidence_chain.method == "PATCH"

    @pytest.mark.asyncio
    async def test_state_manipulation_evidence(self, user1):
        """Chained unauthorized-access + persisted privileged field -> BOLA_STATE_MANIPULATION (Req 32.4, 32.5)."""
        endpoint = "https://api.example.com/users/1"
        store = {
            "https://api.example.com/users/1": {"id": 1, "owner_id": 1},
            "https://api.example.com/users/2": {"id": 2, "owner_id": 999},
        }
        engine = StatefulHTTPEngine(store)
        module = BOLATestingModule(_write_config(), engine, [user1])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_chained_state_manipulation(identifier, "2", [user1])

        assert len(findings) >= 1
        f = findings[0]
        # Req 32.4/32.5: classified as BOLA_STATE_MANIPULATION within {API1, API3}.
        assert f.category == "BOLA_STATE_MANIPULATION"
        assert f.owasp_category in ("API1", "API3")
        assert f.severity.value == "CRITICAL"
        assert "'2'" in f.evidence  # substituted victim id
        # Evidence records both unauthorized access and the state transition.
        assert "access" in f.evidence.lower()
        assert isinstance(f.evidence_chain, EvidenceChain)
        assert f.evidence_chain.substituted_id == "2"

    @pytest.mark.asyncio
    async def test_broken_object_relationship_evidence(self, user1):
        """Foreign child under own parent (non-tenant) -> BOLA_BROKEN_OBJECT_RELATIONSHIP (Req 29.3)."""
        endpoint = "https://api.example.com/orders/10/items/5"
        store = {
            # baseline (invalid child id 0) is absent -> 404 -> discriminating
            "https://api.example.com/orders/10/items/5": {"id": 5, "owner_id": 1},
            "https://api.example.com/orders/10/items/7": {"id": 7, "owner_id": 999},
        }
        engine = StatefulHTTPEngine(store)
        module = BOLATestingModule(_write_config(enable_composite=True), engine, [user1])

        composites = module._discover_composite_identifiers(
            [MockEndpoint(endpoint)]
        )
        findings = await module._test_composite_bola(composites)

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_BROKEN_OBJECT_RELATIONSHIP"
        assert f.owasp_category == "API1"
        # Evidence preserves the parent id and names the substituted child.
        assert "order_id" in f.evidence and "10" in f.evidence
        assert "7" in f.evidence
        assert isinstance(f.evidence_chain, EvidenceChain)
        assert f.evidence_chain.substituted_id == "7"

    @pytest.mark.asyncio
    async def test_cross_tenant_evidence(self, user1):
        """Foreign child under own tenant parent -> BOLA_CROSS_TENANT (Req 29.4)."""
        endpoint = "https://api.example.com/tenants/10/projects/5"
        store = {
            "https://api.example.com/tenants/10/projects/5": {"id": 5, "owner_id": 1},
            "https://api.example.com/tenants/10/projects/7": {"id": 7, "owner_id": 999},
        }
        engine = StatefulHTTPEngine(store)
        module = BOLATestingModule(_write_config(enable_composite=True), engine, [user1])

        composites = module._discover_composite_identifiers([MockEndpoint(endpoint)])
        findings = await module._test_composite_bola(composites)

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_CROSS_TENANT"
        assert f.owasp_category == "API1"
        assert "tenant_id" in f.evidence
        assert isinstance(f.evidence_chain, EvidenceChain)

    @pytest.mark.asyncio
    async def test_id_leakage_evidence(self):
        """Harvested id accessible under anonymous context -> BOLA_ID_LEAKAGE (Req 30.2, 30.3)."""
        endpoint = "https://api.example.com/users/1"
        store = {
            "https://api.example.com/users/2": {"id": 2, "name": "foreign"},
        }
        engine = StatefulHTTPEngine(store)
        # An anonymous (privilege 0) context forces anonymous replay of the
        # harvested id (Req 30.2).
        anon = AuthContext(name="anonymous", type=AuthType.BEARER,
                           token="", privilege_level=0)
        module = BOLATestingModule(_write_config(enable_id_leakage=True), engine, [anon])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_id_leakage({"2"}, [identifier])

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_ID_LEAKAGE"
        assert f.owasp_category == "API1"
        assert f.severity.value == "MEDIUM"
        # Evidence names the harvested id and the probing context.
        assert "'2'" in f.evidence
        assert "anonymous" in f.evidence
        assert isinstance(f.evidence_chain, EvidenceChain)
        assert f.evidence_chain.substituted_id == "2"

    def test_predictable_identifier_evidence(self):
        """Sequential harvested ids -> BOLA_PREDICTABLE_IDENTIFIER (Req 30.4-30.6)."""
        engine = StatefulHTTPEngine()
        user1 = AuthContext(name="user1", type=AuthType.BEARER,
                            token="t", privilege_level=1)
        module = BOLATestingModule(_write_config(), engine, [user1])

        findings = module._test_identifier_predictability({"1", "2", "3", "4"})

        assert len(findings) == 1
        f = findings[0]
        assert f.category == "BOLA_PREDICTABLE_IDENTIFIER"
        assert f.owasp_category == "API1"
        assert "sequential-integer" in f.evidence
        assert isinstance(f.evidence_chain, EvidenceChain)

    def test_predictable_identifier_uuidv4_no_finding(self):
        """A random UUIDv4 scheme yields no predictability finding (Req 30.6)."""
        engine = StatefulHTTPEngine()
        user1 = AuthContext(name="user1", type=AuthType.BEARER,
                            token="t", privilege_level=1)
        module = BOLATestingModule(_write_config(), engine, [user1])

        uuids = {
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "9f8c8b1e-1c2d-4e3f-8a9b-0c1d2e3f4a5b",
        }
        findings = module._test_identifier_predictability(uuids)

        assert findings == []


class TestBOLADryRun:
    """Dry-run records the intended probe WITHOUT issuing the request (Req 28.6)."""

    @pytest.mark.asyncio
    async def test_dry_run_records_without_issuing(self):
        endpoint = "https://api.example.com/users/1"
        store = {
            "https://api.example.com/users/1": {"id": 1, "nickname": "me"},
            "https://api.example.com/users/2": {"id": 2, "nickname": "victim"},
        }
        engine = StatefulHTTPEngine(store)
        user1 = AuthContext(name="user1", type=AuthType.BEARER,
                            token="user1_token", privilege_level=1)
        module = BOLATestingModule(_write_config(dry_run=True), engine, [user1])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_write_bola(identifier, "2", [user1])

        # No finding is produced because nothing was actually written.
        assert findings == []
        # The intended destructive probe was recorded (method, url, id, body).
        assert len(module._dry_run_records) == 1
        record = module._dry_run_records[0]
        assert record["method"] == "PATCH"
        assert record["url"] == "https://api.example.com/users/2"
        assert record["substituted_id"] == "2"
        assert record["body"] is not None
        # Crucially: no state-changing request ever reached the HTTP engine.
        assert all(m in SAFE_METHODS for m in engine.issued_methods)
        assert not any(m in STATE_CHANGING_METHODS for m in engine.issued_methods)


class TestBOLAConfigSafeDefaults:
    """BOLAConfig instantiated with no args resolves to safe defaults (Req 34.1, 34.2)."""

    def test_safe_defaults(self):
        cfg = BOLAConfig()
        assert cfg.allow_destructive is False
        # DELETE is intentionally excluded from the default destructive set.
        assert "DELETE" not in cfg.destructive_methods
        assert cfg.destructive_methods == {"PATCH", "PUT"}
        assert cfg.enable_composite is False
        assert cfg.enable_id_leakage is False
        assert cfg.verb_tampering is False
        assert cfg.parameter_pollution is False
        assert cfg.dry_run is False

    def test_select_write_method_never_returns_delete_by_default(self):
        """_select_write_method honors the safe default set (no DELETE) (Req 28.4)."""
        engine = StatefulHTTPEngine()
        user1 = AuthContext(name="user1", type=AuthType.BEARER,
                            token="t", privilege_level=1)
        module = BOLATestingModule(BOLAConfig(), engine, [user1])
        # PATCH is preferred and DELETE is never selected under the default set.
        assert module._select_write_method() == "PATCH"

    def test_destructive_gate_closed_by_default(self):
        """Default config keeps the destructive gate closed (Req 28.1, 34.4)."""
        engine = StatefulHTTPEngine()
        user1 = AuthContext(name="user1", type=AuthType.BEARER,
                            token="t", privilege_level=1)
        module = BOLATestingModule(BOLAConfig(), engine, [user1])
        assert module._destructive_allowed() is False


class TestBOLALegacyYAMLLoading:
    """Legacy YAML omitting advanced fields loads with safe defaults (Req 34.5)."""

    def test_legacy_config_dict_loads_with_safe_defaults(self):
        from core.config import ConfigurationManager

        # A legacy owasp_testing.bola_testing block that predates the advanced
        # fields - only the original keys are present.
        config_dict = {
            "target": {"base_url": "https://api.example.com"},
            "owasp_testing": {
                "bola_testing": {
                    "enabled": True,
                    "id_patterns": ["sequential", "guid"],
                    "test_contexts": ["anonymous", "user"],
                }
            },
        }

        loaded = ConfigurationManager().load_config_from_dict(config_dict)
        bola = loaded.owasp_testing.bola_testing

        # No error, and every advanced field resolves to its safe default.
        assert bola.allow_destructive is False
        assert bola.destructive_methods == {"PATCH", "PUT"}
        assert bola.enable_composite is False
        assert bola.enable_id_leakage is False
        assert bola.verb_tampering is False
        assert bola.parameter_pollution is False
        assert bola.dry_run is False

    def test_config_without_bola_block_loads_with_safe_defaults(self):
        from core.config import ConfigurationManager

        loaded = ConfigurationManager().load_config_from_dict(
            {"target": {"base_url": "https://api.example.com"}}
        )
        bola = loaded.owasp_testing.bola_testing
        assert bola.allow_destructive is False
        assert "DELETE" not in bola.destructive_methods


class TestBOLACLIThreading:
    """CLI flags thread into the constructed BOLAConfig (Req 34.3, 34.4)."""

    class _ShortCircuit(Exception):
        pass

    def _capture_config(self, args):
        """Invoke ``full`` and return the config_dict handed to the loader."""
        from unittest.mock import patch
        from click.testing import CliRunner
        import apileaks
        from apileaks import cli

        captured = {}

        def _capture(self, config_dict):
            captured["config_dict"] = config_dict
            raise TestBOLACLIThreading._ShortCircuit()

        runner = CliRunner()
        with patch.object(
            apileaks.ConfigurationManager, "load_config_from_dict", _capture
        ):
            runner.invoke(
                cli,
                ["--no-banner", "full", "--target", "https://api.example.com", *args],
            )
        return captured.get("config_dict")

    def test_no_flags_preserves_readonly_defaults(self):
        """Without advanced flags, BOLAConfig loads read-only safe defaults (Req 34.4)."""
        from core.config import ConfigurationManager

        config_dict = self._capture_config([])
        assert config_dict is not None
        bola = ConfigurationManager().load_config_from_dict(config_dict).owasp_testing.bola_testing
        assert bola.allow_destructive is False
        assert bola.enable_composite is False
        assert bola.enable_id_leakage is False
        assert bola.dry_run is False

    def test_allow_write_bola_sets_allow_destructive(self):
        """--allow-write-bola threads into allow_destructive=True (Req 34.3)."""
        from core.config import ConfigurationManager

        config_dict = self._capture_config([
            "--allow-write-bola",
            "--bola-composite",
            "--bola-id-leakage",
            "--bola-verb-tampering",
            "--bola-parameter-pollution",
            "--bola-dry-run",
            "--bola-destructive-methods", "patch,put,delete",
        ])
        assert config_dict is not None
        bola = ConfigurationManager().load_config_from_dict(config_dict).owasp_testing.bola_testing

        assert bola.allow_destructive is True
        assert bola.enable_composite is True
        assert bola.enable_id_leakage is True
        assert bola.verb_tampering is True
        assert bola.parameter_pollution is True
        assert bola.dry_run is True
        # Comma-separated methods are parsed and uppercased into the set.
        assert bola.destructive_methods == {"PATCH", "PUT", "DELETE"}


# ===========================================================================
# Typed-payload consumption in write BOLA probes (Task 45.2, Reqs 52.1, 52.4,
# 52.5, 56.3, 56.4, 56.5).
# ===========================================================================

from utils.spec_import import SpecSchema, SpecOperation


class TestWriteBOLATypedPayload:
    """`_test_write_bola` starts the mutation body from a schema-valid
    Typed_Payload when a Spec_Schema declares the operation, and falls back to
    the existing minimal body otherwise."""

    @pytest.fixture
    def user1(self):
        return AuthContext(name="user1", type=AuthType.BEARER,
                           token="user1_token", privilege_level=1)

    @pytest.mark.asyncio
    async def test_write_body_uses_typed_payload_when_schema_present(self, user1):
        """The victim mutation body includes schema-required fields plus the
        mutated field when the Spec_Schema declares the operation (Req 52.1)."""
        endpoint = "https://api.example.com/users/1"
        victim_url = "https://api.example.com/users/2"
        store = {
            endpoint: {"id": 1, "nickname": "me"},
            victim_url: {"id": 2, "nickname": "victim"},
        }
        engine = StatefulHTTPEngine(store)

        # Declare the PATCH operation (selected write method) with a required
        # field that is NOT one of the mutated candidate fields.
        schema = SpecSchema(operations=[
            SpecOperation(
                path=endpoint,
                method="PATCH",
                request_body_schema={
                    "type": "object",
                    "required": ["display_name"],
                    "properties": {
                        "display_name": {"type": "string"},
                        "nickname": {"type": "string"},
                    },
                },
            )
        ])

        module = BOLATestingModule(_write_config(), engine, [user1],
                                   spec_schema=schema)

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        await module._test_write_bola(identifier, "2", [user1])

        # Find the state-changing write body issued against the victim URL.
        write_bodies = [
            body for (m, url, body) in engine.calls
            if m == "PATCH" and url == victim_url and isinstance(body, dict)
        ]
        assert write_bodies, "expected a PATCH write against the victim object"
        body = write_bodies[0]
        # Schema-required field is present (Typed_Payload base) ...
        assert "display_name" in body
        # ... and the mutated candidate field override is applied on top.
        assert "nickname" in body

    @pytest.mark.asyncio
    async def test_write_body_falls_back_when_no_schema(self, user1):
        """Without a Spec_Schema, the write body is the existing minimal
        {field: mutated_value} body (Req 52.6)."""
        endpoint = "https://api.example.com/users/1"
        victim_url = "https://api.example.com/users/2"
        store = {
            endpoint: {"id": 1, "nickname": "me"},
            victim_url: {"id": 2, "nickname": "victim"},
        }
        engine = StatefulHTTPEngine(store)

        module = BOLATestingModule(_write_config(), engine, [user1])

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        await module._test_write_bola(identifier, "2", [user1])

        write_bodies = [
            body for (m, url, body) in engine.calls
            if m == "PATCH" and url == victim_url and isinstance(body, dict)
        ]
        assert write_bodies, "expected a PATCH write against the victim object"
        # The minimal body only carries the mutated candidate field(s); no
        # schema-injected fields appear.
        assert all(set(body.keys()) == {"nickname"} for body in write_bodies)

    @pytest.mark.asyncio
    async def test_typed_payload_never_issued_under_safe_mode(self, user1):
        """Even with a Spec_Schema, Safe_Mode issues no state-changing write
        (Reqs 52.4, 56.5)."""
        endpoint = "https://api.example.com/users/1"
        store = {
            endpoint: {"id": 1, "nickname": "me"},
            "https://api.example.com/users/2": {"id": 2, "nickname": "victim"},
        }
        engine = StatefulHTTPEngine(store)

        schema = SpecSchema(operations=[
            SpecOperation(
                path=endpoint,
                method="PATCH",
                request_body_schema={
                    "type": "object",
                    "required": ["display_name"],
                    "properties": {"display_name": {"type": "string"}},
                },
            )
        ])

        # Safe_Mode on -> destructive gate closed, no write issued.
        module = BOLATestingModule(
            _write_config(safe_mode=True), engine, [user1], spec_schema=schema
        )

        identifier = ObjectIdentifier(
            value="1", type="sequential", endpoint=endpoint,
            parameter_name="user_id", location="path",
        )

        findings = await module._test_write_bola(identifier, "2", [user1])

        assert findings == []
        assert all(m in SAFE_METHODS for m in engine.issued_methods)


# ===========================================================================
# Spec-driven path-parameter slot selection (Requirement 53)
# ===========================================================================

from utils.spec_import import SpecParameter as _SpecParameter


def _bola_module_for_spec(spec_schema=None):
    """Build a BOLA module with a mock HTTP client for pure-function tests."""
    client = Mock(spec=HTTPRequestEngine)
    client.request = AsyncMock()
    client.set_auth_context = Mock()
    user1 = AuthContext(name="user1", type=AuthType.BEARER,
                        token="t", privilege_level=1)
    return BOLATestingModule(
        BOLAConfig(enabled=True, id_patterns=["sequential", "guid", "uuid"]),
        client, [user1], spec_schema=spec_schema,
    )


class TestSpecDrivenIdentifierTargeting:
    """`_spec_path_slots` / `_identifier_from_spec` select the declared path
    slot and reuse the existing `_substitute_identifier` mechanics unchanged
    (Requirements 53.1, 53.2, 53.3, 53.4)."""

    def test_spec_path_slots_returns_only_path_params_in_path_order(self):
        """Declared path parameters are returned in left-to-right path order,
        query/header parameters are excluded (Req 53.1)."""
        op = SpecOperation(
            path="/tenants/{tenant_id}/projects/{project_id}",
            method="GET",
            parameters=[
                # Declared out of path order and mixed with a query param.
                _SpecParameter(name="project_id", location="path"),
                _SpecParameter(name="verbose", location="query"),
                _SpecParameter(name="tenant_id", location="path"),
            ],
        )
        module = _bola_module_for_spec()

        slots = module._spec_path_slots(op)

        assert [s.name for s in slots] == ["tenant_id", "project_id"]

    def test_spec_path_slots_empty_when_no_path_param(self):
        """No declared path parameter -> empty list -> regex fallback (Req 53.2)."""
        op = SpecOperation(
            path="/accounts",
            method="GET",
            parameters=[_SpecParameter(name="verbose", location="query")],
        )
        module = _bola_module_for_spec()

        assert module._spec_path_slots(op) == []

    def test_identifier_from_spec_targets_declared_slot(self):
        """The identifier carries the declared parameter name and the concrete
        value at that `{param}` position (Req 53.1)."""
        op = SpecOperation(
            path="/users/{id}",
            method="GET",
            parameters=[_SpecParameter(name="id", location="path")],
        )
        module = _bola_module_for_spec()

        endpoint = "https://api.example.com/users/42"
        identifier = module._identifier_from_spec(op, endpoint)

        assert identifier is not None
        assert identifier.location == "path"
        assert identifier.parameter_name == "id"
        assert identifier.value == "42"
        assert identifier.endpoint == endpoint

    def test_identifier_from_spec_returns_none_without_path_param(self):
        """No declared path parameter -> None so the caller uses regex inference
        (Req 53.2)."""
        op = SpecOperation(
            path="/accounts",
            method="GET",
            parameters=[_SpecParameter(name="verbose", location="query")],
        )
        module = _bola_module_for_spec()

        assert module._identifier_from_spec(op, "https://api.example.com/accounts") is None

    def test_substitution_preserves_other_segments_and_query(self):
        """Feeding the spec identifier to the EXISTING `_substitute_identifier`
        replaces only the targeted slot; other segments and query preserved
        (Req 53.3)."""
        op = SpecOperation(
            path="/users/{id}",
            method="GET",
            parameters=[_SpecParameter(name="id", location="path")],
        )
        module = _bola_module_for_spec()

        endpoint = "https://api.example.com/v1/users/42?expand=true"
        identifier = module._identifier_from_spec(op, endpoint)
        assert identifier is not None
        assert identifier.value == "42"

        substituted = module._substitute_identifier(identifier, "99")
        assert substituted == "https://api.example.com/v1/users/99?expand=true"

    def test_multi_slot_targets_one_slot_preserving_others(self):
        """A multi-slot operation substitutes only the targeted slot and
        preserves the other declared slot's value (Req 53.4)."""
        op = SpecOperation(
            path="/tenants/{tenant_id}/projects/{project_id}",
            method="GET",
            parameters=[
                _SpecParameter(name="tenant_id", location="path"),
                _SpecParameter(name="project_id", location="path"),
            ],
        )
        module = _bola_module_for_spec()
        endpoint = "https://api.example.com/tenants/42/projects/7"

        # Target the parent slot (slot_index=0): only tenant_id changes.
        parent = module._identifier_from_spec(op, endpoint, slot_index=0)
        assert parent is not None and parent.value == "42"
        assert parent.parameter_name == "tenant_id"
        assert module._substitute_identifier(parent, "100") == \
            "https://api.example.com/tenants/100/projects/7"

        # Target the child slot (slot_index=1): only project_id changes.
        child = module._identifier_from_spec(op, endpoint, slot_index=1)
        assert child is not None and child.value == "7"
        assert child.parameter_name == "project_id"
        assert module._substitute_identifier(child, "9") == \
            "https://api.example.com/tenants/42/projects/9"

    def test_identifier_from_spec_out_of_range_slot_index(self):
        """An out-of-range slot_index returns None (regex fallback, Req 53.2)."""
        op = SpecOperation(
            path="/users/{id}",
            method="GET",
            parameters=[_SpecParameter(name="id", location="path")],
        )
        module = _bola_module_for_spec()
        endpoint = "https://api.example.com/users/42"

        assert module._identifier_from_spec(op, endpoint, slot_index=5) is None
