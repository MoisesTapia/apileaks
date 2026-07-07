"""
tests/test_aws_security_hub.py
Tests for ci-cd/scripts/aws_security_hub.py

Requirements: 5.5
"""

import os
import sys
import unittest
from datetime import datetime
from unittest.mock import MagicMock, call, patch

# ---------------------------------------------------------------------------
# Import path — ci-cd/scripts uses a hyphen so we inject the path manually.
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "ci-cd", "scripts"),
)

from aws_security_hub import SecurityHubPublisher  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_ACCOUNT_ID = "123456789012"
_PRODUCT_ARN = "arn:aws:securityhub:us-east-1:123456789012:product/apileaks/apileaks"
_PIPELINE_ID = "exec-abc123"


def _make_publisher(mock_boto_client=None):
    """Return a SecurityHubPublisher with its boto3 client replaced by a mock."""
    with patch("boto3.client") as mock_ctor:
        if mock_boto_client is not None:
            mock_ctor.return_value = mock_boto_client
        pub = SecurityHubPublisher(
            region=_REGION,
            account_id=_ACCOUNT_ID,
            product_arn=_PRODUCT_ARN,
        )
    return pub, mock_ctor


def _make_finding(
    fid="finding-001",
    severity="HIGH",
    category="JWT_WEAK_SECRET",
    endpoint="/api/v1/login",
    evidence="Weak secret detected in JWT",
    timestamp="2024-01-15T10:30:00Z",
):
    return {
        "id": fid,
        "severity": severity,
        "category": category,
        "endpoint": endpoint,
        "evidence": evidence,
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# Unit tests — finding_to_asff field mapping
# ---------------------------------------------------------------------------


class TestFindingToAsff(unittest.TestCase):
    """Verify that ALL required ASFF fields are mapped correctly."""

    def setUp(self):
        with patch("boto3.client"):
            self.pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )
        self.finding = _make_finding()
        self.asff = self.pub.finding_to_asff(self.finding, _PIPELINE_ID)

    def test_schema_version(self):
        self.assertEqual(self.asff["SchemaVersion"], "2018-10-08")

    def test_id_contains_product_arn_and_finding_id(self):
        self.assertIn(_PRODUCT_ARN, self.asff["Id"])
        self.assertIn("finding-001", self.asff["Id"])

    def test_product_arn(self):
        self.assertEqual(self.asff["ProductArn"], _PRODUCT_ARN)

    def test_generator_id(self):
        self.assertEqual(self.asff["GeneratorId"], "apileaks-ci-cd")

    def test_aws_account_id(self):
        self.assertEqual(self.asff["AwsAccountId"], _ACCOUNT_ID)

    def test_types_is_nonempty_list(self):
        self.assertIsInstance(self.asff["Types"], list)
        self.assertTrue(len(self.asff["Types"]) > 0)

    def test_created_at_is_iso8601(self):
        # Must be parseable and follow YYYY-MM-DDTHH:MM:SSZ format
        ts = self.asff["CreatedAt"]
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def test_updated_at_is_iso8601(self):
        ts = self.asff["UpdatedAt"]
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def test_severity_label_high(self):
        self.assertEqual(self.asff["Severity"]["Label"], "HIGH")

    def test_title_is_category(self):
        self.assertEqual(self.asff["Title"], "JWT_WEAK_SECRET")

    def test_description_is_evidence(self):
        self.assertEqual(self.asff["Description"], "Weak secret detected in JWT")

    def test_resources_contains_endpoint(self):
        resources = self.asff["Resources"]
        self.assertIsInstance(resources, list)
        self.assertGreater(len(resources), 0)
        resource = resources[0]
        self.assertIn("Type", resource)
        self.assertIn("Id", resource)
        self.assertEqual(resource["Id"], "/api/v1/login")


class TestSeverityMapping(unittest.TestCase):
    """Verify all severity values map correctly to ASFF labels."""

    def setUp(self):
        with patch("boto3.client"):
            self.pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

    def _label(self, sev):
        finding = _make_finding(severity=sev)
        asff = self.pub.finding_to_asff(finding)
        return asff["Severity"]["Label"]

    def test_critical(self):
        self.assertEqual(self._label("CRITICAL"), "CRITICAL")

    def test_high(self):
        self.assertEqual(self._label("HIGH"), "HIGH")

    def test_medium(self):
        self.assertEqual(self._label("MEDIUM"), "MEDIUM")

    def test_low(self):
        self.assertEqual(self._label("LOW"), "LOW")

    def test_info(self):
        self.assertEqual(self._label("INFO"), "INFORMATIONAL")

    def test_informational(self):
        self.assertEqual(self._label("INFORMATIONAL"), "INFORMATIONAL")

    def test_unknown_severity_defaults_to_informational(self):
        self.assertEqual(self._label("UNKNOWN_VALUE"), "INFORMATIONAL")


class TestDescriptionTruncation(unittest.TestCase):
    """Verify long evidence strings are truncated to 1024 chars."""

    def setUp(self):
        with patch("boto3.client"):
            self.pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

    def test_description_truncated_at_1024(self):
        long_evidence = "A" * 2000
        finding = _make_finding(evidence=long_evidence)
        asff = self.pub.finding_to_asff(finding)
        self.assertEqual(len(asff["Description"]), 1024)

    def test_description_not_truncated_when_short(self):
        short_evidence = "Short evidence"
        finding = _make_finding(evidence=short_evidence)
        asff = self.pub.finding_to_asff(finding)
        self.assertEqual(asff["Description"], short_evidence)

    def test_description_exactly_1024_not_truncated(self):
        exact_evidence = "B" * 1024
        finding = _make_finding(evidence=exact_evidence)
        asff = self.pub.finding_to_asff(finding)
        self.assertEqual(len(asff["Description"]), 1024)


class TestTimestampHandling(unittest.TestCase):
    """Verify timestamp handling for missing/invalid values."""

    def setUp(self):
        with patch("boto3.client"):
            self.pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

    def test_uses_finding_timestamp_when_present(self):
        finding = _make_finding(timestamp="2024-06-01T12:00:00Z")
        asff = self.pub.finding_to_asff(finding)
        self.assertEqual(asff["CreatedAt"], "2024-06-01T12:00:00Z")

    def test_falls_back_to_utcnow_when_timestamp_absent(self):
        finding = _make_finding()
        del finding["timestamp"]
        asff = self.pub.finding_to_asff(finding)
        # Should be a valid ISO 8601 UTC string
        datetime.strptime(asff["CreatedAt"], "%Y-%m-%dT%H:%M:%SZ")

    def test_falls_back_to_utcnow_when_timestamp_none(self):
        finding = _make_finding()
        finding["timestamp"] = None
        asff = self.pub.finding_to_asff(finding)
        datetime.strptime(asff["CreatedAt"], "%Y-%m-%dT%H:%M:%SZ")

    def test_falls_back_to_utcnow_when_timestamp_invalid(self):
        finding = _make_finding(timestamp="not-a-date")
        asff = self.pub.finding_to_asff(finding)
        datetime.strptime(asff["CreatedAt"], "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Unit tests — publish_findings batching
# ---------------------------------------------------------------------------


class TestPublishFindingsBatching(unittest.TestCase):
    """Verify BatchImportFindings is called in batches of max 100."""

    def _make_publisher_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.batch_import_findings.return_value = {
            "SuccessCount": 100,
            "FailedCount": 0,
            "FailedFindings": [],
        }
        with patch("boto3.client", return_value=mock_client):
            pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )
        return pub, mock_client

    def test_single_batch_for_less_than_100(self):
        """50 findings → exactly 1 call to BatchImportFindings."""
        pub, mock_client = self._make_publisher_with_mock_client()
        findings = [_make_finding(fid=f"f-{i}") for i in range(50)]
        pub.publish_findings(findings, _PIPELINE_ID)
        self.assertEqual(mock_client.batch_import_findings.call_count, 1)

    def test_single_batch_for_exactly_100(self):
        """100 findings → exactly 1 call."""
        pub, mock_client = self._make_publisher_with_mock_client()
        findings = [_make_finding(fid=f"f-{i}") for i in range(100)]
        pub.publish_findings(findings, _PIPELINE_ID)
        self.assertEqual(mock_client.batch_import_findings.call_count, 1)

    def test_three_batches_for_250_findings(self):
        """250 findings → 3 calls (100 + 100 + 50)."""
        pub, mock_client = self._make_publisher_with_mock_client()
        mock_client.batch_import_findings.return_value = {
            "SuccessCount": 50,
            "FailedCount": 0,
            "FailedFindings": [],
        }
        findings = [_make_finding(fid=f"f-{i}") for i in range(250)]
        pub.publish_findings(findings, _PIPELINE_ID)
        self.assertEqual(mock_client.batch_import_findings.call_count, 3)

    def test_first_batch_has_100_findings(self):
        """First batch call receives exactly 100 ASFF findings."""
        pub, mock_client = self._make_publisher_with_mock_client()
        findings = [_make_finding(fid=f"f-{i}") for i in range(150)]
        pub.publish_findings(findings, _PIPELINE_ID)
        first_call_kwargs = mock_client.batch_import_findings.call_args_list[0]
        # Can be called with positional or keyword args
        batch_sent = (
            first_call_kwargs[1].get("Findings")
            or first_call_kwargs[0][0]
        )
        self.assertEqual(len(batch_sent), 100)

    def test_second_batch_has_remaining_findings(self):
        """Second batch call receives the remaining 50 findings (150 total)."""
        pub, mock_client = self._make_publisher_with_mock_client()
        findings = [_make_finding(fid=f"f-{i}") for i in range(150)]
        pub.publish_findings(findings, _PIPELINE_ID)
        second_call_kwargs = mock_client.batch_import_findings.call_args_list[1]
        batch_sent = (
            second_call_kwargs[1].get("Findings")
            or second_call_kwargs[0][0]
        )
        self.assertEqual(len(batch_sent), 50)

    def test_no_call_when_findings_empty(self):
        """Empty findings list → zero calls to BatchImportFindings."""
        pub, mock_client = self._make_publisher_with_mock_client()
        pub.publish_findings([], _PIPELINE_ID)
        mock_client.batch_import_findings.assert_not_called()

    def test_correct_batch_count_for_various_sizes(self):
        """Parameterised batch count verification."""
        cases = [
            (1, 1),
            (99, 1),
            (100, 1),
            (101, 2),
            (200, 2),
            (201, 3),
            (300, 3),
        ]
        for n_findings, expected_calls in cases:
            with self.subTest(n=n_findings):
                pub, mock_client = self._make_publisher_with_mock_client()
                findings = [_make_finding(fid=f"f-{i}") for i in range(n_findings)]
                pub.publish_findings(findings, _PIPELINE_ID)
                self.assertEqual(
                    mock_client.batch_import_findings.call_count,
                    expected_calls,
                    f"Expected {expected_calls} call(s) for {n_findings} findings",
                )


# ---------------------------------------------------------------------------
# Unit tests — error handling: BatchImportFindings failure
# ---------------------------------------------------------------------------


class TestPublishFindingsErrorHandling(unittest.TestCase):
    """Verify that a BatchImportFindings error is logged but does not stop processing."""

    def test_error_in_first_batch_continues_with_second(self):
        """
        If the first batch raises an exception, the second batch must still
        be submitted and BatchImportFindings must be called twice total.
        """
        mock_client = MagicMock()
        mock_client.batch_import_findings.side_effect = [
            Exception("Simulated AWS error"),
            {"SuccessCount": 50, "FailedCount": 0, "FailedFindings": []},
        ]

        with patch("boto3.client", return_value=mock_client):
            pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

        findings = [_make_finding(fid=f"f-{i}") for i in range(150)]

        # Must NOT raise even though the first batch fails
        pub.publish_findings(findings, _PIPELINE_ID)

        # Both batches were attempted
        self.assertEqual(mock_client.batch_import_findings.call_count, 2)

    def test_error_does_not_raise_exception(self):
        """A boto3 error in any batch must not propagate as an exception."""
        mock_client = MagicMock()
        mock_client.batch_import_findings.side_effect = RuntimeError("AWS unavailable")

        with patch("boto3.client", return_value=mock_client):
            pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

        findings = [_make_finding(fid="f-1")]

        # This must complete without raising
        try:
            pub.publish_findings(findings, _PIPELINE_ID)
        except Exception as exc:
            self.fail(f"publish_findings raised unexpectedly: {exc}")

    def test_error_is_logged(self):
        """A boto3 error must be logged at ERROR level."""
        mock_client = MagicMock()
        mock_client.batch_import_findings.side_effect = Exception("Simulated failure")

        with patch("boto3.client", return_value=mock_client):
            pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

        findings = [_make_finding(fid="f-1")]

        import logging

        with self.assertLogs("aws_security_hub", level=logging.ERROR) as cm:
            pub.publish_findings(findings, _PIPELINE_ID)

        self.assertTrue(
            any("error" in line.lower() or "Error" in line for line in cm.output),
            f"Expected an error log entry, got: {cm.output}",
        )

    def test_all_batches_still_called_when_every_batch_fails(self):
        """All three batches (for 250 findings) must be attempted even if all fail."""
        mock_client = MagicMock()
        mock_client.batch_import_findings.side_effect = Exception("Always fails")

        with patch("boto3.client", return_value=mock_client):
            pub = SecurityHubPublisher(
                region=_REGION,
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )

        findings = [_make_finding(fid=f"f-{i}") for i in range(250)]
        pub.publish_findings(findings, _PIPELINE_ID)

        self.assertEqual(mock_client.batch_import_findings.call_count, 3)


# ---------------------------------------------------------------------------
# Unit tests — boto3 client initialisation
# ---------------------------------------------------------------------------


class TestInitialisation(unittest.TestCase):
    """Verify the boto3 client is created with the correct region."""

    def test_boto3_client_called_with_securityhub_and_region(self):
        with patch("boto3.client") as mock_ctor:
            mock_ctor.return_value = MagicMock()
            SecurityHubPublisher(
                region="eu-west-1",
                account_id=_ACCOUNT_ID,
                product_arn=_PRODUCT_ARN,
            )
        mock_ctor.assert_called_once_with("securityhub", region_name="eu-west-1")

    def test_attributes_stored_correctly(self):
        with patch("boto3.client") as mock_ctor:
            mock_ctor.return_value = MagicMock()
            pub = SecurityHubPublisher(
                region="ap-southeast-1",
                account_id="999888777666",
                product_arn="arn:aws:securityhub:ap-southeast-1:999888777666:product/x/y",
            )
        self.assertEqual(pub.region, "ap-southeast-1")
        self.assertEqual(pub.account_id, "999888777666")
        self.assertEqual(
            pub.product_arn,
            "arn:aws:securityhub:ap-southeast-1:999888777666:product/x/y",
        )


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
