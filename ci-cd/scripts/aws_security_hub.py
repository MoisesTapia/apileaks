#!/usr/bin/env python3
"""
aws_security_hub.py — AWS Security Hub publisher for APILeaks CI/CD pipelines.

Reads findings from reports/*.json in the current directory and publishes them
to AWS Security Hub using the ASFF (Amazon Security Finding Format).

Findings are sent via ``securityhub:BatchImportFindings`` in batches of at
most 100 findings per call (AWS API limit).

Env vars:
    AWS_REGION          (required) — AWS region for Security Hub client
    AWS_ACCOUNT_ID      (required) — 12-digit AWS account ID
    APILEAK_PRODUCT_ARN (required) — ARN of the registered Security Hub product
    APILEAK_PIPELINE_ID (optional, default "") — pipeline execution ID to tag findings

Requirements: 5.5
"""

import glob
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, List, Optional, Type

import boto3

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------------

_ASFF_SCHEMA_VERSION = "2018-10-08"
_GENERATOR_ID = "apileaks-ci-cd"
_FINDING_TYPES = ["Software and Configuration Checks/Vulnerabilities/CVE"]
_BATCH_SIZE = 100
_DESCRIPTION_MAX_LEN = 1024

# ASFF severity label mapping (Req 5.5)
_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
}


# -------------------------------------------------------------------------------
# SecurityHubPublisher
# -------------------------------------------------------------------------------


class SecurityHubPublisher:
    """Publishes APILeaks findings to AWS Security Hub in ASFF format."""

    def __init__(self, region: str, account_id: str, product_arn: str) -> None:
        """
        Initialise the Security Hub publisher.

        Args:
            region:      AWS region string (e.g. ``"us-east-1"``).
            account_id:  12-digit AWS account ID.
            product_arn: ARN of the registered Security Hub product.
        """
        self.region = region
        self.account_id = account_id
        self.product_arn = product_arn
        self.client = boto3.client("securityhub", region_name=region)

    # ---------------------------------------------------------------------------
    # ASFF conversion
    # ---------------------------------------------------------------------------

    def finding_to_asff(
        self,
        finding: dict[str, Any],
        pipeline_execution_id: str = "",
    ) -> dict[str, Any]:
        """
        Map an APILeaks finding dict to ASFF format.

        All required ASFF fields are populated.  The ``Description`` field is
        truncated to ``_DESCRIPTION_MAX_LEN`` characters if necessary.

        Args:
            finding:               Finding dict (deserialized from JSON report).
            pipeline_execution_id: Optional pipeline execution ID for the
                                   finding ``Id`` to make it unique per run.

        Returns:
            ASFF-formatted finding dict suitable for ``BatchImportFindings``.
        """
        finding_id = finding.get("id", "unknown")
        severity_raw = str(finding.get("severity", "")).upper()
        severity_label = _SEVERITY_MAP.get(severity_raw, "INFORMATIONAL")

        # Timestamp — use finding's timestamp when present, else UTC now
        timestamp_raw = finding.get("timestamp")
        if timestamp_raw:
            try:
                # Accept ISO strings with or without trailing Z
                ts_str = str(timestamp_raw).replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_str)
                timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Description — truncate at 1024 chars
        description = str(finding.get("evidence", "No evidence provided"))
        if len(description) > _DESCRIPTION_MAX_LEN:
            description = description[:_DESCRIPTION_MAX_LEN]

        # Unique finding ID
        suffix = f"/{pipeline_execution_id}" if pipeline_execution_id else ""
        asff_id = f"{self.product_arn}/apileaks/{finding_id}{suffix}"

        endpoint = finding.get("endpoint", "unknown")

        return {
            "SchemaVersion": _ASFF_SCHEMA_VERSION,
            "Id": asff_id,
            "ProductArn": self.product_arn,
            "GeneratorId": _GENERATOR_ID,
            "AwsAccountId": self.account_id,
            "Types": _FINDING_TYPES,
            "CreatedAt": timestamp,
            "UpdatedAt": timestamp,
            "Severity": {"Label": severity_label},
            "Title": str(finding.get("category", "APILeaks Finding")),
            "Description": description,
            "Resources": [
                {
                    "Type": "Other",
                    "Id": endpoint,
                }
            ],
        }

    # ---------------------------------------------------------------------------
    # Publishing
    # ---------------------------------------------------------------------------

    def publish_findings(
        self,
        findings: list[dict[str, Any]],
        pipeline_execution_id: str = "",
    ) -> None:
        """
        Publish a list of findings to AWS Security Hub.

        Findings are sent in batches of at most ``_BATCH_SIZE`` (100) per
        ``BatchImportFindings`` call.  If a batch call fails, the error is
        logged and processing continues with the next batch (Req 5.5).

        Args:
            findings:              List of finding dicts from JSON reports.
            pipeline_execution_id: Pipeline execution ID forwarded to
                                   ``finding_to_asff`` for unique IDs.
        """
        if not findings:
            logger.info("No findings to publish to Security Hub.")
            return

        total = len(findings)
        logger.info("Publishing %d finding(s) to AWS Security Hub…", total)

        # Slice into batches of at most _BATCH_SIZE
        for batch_start in range(0, total, _BATCH_SIZE):
            batch = findings[batch_start : batch_start + _BATCH_SIZE]
            asff_batch = [
                self.finding_to_asff(f, pipeline_execution_id) for f in batch
            ]

            # Log each finding ID in the batch
            for asff in asff_batch:
                logger.info("Publishing finding: %s", asff["Id"])

            try:
                response = self.client.batch_import_findings(Findings=asff_batch)
                failed = response.get("FailedCount", 0)
                success = response.get("SuccessCount", 0)
                logger.info(
                    "Batch [%d–%d]: %d succeeded, %d failed.",
                    batch_start + 1,
                    batch_start + len(batch),
                    success,
                    failed,
                )
                if failed and response.get("FailedFindings"):
                    for ff in response["FailedFindings"]:
                        logger.error(
                            "Failed finding %s: %s — %s",
                            ff.get("Id"),
                            ff.get("ErrorCode"),
                            ff.get("ErrorMessage"),
                        )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "BatchImportFindings error for batch [%d–%d]: %s",
                    batch_start + 1,
                    batch_start + len(batch),
                    exc,
                )
                # Continue with next batch — do not re-raise


# -------------------------------------------------------------------------------
# CLI entry point
# -------------------------------------------------------------------------------

if __name__ == "__main__":
    region = os.environ.get("AWS_REGION", "")
    account_id = os.environ.get("AWS_ACCOUNT_ID", "")
    product_arn = os.environ.get("APILEAK_PRODUCT_ARN", "")
    pipeline_id = os.environ.get("APILEAK_PIPELINE_ID", "")

    if not region:
        logger.error("AWS_REGION environment variable is not set.")
        sys.exit(1)
    if not account_id:
        logger.error("AWS_ACCOUNT_ID environment variable is not set.")
        sys.exit(1)
    if not product_arn:
        logger.error("APILEAK_PRODUCT_ARN environment variable is not set.")
        sys.exit(1)

    # Collect all findings from reports/*.json
    all_findings: list[dict] = []
    report_files = sorted(glob.glob(os.path.join("reports", "*.json")))

    if not report_files:
        logger.info("No report files found in reports/*.json — nothing to publish.")
        sys.exit(0)

    for report_path in report_files:
        try:
            with open(report_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            findings_list = data.get("findings", [])
            if isinstance(findings_list, list):
                all_findings.extend(findings_list)
                logger.info(
                    "Loaded %d finding(s) from %s", len(findings_list), report_path
                )
            else:
                logger.warning("Skipping %s — 'findings' is not an array.", report_path)
        except json.JSONDecodeError as exc:
            logger.warning("Skipping %s — JSON parse error: %s", report_path, exc)
        except OSError as exc:
            logger.warning("Skipping %s — I/O error: %s", report_path, exc)

    logger.info("Total findings collected: %d", len(all_findings))

    publisher = SecurityHubPublisher(
        region=region,
        account_id=account_id,
        product_arn=product_arn,
    )
    publisher.publish_findings(all_findings, pipeline_execution_id=pipeline_id)
