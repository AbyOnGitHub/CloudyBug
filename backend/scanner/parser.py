"""
Parser module for AWS Security Finding Format (ASFF).
Converts raw ASFF findings into:
1. Normalized JSON objects for API consumption (NormalizedFinding)
2. Simplified, high-density JSON objects optimized for LLM reasoning (LLMReasoningFinding)
"""

import json
import uuid
import re
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Union, Optional
from pathlib import Path
from pydantic import BaseModel, Field, field_validator

from backend.scanner.models import (
    ASFFFinding,
    NormalizedFinding,
    SeverityLevel,
    ComplianceStatus,
    ScanSummary,
)

# ==============================================================================
# 1. Pydantic Models & Enums for LLM Reasoning Objects
# Re-exported from backend.scanner.llm_parser for unified module access
# ==============================================================================
from backend.scanner.llm_parser import (
    LLMSeverityLevel,
    PriorityTier,
    RiskCategory,
    LLMComplianceStatus,
    LLMSeverity,
    LLMResourceMetadata,
    LLMRemediation,
    LLMTimestamps,
    LLMReasoningFinding,
    LLMASFFParser,
)


# ==============================================================================
# 2. Standard ASFFParser (General Normalization)
# ==============================================================================

class ASFFParser:
    """
    Parser and normalizer for AWS Security Finding Format (ASFF) JSON data.
    Converts raw ASFF finding dictionaries or Prowler json-asff outputs into
    strongly-typed, normalized JSON objects.
    """

    @staticmethod
    def parse_finding(raw: Union[Dict[str, Any], ASFFFinding]) -> NormalizedFinding:
        """Extract and normalize the core required fields from a single ASFF finding."""
        if isinstance(raw, ASFFFinding):
            raw_dict = raw.model_dump()
        elif isinstance(raw, dict):
            raw_dict = raw
        else:
            raise TypeError(f"Unsupported finding type: {type(raw)}")

        raw_id = raw_dict.get("Id", "")
        finding_id = raw_id if raw_id else f"asff-{uuid.uuid4().hex[:12]}"
        internal_id = f"norm-{uuid.uuid4().hex[:8]}"

        raw_severity = raw_dict.get("Severity", {})
        if isinstance(raw_severity, dict):
            label_str = raw_severity.get("Label", "INFORMATIONAL")
            normalized_score = raw_severity.get("Normalized", 0)
        else:
            label_str = str(raw_severity)
            normalized_score = 0

        try:
            severity = SeverityLevel(label_str.upper())
        except (ValueError, AttributeError):
            severity = SeverityLevel.INFORMATIONAL

        if not normalized_score:
            score_map = {
                SeverityLevel.CRITICAL: 90,
                SeverityLevel.HIGH: 70,
                SeverityLevel.MEDIUM: 40,
                SeverityLevel.LOW: 20,
                SeverityLevel.INFORMATIONAL: 0,
            }
            normalized_score = score_map.get(severity, 0)

        resources = raw_dict.get("Resources", [])
        if resources and isinstance(resources, list) and len(resources) > 0:
            first_resource = resources[0]
            resource_id = first_resource.get("Id", "unknown-resource")
            resource_type = first_resource.get("Type", "AwsUnknownResource")
            region = first_resource.get("Region", raw_dict.get("Region", "us-east-1"))
        else:
            resource_id = raw_dict.get("ResourceId", "unknown-resource")
            resource_type = raw_dict.get("ResourceType", "AwsUnknownResource")
            region = raw_dict.get("Region", "us-east-1")

        compliance_obj = raw_dict.get("Compliance", {})
        if isinstance(compliance_obj, dict):
            status_str = compliance_obj.get("Status", "NOT_AVAILABLE")
            frameworks = compliance_obj.get("RelatedRequirements", []) or []
        else:
            status_str = "NOT_AVAILABLE"
            frameworks = []

        try:
            compliance_status = ComplianceStatus(status_str.upper())
        except (ValueError, AttributeError):
            compliance_status = ComplianceStatus.NOT_AVAILABLE

        remediation_obj = raw_dict.get("Remediation", {})
        recommendation_text = ""
        recommendation_url = None

        if isinstance(remediation_obj, dict):
            rec_obj = remediation_obj.get("Recommendation", {})
            if isinstance(rec_obj, dict):
                recommendation_text = rec_obj.get("Text", "")
                recommendation_url = rec_obj.get("Url")

        if not recommendation_text:
            recommendation_text = raw_dict.get(
                "Recommendation",
                raw_dict.get("RemediationRecommendation", "Review security best practices for this resource.")
            )

        title = raw_dict.get("Title", "Security Finding")
        description = raw_dict.get("Description", "")
        account_id = raw_dict.get("AwsAccountId", "000000000000")
        generator_id = raw_dict.get("GeneratorId", "")
        created_at = raw_dict.get("CreatedAt") or raw_dict.get("FirstObservedAt") or datetime.now(timezone.utc).isoformat()

        return NormalizedFinding(
            id=internal_id,
            finding_id=finding_id,
            title=title,
            description=description,
            severity=severity,
            severity_score=normalized_score,
            resource_id=resource_id,
            resource_type=resource_type,
            region=region,
            account_id=account_id,
            compliance_status=compliance_status,
            compliance_frameworks=frameworks,
            recommendation=recommendation_text,
            recommendation_url=recommendation_url,
            generator_id=generator_id,
            created_at=created_at,
            raw_asff=raw_dict,
        )

    @classmethod
    def parse_findings(cls, raw_list: List[Union[Dict[str, Any], ASFFFinding]]) -> List[NormalizedFinding]:
        """Parse an array of ASFF findings into a list of NormalizedFinding objects."""
        normalized: List[NormalizedFinding] = []
        for item in raw_list:
            try:
                normalized.append(cls.parse_finding(item))
            except Exception:
                continue
        return normalized

    @classmethod
    def parse_asff_json_file(cls, file_path: Union[str, Path]) -> List[NormalizedFinding]:
        """Read and parse an ASFF JSON file generated by Prowler or AWS Security Hub."""
        path = Path(file_path)
        if not path.exists():
            return []

        findings_raw: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    findings_raw = data
                elif isinstance(data, dict):
                    if "Findings" in data and isinstance(data["Findings"], list):
                        findings_raw = data["Findings"]
                    else:
                        findings_raw = [data]
            except json.JSONDecodeError:
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings_raw.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        return cls.parse_findings(findings_raw)

    @staticmethod
    def filter_findings(
        findings: List[NormalizedFinding],
        severities: Optional[List[SeverityLevel]] = None,
        compliance_statuses: Optional[List[ComplianceStatus]] = None,
        resource_types: Optional[List[str]] = None,
    ) -> List[NormalizedFinding]:
        """Filter a list of findings by severity, compliance status, or resource types."""
        result = findings
        if severities:
            result = [f for f in result if f.severity in severities]
        if compliance_statuses:
            result = [f for f in result if f.compliance_status in compliance_statuses]
        if resource_types:
            result = [f for f in result if f.resource_type in resource_types]
        return result

    @staticmethod
    def summarize_findings(
        findings: List[NormalizedFinding],
        scanned_services: Optional[List[str]] = None,
        duration: float = 0.0,
    ) -> ScanSummary:
        """Compute aggregate summary metrics and security risk score from normalized findings."""
        total = len(findings)
        passed = sum(1 for f in findings if f.compliance_status == ComplianceStatus.PASSED)
        failed = sum(1 for f in findings if f.compliance_status == ComplianceStatus.FAILED)

        critical = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL and f.compliance_status == ComplianceStatus.FAILED)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH and f.compliance_status == ComplianceStatus.FAILED)
        medium = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM and f.compliance_status == ComplianceStatus.FAILED)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW and f.compliance_status == ComplianceStatus.FAILED)
        info = sum(1 for f in findings if f.severity == SeverityLevel.INFORMATIONAL)

        pass_rate = round((passed / total * 100.0), 2) if total > 0 else 100.0
        raw_risk_weight = (critical * 25.0) + (high * 15.0) + (medium * 8.0) + (low * 3.0)
        risk_score = round(min(100.0, raw_risk_weight), 2)

        return ScanSummary(
            total_findings=total,
            passed=passed,
            failed=failed,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            informational=info,
            pass_percentage=pass_rate,
            risk_score=risk_score,
            scanned_services=scanned_services or ["s3", "iam", "ec2"],
            scan_duration_seconds=round(duration, 3),
        )

    # Convenience helper to convert findings to LLM reasoning format
    @staticmethod
    def to_llm_findings(raw_list: List[Dict[str, Any]]) -> List[LLMReasoningFinding]:
        """Convenience method: convert raw ASFF list directly to LLM reasoning objects."""
        return LLMASFFParser.parse_findings(raw_list)
