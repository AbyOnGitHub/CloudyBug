import re
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional

from backend.agents.models import (
    SanitizedCloudPayload,
    SanitizedSecurityGroup,
    SanitizedIngressRule,
    SanitizedS3Bucket,
    SanitizedIAMRole,
    InjectionDetectionResult,
)
from backend.scanner.prowler_service import ProwlerService
from backend.scanner.models import ScanRequest
from backend.core.config import settings

logger = logging.getLogger("dual_agent.quarantined_llm")

# Regular expression patterns for detecting prompt injection attacks in cloud metadata
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)", "INSTRUCTION_OVERRIDE"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)", "DISREGARD_OVERRIDE"),
    (r"(?i)you\s+are\s+now\s+(a|an|in)\s+", "ROLEPLAY_JAILBREAK"),
    (r"(?i)developer\s+mode\s+(enabled|on|activate)", "DEVELOPER_MODE_JAILBREAK"),
    (r"(?i)system\s*:\s*", "DELIMITER_INJECTION_SYSTEM"),
    (r"(?i)<\s*(system|instruction|prompt)\s*>", "TAG_INJECTION"),
    (r"(?i)(do\s+not|never)\s+(flag|report|audit|alert|remediate)\s+this", "DETECTION_BYPASS_ATTEMPT"),
    (r"(?i)mark\s+(this\s+)?(as\s+)?(safe|passed|compliant|clean)", "COMPLIANCE_GASLIGHTING"),
    (r"(?i)treat\s+(0\.0\.0\.0/0|this)\s+as\s+(internal|vpn|safe|authorized)", "RISK_MASKING_ATTEMPT"),
    (r"(?i)169\.254\.169\.254", "METADATA_EXFILTRATION_SSRF"),
    (r"(?i)(curl|wget|nc|bash)\s+https?://", "COMMAND_INJECTION_EXFIL"),
    (r"(?i)eval\s*\(", "CODE_EXECUTION_ATTEMPT"),
    (r"(?i)\[\s*system\s*\]", "BRACKET_DELIMITER_HIJACK"),
]


class QuarantinedSanitizerAgent:
    """
    Isolated Quarantined LLM Agent.
    - Sits directly adjacent to Cloud APIs (LocalStack / AWS).
    - Ingests raw cloud metadata containing potential indirect prompt injections.
    - Strips adversarial prompts, neutralizes instructions, and enforces a strict
      schema-validated JSON boundary before passing data to the Privileged LLM.
    """

    def __init__(self, endpoint_url: Optional[str] = None):
        self.agent_id = "quarantined-sanitizer-agent-v1"
        self.endpoint_url = endpoint_url or settings.LOCALSTACK_ENDPOINT

    def inspect_and_sanitize_text(self, text: Optional[str]) -> Tuple[str, Optional[InjectionDetectionResult]]:
        """
        Inspect untrusted text field (e.g. S3 tag, IAM description, Security Group rule description)
        for indirect prompt injection attempts. Neutralize if malicious.
        """
        if not text:
            return "", None

        detected_threats: List[str] = []
        threat_score = 0.0

        for pattern, threat_type in PROMPT_INJECTION_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                detected_threats.append(threat_type)
                threat_score += 25.0

        if detected_threats:
            threat_score = min(100.0, threat_score)
            logger.warning(
                f"[QUARANTINE ALERT] Prompt injection detected: {detected_threats} in text snippet '{text[:60]}...'"
            )

            # Neutralize: Strip prompt injection delimiters and command directives
            sanitized = text
            for pattern, _ in PROMPT_INJECTION_PATTERNS:
                sanitized = re.sub(pattern, "[PROMPT_INJECTION_REMOVED]", sanitized)

            # Strip control characters, markdown code fences, and XML-like tags
            sanitized = re.sub(r"[`<>{}\[\]\\]", "", sanitized)
            sanitized = f"[SANITIZED_BY_QUARANTINE: Neutralized threats {detected_threats}] - {sanitized.strip()}"

            detection = InjectionDetectionResult(
                is_malicious=True,
                threat_score=threat_score,
                detected_patterns=detected_threats,
                original_text_sample=text[:120],
                sanitized_text_sample=sanitized[:120],
            )
            return sanitized, detection

        # Safe text: Normalize whitespace and remove non-printable characters
        cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text).strip()
        return cleaned, None

    def sanitize_security_groups(self, raw_sgs: List[Dict[str, Any]], audit_log: List[InjectionDetectionResult]) -> List[SanitizedSecurityGroup]:
        """Convert raw Security Group metadata into strict, validated JSON structures."""
        sanitized_list = []
        for sg in raw_sgs:
            sg_id = sg.get("GroupId") or sg.get("resource_id", "sg-unknown")
            sg_name = sg.get("GroupName") or sg.get("resource_name", sg_id)
            desc_raw = sg.get("Description", "")

            clean_desc, detection = self.inspect_and_sanitize_text(desc_raw)
            clean_name, name_detection = self.inspect_and_sanitize_text(sg_name)

            injection_present = False
            if detection:
                audit_log.append(detection)
                injection_present = True
            if name_detection:
                audit_log.append(name_detection)
                injection_present = True

            ingress_rules = []
            has_open_ssh = False

            # Parse permissions into strict structured objects
            for perm in sg.get("IpPermissions", []):
                proto = str(perm.get("IpProtocol", "tcp"))
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]

                is_ssh = (from_p is not None and from_p <= 22 and to_p is not None and to_p >= 22) or proto == "-1"
                if is_ssh and "0.0.0.0/0" in cidrs:
                    has_open_ssh = True

                ingress_rules.append(
                    SanitizedIngressRule(
                        protocol=proto,
                        from_port=from_p,
                        to_port=to_p,
                        cidr_blocks=cidrs,
                        is_unrestricted_ssh=(is_ssh and "0.0.0.0/0" in cidrs),
                    )
                )

            # If simulated or finding object format
            if not ingress_rules and "22" in str(sg):
                has_open_ssh = True
                ingress_rules.append(
                    SanitizedIngressRule(
                        protocol="tcp",
                        from_port=22,
                        to_port=22,
                        cidr_blocks=["0.0.0.0/0"],
                        is_unrestricted_ssh=True,
                    )
                )

            sanitized_list.append(
                SanitizedSecurityGroup(
                    resource_id=sg_id,
                    resource_name=clean_name,
                    arn=f"arn:aws:ec2:us-east-1:000000000000:security-group/{sg_id}",
                    vpc_id=sg.get("VpcId", "vpc-default"),
                    ingress_rules=ingress_rules,
                    has_unrestricted_ssh=has_open_ssh,
                    sanitized_description=clean_desc,
                    injection_detected=injection_present,
                )
            )
        return sanitized_list

    def sanitize_s3_buckets(self, raw_buckets: List[Dict[str, Any]], audit_log: List[InjectionDetectionResult]) -> List[SanitizedS3Bucket]:
        """Convert raw S3 Bucket metadata into strict, validated JSON structures."""
        sanitized_list = []
        for b in raw_buckets:
            name_raw = b.get("Name") or b.get("resource_name", "unknown-bucket")
            clean_name, name_detection = self.inspect_and_sanitize_text(name_raw)

            injection_present = False
            if name_detection:
                audit_log.append(name_detection)
                injection_present = True

            # Sanitize tags
            raw_tags = b.get("Tags", {})
            clean_tags = {}
            for k, v in raw_tags.items():
                san_k, det_k = self.inspect_and_sanitize_text(k)
                san_v, det_v = self.inspect_and_sanitize_text(v)
                if det_k:
                    audit_log.append(det_k)
                    injection_present = True
                if det_v:
                    audit_log.append(det_v)
                    injection_present = True
                clean_tags[san_k] = san_v

            sanitized_list.append(
                SanitizedS3Bucket(
                    resource_id=f"arn:aws:s3:::{clean_name}",
                    bucket_name=clean_name,
                    arn=f"arn:aws:s3:::{clean_name}",
                    region=b.get("Region", "us-east-1"),
                    default_encryption_enabled=b.get("EncryptionEnabled", False),
                    public_access_blocked=b.get("PublicAccessBlocked", False),
                    sanitized_tags=clean_tags,
                    injection_detected=injection_present,
                )
            )
        return sanitized_list

    def sanitize_iam_roles(self, raw_roles: List[Dict[str, Any]], audit_log: List[InjectionDetectionResult]) -> List[SanitizedIAMRole]:
        """Convert raw IAM Role metadata into strict, validated JSON structures."""
        sanitized_list = []
        for r in raw_roles:
            role_name_raw = r.get("RoleName") or r.get("resource_name", "unknown-role")
            desc_raw = r.get("Description", "")

            clean_name, name_det = self.inspect_and_sanitize_text(role_name_raw)
            clean_desc, desc_det = self.inspect_and_sanitize_text(desc_raw)

            injection_present = False
            if name_det:
                audit_log.append(name_det)
                injection_present = True
            if desc_det:
                audit_log.append(desc_det)
                injection_present = True

            policies = [str(p) for p in r.get("AttachedPolicies", [])]
            has_admin = any("AdministratorAccess" in p for p in policies) or r.get("HasAdmin", False)

            sanitized_list.append(
                SanitizedIAMRole(
                    resource_id=f"arn:aws:iam::000000000000:role/{clean_name}",
                    role_name=clean_name,
                    arn=f"arn:aws:iam::000000000000:role/{clean_name}",
                    has_administrator_access=has_admin,
                    attached_policies=policies,
                    sanitized_description=clean_desc,
                    injection_detected=injection_present,
                )
            )
        return sanitized_list

    def fetch_and_sanitize_cloud_metadata(self, services: Optional[List[str]] = None, injected_mock_data: Optional[Dict[str, Any]] = None) -> SanitizedCloudPayload:
        """
        Main entry point for Quarantined LLM:
        1. Query Cloud APIs (or process incoming cloud metadata).
        2. Detect & neutralize prompt injections.
        3. Convert all raw metadata into strictly validated JSON conforming to SanitizedCloudPayload.
        """
        target_services = services or ["ec2", "iam", "s3"]
        audit_log: List[InjectionDetectionResult] = []

        raw_sgs: List[Dict[str, Any]] = []
        raw_buckets: List[Dict[str, Any]] = []
        raw_roles: List[Dict[str, Any]] = []

        # If adversarial mock data is provided (e.g. for testing injection defense)
        if injected_mock_data:
            raw_sgs = injected_mock_data.get("security_groups", [])
            raw_buckets = injected_mock_data.get("s3_buckets", [])
            raw_roles = injected_mock_data.get("iam_roles", [])
        else:
            # Query ProwlerService / LocalStack
            prowler = ProwlerService(endpoint_url=self.endpoint_url)
            scan_res = prowler.execute_scan(ScanRequest(services=target_services))

            # Transform raw findings into cloud resource inventories
            for f in scan_res.findings:
                res_id = getattr(f, "resource_id", "res-unknown")
                res_name = getattr(f, "resource_name", None) or res_id.split("/")[-1].split(":")[-1]
                svc = (getattr(f, "service", None) or getattr(f, "resource_type", "")).lower()
                desc = getattr(f, "description", "")

                if "ec2" in svc or "security-group" in res_id.lower():
                    raw_sgs.append({
                        "GroupId": res_name if "sg-" in res_name else "sg-3423",
                        "GroupName": res_name,
                        "Description": desc,
                        "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                    })
                elif "s3" in svc:
                    raw_buckets.append({
                        "Name": res_name,
                        "Tags": {"Environment": "Dev", "Owner": "SecOps"},
                        "EncryptionEnabled": getattr(f.compliance_status, "value", str(f.compliance_status)) == "PASSED",
                        "PublicAccessBlocked": False if "public" in getattr(f, "title", "").lower() else True,
                    })
                elif "iam" in svc:
                    title_str = getattr(f, "title", "").lower()
                    raw_roles.append({
                        "RoleName": res_name,
                        "Description": desc,
                        "AttachedPolicies": ["AdministratorAccess"] if "administratoraccess" in title_str else [],
                        "HasAdmin": "administratoraccess" in title_str,
                    })

        # Sanitize all items
        sanitized_sgs = self.sanitize_security_groups(raw_sgs, audit_log)
        sanitized_buckets = self.sanitize_s3_buckets(raw_buckets, audit_log)
        sanitized_roles = self.sanitize_iam_roles(raw_roles, audit_log)

        total_scanned = len(sanitized_sgs) + len(sanitized_buckets) + len(sanitized_roles)
        total_neutralized = len(audit_log)

        payload = SanitizedCloudPayload(
            schema_version="2026-10-05.strict-json-v1",
            sanitizer_agent=self.agent_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_resources_scanned=total_scanned,
            total_injections_neutralized=total_neutralized,
            security_groups=sanitized_sgs,
            s3_buckets=sanitized_buckets,
            iam_roles=sanitized_roles,
            injection_audit_log=audit_log,
        )

        # Enforce strict JSON serialization guarantee: payload MUST roundtrip through JSON
        strict_json = payload.model_dump_json()
        validated_payload = SanitizedCloudPayload.model_validate_json(strict_json)
        return validated_payload
