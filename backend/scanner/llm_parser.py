"""
LLM-Optimized ASFF Parser Module
Converts raw AWS Security Finding Format (ASFF) findings into streamlined,
information-dense JSON objects specifically tailored for LLM reasoning,
prompt context injection, and agentic security workflows.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, model_validator


# ==========================================
# Enums for Semantic LLM Reasoning
# ==========================================

class LLMSeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class PriorityTier(str, Enum):
    P0_IMMEDIATE = "P0_IMMEDIATE"   # < 24 Hours (Active exposure / Admin compromise)
    P1_URGENT = "P1_URGENT"         # < 72 Hours (Network ingress / perimeter risks)
    P2_ELEVATED = "P2_ELEVATED"     # < 14 Days (Storage at rest, missing backups)
    P3_HYGIENE = "P3_HYGIENE"       # < 30 Days (Minor configurations, tags)


class RiskCategory(str, Enum):
    DATA_EXPOSURE = "DATA_EXPOSURE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERIMETER_BREACH = "PERIMETER_BREACH"
    ENCRYPTION_AT_REST = "ENCRYPTION_AT_REST"
    GOVERNANCE_AUDIT = "GOVERNANCE_AUDIT"
    OTHER = "OTHER"


class LLMComplianceStatus(str, Enum):
    FAILED = "FAILED"
    PASSED = "PASSED"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


# ==========================================
# Pydantic Models for LLM Reasoning Objects
# ==========================================

class LLMSeverity(BaseModel):
    level: LLMSeverityLevel = Field(description="Normalized severity level")
    score: int = Field(ge=0, le=100, description="Normalized risk score 0-100")
    priority: PriorityTier = Field(description="Actionable remediation priority tier")
    original_label: Optional[str] = Field(default=None, description="Original raw severity label")

    @classmethod
    def from_raw(cls, raw_severity: Union[str, Dict[str, Any], None]) -> "LLMSeverity":
        """Map raw ASFF severity to strongly typed LLMSeverity."""
        label_str = "INFORMATIONAL"
        score = 0
        orig = None

        if isinstance(raw_severity, dict):
            label_str = str(raw_severity.get("Label", "INFORMATIONAL")).upper()
            score = raw_severity.get("Normalized", 0) or 0
            orig = raw_severity.get("Original")
        elif isinstance(raw_severity, str):
            label_str = raw_severity.upper()
            orig = raw_severity

        # Standardize synonyms or vendor-specific labels
        mapping = {
            "CRITICAL": LLMSeverityLevel.CRITICAL,
            "HIGH": LLMSeverityLevel.HIGH,
            "MEDIUM": LLMSeverityLevel.MEDIUM,
            "LOW": LLMSeverityLevel.LOW,
            "INFORMATIONAL": LLMSeverityLevel.INFORMATIONAL,
            "INFO": LLMSeverityLevel.INFORMATIONAL,
            "WARNING": LLMSeverityLevel.MEDIUM,
            "ERROR": LLMSeverityLevel.HIGH,
            "FATAL": LLMSeverityLevel.CRITICAL,
        }
        level = mapping.get(label_str, LLMSeverityLevel.INFORMATIONAL)

        # Calculate score & priority if not provided
        if not score:
            score_defaults = {
                LLMSeverityLevel.CRITICAL: 90,
                LLMSeverityLevel.HIGH: 70,
                LLMSeverityLevel.MEDIUM: 40,
                LLMSeverityLevel.LOW: 20,
                LLMSeverityLevel.INFORMATIONAL: 0,
            }
            score = score_defaults[level]

        priority_map = {
            LLMSeverityLevel.CRITICAL: PriorityTier.P0_IMMEDIATE,
            LLMSeverityLevel.HIGH: PriorityTier.P1_URGENT,
            LLMSeverityLevel.MEDIUM: PriorityTier.P2_ELEVATED,
            LLMSeverityLevel.LOW: PriorityTier.P3_HYGIENE,
            LLMSeverityLevel.INFORMATIONAL: PriorityTier.P3_HYGIENE,
        }

        return cls(
            level=level,
            score=score,
            priority=priority_map[level],
            original_label=orig or label_str,
        )


class LLMResourceMetadata(BaseModel):
    arn: str = Field(description="Full AWS Amazon Resource Name (ARN) or identifier")
    name: str = Field(description="Extracted clean resource identifier (bucket name, role name, SG ID)")
    service: str = Field(description="AWS service name (e.g. s3, iam, ec2, rds)")
    resource_type: str = Field(description="Standard AWS resource type e.g. AwsS3Bucket")
    region: str = Field(default="us-east-1", description="Target AWS region")
    account_id: str = Field(default="000000000000", description="AWS Account ID")
    tags: Optional[Dict[str, str]] = Field(default_factory=dict, description="Resource tags")

    @classmethod
    def from_raw(cls, resource_dict: Dict[str, Any], default_region: str = "us-east-1", default_account: str = "000000000000") -> "LLMResourceMetadata":
        """Extract clean resource metadata from raw ASFF resource entry."""
        arn = resource_dict.get("Id", "unknown-resource")
        raw_type = resource_dict.get("Type", "AwsUnknownResource")
        region = resource_dict.get("Region") or default_region
        tags = resource_dict.get("Tags") or {}

        # 1. Deduce AWS Service
        service = "other"
        type_lower = raw_type.lower()
        if "s3" in type_lower or "s3:::" in arn:
            service = "s3"
        elif "iam" in type_lower or "iam::" in arn:
            service = "iam"
        elif "ec2" in type_lower or "securitygroup" in type_lower or "vpc" in type_lower:
            service = "ec2"
        elif "rds" in type_lower:
            service = "rds"
        elif "lambda" in type_lower:
            service = "lambda"

        # 2. Extract clean human-readable name from ARN
        # Examples:
        #   arn:aws:s3:::my-bucket -> my-bucket
        #   arn:aws:iam::123:role/my-role -> my-role
        #   arn:aws:ec2:us-east-1:123:security-group/sg-01 -> sg-01
        name = arn
        if ":::" in arn:
            name = arn.split(":::")[-1]
        elif "/" in arn:
            name = arn.split("/")[-1]
        elif ":" in arn:
            name = arn.split(":")[-1]

        # Extract account ID if embedded in ARN
        account_id = default_account
        arn_match = re.match(r"^arn:aws:[^:]*:[^:]*:(\d{12}):", arn)
        if arn_match:
            account_id = arn_match.group(1)

        return cls(
            arn=arn,
            name=name,
            service=service,
            resource_type=raw_type,
            region=region,
            account_id=account_id,
            tags=tags,
        )


class LLMRemediation(BaseModel):
    recommendation_summary: str = Field(description="Concise, 1-2 sentence remediation instruction")
    documentation_url: Optional[str] = Field(default=None, description="Official AWS documentation reference")
    suggested_cli_command: Optional[str] = Field(default=None, description="Pre-computed AWS CLI fix command")
    suggested_terraform_snippet: Optional[str] = Field(default=None, description="Pre-computed Terraform code fix")

    @classmethod
    def from_raw(cls, raw_remediation: Any, title: str, resource: LLMResourceMetadata) -> "LLMRemediation":
        """Extract and enrich remediation guidance with CLI and Terraform snippets for LLM reasoning."""
        rec_text = ""
        url = None

        if isinstance(raw_remediation, dict):
            rec_obj = raw_remediation.get("Recommendation", {})
            if isinstance(rec_obj, dict):
                rec_text = rec_obj.get("Text", "")
                url = rec_obj.get("Url")

        if not rec_text:
            rec_text = f"Review security configuration and apply least privilege controls to {resource.name}."

        # Auto-synthesize CLI and Terraform snippets to accelerate LLM remediation generation
        cli_cmd = None
        tf_snippet = None
        title_lower = title.lower()

        if "public_access_block" in title_lower or ("public" in title_lower and resource.service == "s3"):
            cli_cmd = f"aws s3api put-public-access-block --bucket {resource.name} --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
            tf_snippet = f'resource "aws_s3_bucket_public_access_block" "remediation" {{\n  bucket = "{resource.name}"\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}}'
        elif "encryption" in title_lower and resource.service == "s3":
            cli_cmd = f"aws s3api put-bucket-encryption --bucket {resource.name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
            tf_snippet = f'resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {{\n  bucket = "{resource.name}"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}'
        elif "administratoraccess" in title_lower or (resource.service == "iam" and "admin" in title_lower):
            cli_cmd = f"aws iam detach-role-policy --role-name {resource.name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
            tf_snippet = f'# Replace AdministratorAccess on role "{resource.name}" with scoped policy'
        elif "ssh" in title_lower or ("22" in title_lower and resource.service == "ec2"):
            cli_cmd = f"aws ec2 revoke-security-group-ingress --group-id {resource.name} --protocol tcp --port 22 --cidr 0.0.0.0/0"
            tf_snippet = f'# Remove 0.0.0.0/0 on port 22 in security group "{resource.name}"'

        return cls(
            recommendation_summary=rec_text,
            documentation_url=url,
            suggested_cli_command=cli_cmd,
            suggested_terraform_snippet=tf_snippet,
        )


class LLMTimestamps(BaseModel):
    detected_at: str = Field(description="ISO timestamp when vulnerability was first observed")
    parsed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO timestamp when parsed for LLM")


class LLMReasoningFinding(BaseModel):
    """
    Simplified, high-density security finding object optimized for LLM reasoning.
    Removes boilerplate schema wrappers and isolates the essential reasoning signals.
    """
    id: str = Field(description="Unique finding identifier")
    check_id: str = Field(description="Prowler or SecurityHub check code (e.g. s3_bucket_default_encryption)")
    title: str = Field(description="Crisp finding title")
    description: str = Field(description="Concise description of the security check")
    severity: LLMSeverity = Field(description="Severity classification and score")
    compliance_status: LLMComplianceStatus = Field(description="PASSED, FAILED, WARNING")
    risk_category: RiskCategory = Field(description="Categorization of risk vector for LLM threat modeling")
    mitre_attack: Optional[str] = Field(default=None, description="MITRE ATT&CK technique reference (e.g. T1530)")
    resource: LLMResourceMetadata = Field(description="Target resource metadata block")
    remediation: LLMRemediation = Field(description="Actionable fix recommendations and code")
    frameworks: List[str] = Field(default_factory=list, description="Related standards (CIS, AWS FSBP, PCI-DSS)")
    timestamps: LLMTimestamps = Field(description="Lifecycle timestamps")

    @field_validator("title", "description", mode="before")
    @classmethod
    def clean_text_whitespace(cls, v: Any) -> str:
        """Strip superfluous whitespace and newlines for token efficiency."""
        if not v:
            return ""
        return " ".join(str(v).split())

    def to_llm_dict(self) -> Dict[str, Any]:
        """Convert to clean JSON dictionary without nulls for token-optimized LLM context."""
        return self.model_dump(exclude_none=True)

    def to_tool_call_args(self) -> Dict[str, Any]:
        """Format finding as lightweight arguments suitable for agentic tool/remediation execution."""
        return {
            "finding_id": self.id,
            "resource_arn": self.resource.arn,
            "resource_name": self.resource.name,
            "service": self.resource.service,
            "severity": self.severity.level.value,
            "priority": self.severity.priority.value,
            "risk_category": self.risk_category.value,
            "mitre_attack": self.mitre_attack,
            "suggested_cli": self.remediation.suggested_cli_command,
            "action_required": self.remediation.recommendation_summary,
        }

    def to_anthropic_xml(self) -> str:
        """Format finding as a structured XML element for Claude/Anthropic prompt reasoning."""
        cli_tag = f"\n    <cli_command>{self.remediation.suggested_cli_command}</cli_command>" if self.remediation.suggested_cli_command else ""
        tf_tag = f"\n    <terraform_code><![CDATA[{self.remediation.suggested_terraform_snippet}]]></terraform_code>" if self.remediation.suggested_terraform_snippet else ""
        mitre_tag = f"\n  <mitre_technique>{self.mitre_attack}</mitre_technique>" if self.mitre_attack else ""

        return (
            f'<security_finding id="{self.id}" severity="{self.severity.level.value}" priority="{self.severity.priority.value}">\n'
            f"  <title>{self.title}</title>\n"
            f"  <status>{self.compliance_status.value}</status>\n"
            f"  <risk_category>{self.risk_category.value}</risk_category>{mitre_tag}\n"
            f'  <resource service="{self.resource.service}" type="{self.resource.resource_type}" name="{self.resource.name}">\n'
            f"    <arn>{self.resource.arn}</arn>\n"
            f"    <region>{self.resource.region}</region>\n"
            f"    <account_id>{self.resource.account_id}</account_id>\n"
            f"  </resource>\n"
            f"  <description>{self.description}</description>\n"
            f"  <remediation>\n"
            f"    <summary>{self.remediation.recommendation_summary}</summary>{cli_tag}{tf_tag}\n"
            f"  </remediation>\n"
            f"</security_finding>"
        )

    def to_llm_prompt_block(self) -> str:
        """
        Format as a token-efficient Markdown snippet ready for direct prompt injection.
        Ideal for LangGraph, Gemini, OpenAI, Claude prompts.
        """
        status_icon = "❌ FAIL" if self.compliance_status == LLMComplianceStatus.FAILED else "✅ PASS"
        lines = [
            f"### [{self.severity.level.value}] {self.title} ({status_icon})",
            f"- **Resource**: `{self.resource.name}` (`{self.resource.arn}`) [{self.resource.service.upper()}]",
            f"- **Category**: `{self.risk_category.value}` | **Priority**: `{self.severity.priority.value}` (Score: {self.severity.score}/100)",
            f"- **Issue**: {self.description}",
            f"- **Fix**: {self.remediation.recommendation_summary}",
        ]
        if self.mitre_attack:
            lines.append(f"- **MITRE ATT&CK**: `{self.mitre_attack}`")
        if self.remediation.suggested_cli_command:
            lines.append(f"- **CLI Fix**: `{self.remediation.suggested_cli_command}`")
        if self.frameworks:
            lines.append(f"- **Compliance**: {', '.join(self.frameworks)}")
        return "\n".join(lines)


# ==========================================
# Parser Module
# ==========================================

class LLMASFFParser:
    """
    Parser module for converting raw AWS Security Finding Format (ASFF) data
    into simplified, structured JSON objects optimized for LLM reasoning.
    """

    @staticmethod
    def classify_risk_category(title: str, resource_type: str, description: str) -> RiskCategory:
        """Categorize finding into clear threat modeling vector for LLM understanding."""
        combined = f"{title} {resource_type} {description}".lower()
        if "public" in combined or "leak" in combined or "unrestricted" in combined:
            if "s3" in combined or "bucket" in combined or "data" in combined:
                return RiskCategory.DATA_EXPOSURE
        if "iam" in combined or "administratoraccess" in combined or "privilege" in combined or "role" in combined:
            return RiskCategory.PRIVILEGE_ESCALATION
        if "ssh" in combined or "security group" in combined or "0.0.0.0/0" in combined or "port" in combined:
            return RiskCategory.PERIMETER_BREACH
        if "encryption" in combined or "kms" in combined or "sse" in combined:
            return RiskCategory.ENCRYPTION_AT_REST
        if "compliance" in combined or "logging" in combined or "trail" in combined:
            return RiskCategory.GOVERNANCE_AUDIT
        return RiskCategory.OTHER

    @classmethod
    def parse_finding(cls, raw: Dict[str, Any]) -> LLMReasoningFinding:
        """
        Parse a single raw ASFF dictionary into an LLM-optimized finding object.
        Extracts resource metadata, maps severity, generates remediation, and validates via Pydantic.
        """
        if not isinstance(raw, dict):
            raise TypeError(f"Expected dict for ASFF finding, got {type(raw).__name__}")

        finding_id = raw.get("Id", "unknown-id")
        check_id = raw.get("GeneratorId", "prowler")
        title = raw.get("Title", "Security Finding")
        description = raw.get("Description", "")
        account_id = raw.get("AwsAccountId", "000000000000")
        default_region = raw.get("Region", "us-east-1")

        # 1. Severity Mapping
        severity = LLMSeverity.from_raw(raw.get("Severity"))

        # 2. Resource Metadata Extraction
        resources = raw.get("Resources", [])
        if resources and isinstance(resources, list) and len(resources) > 0:
            resource = LLMResourceMetadata.from_raw(resources[0], default_region=default_region, default_account=account_id)
        else:
            resource = LLMResourceMetadata(
                arn=raw.get("ResourceId", "unknown-resource"),
                name=raw.get("ResourceId", "unknown-resource"),
                service="other",
                resource_type=raw.get("ResourceType", "AwsUnknownResource"),
                region=default_region,
                account_id=account_id,
            )

        # 3. Compliance Status Extraction
        compliance_obj = raw.get("Compliance", {})
        status_str = "NOT_AVAILABLE"
        frameworks = []
        if isinstance(compliance_obj, dict):
            status_str = str(compliance_obj.get("Status", "NOT_AVAILABLE")).upper()
            frameworks = compliance_obj.get("RelatedRequirements", []) or []

        status_mapping = {
            "PASSED": LLMComplianceStatus.PASSED,
            "FAILED": LLMComplianceStatus.FAILED,
            "WARNING": LLMComplianceStatus.WARNING,
            "NOT_AVAILABLE": LLMComplianceStatus.NOT_AVAILABLE,
        }
        compliance_status = status_mapping.get(status_str, LLMComplianceStatus.NOT_AVAILABLE)

        # 4. Remediation Recommendations
        remediation = LLMRemediation.from_raw(raw.get("Remediation"), title=title, resource=resource)

        # 5. Timestamps
        detected_at = raw.get("FirstObservedAt") or raw.get("CreatedAt") or datetime.now(timezone.utc).isoformat()
        timestamps = LLMTimestamps(detected_at=detected_at)

        # 6. Risk Categorization
        risk_cat = cls.classify_risk_category(title=title, resource_type=resource.resource_type, description=description)

        # 7. MITRE ATT&CK Technique Mapping
        mitre_attack = cls.map_mitre_attack(check_id=check_id, risk_category=risk_cat)

        return LLMReasoningFinding(
            id=finding_id,
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            compliance_status=compliance_status,
            risk_category=risk_cat,
            mitre_attack=mitre_attack,
            resource=resource,
            remediation=remediation,
            frameworks=frameworks,
            timestamps=timestamps,
        )

    @staticmethod
    def map_mitre_attack(check_id: str, risk_category: RiskCategory) -> Optional[str]:
        """Map security check or risk category to MITRE ATT&CK Cloud Matrix technique."""
        check_lower = check_id.lower()
        if "s3" in check_lower and ("public" in check_lower or "leak" in check_lower or "acl" in check_lower):
            return "T1530: Data from Cloud Storage Object"
        if "encryption" in check_lower:
            return "T1486: Data Encrypted for Impact"
        if "iam" in check_lower or "admin" in check_lower or "privilege" in check_lower:
            return "T1078.004: Valid Accounts - Cloud Accounts"
        if "ssh" in check_lower or "22" in check_lower or "security_group" in check_lower or "ingress" in check_lower:
            return "T1190: Exploit Public-Facing Application"
        if "cloudtrail" in check_lower or "logging" in check_lower or "audit" in check_lower:
            return "T1562.001: Impair Defenses - Disable Cloud Logs"

        # Fallback to category standard mapping
        category_map = {
            RiskCategory.DATA_EXPOSURE: "T1530: Data from Cloud Storage Object",
            RiskCategory.PRIVILEGE_ESCALATION: "T1078.004: Valid Accounts - Cloud Accounts",
            RiskCategory.PERIMETER_BREACH: "T1190: Exploit Public-Facing Application",
            RiskCategory.ENCRYPTION_AT_REST: "T1486: Data Encrypted for Impact",
            RiskCategory.GOVERNANCE_AUDIT: "T1562.001: Impair Defenses - Disable Cloud Logs",
        }
        return category_map.get(risk_category)

    @classmethod
    def filter_by_severity(
        cls, findings: List[LLMReasoningFinding], min_severity: LLMSeverityLevel = LLMSeverityLevel.MEDIUM
    ) -> List[LLMReasoningFinding]:
        """Filter findings that meet or exceed the specified minimum severity level."""
        severity_ranks = {
            LLMSeverityLevel.INFORMATIONAL: 0,
            LLMSeverityLevel.LOW: 1,
            LLMSeverityLevel.MEDIUM: 2,
            LLMSeverityLevel.HIGH: 3,
            LLMSeverityLevel.CRITICAL: 4,
        }
        min_rank = severity_ranks.get(min_severity, 0)
        return [f for f in findings if severity_ranks.get(f.severity.level, 0) >= min_rank]

    @classmethod
    def group_by_service(cls, findings: List[LLMReasoningFinding]) -> Dict[str, List[LLMReasoningFinding]]:
        """Group reasoning findings by AWS service for targeted remediation prompting."""
        grouped: Dict[str, List[LLMReasoningFinding]] = {}
        for f in findings:
            grouped.setdefault(f.resource.service, []).append(f)
        return grouped

    @classmethod
    def group_by_priority(cls, findings: List[LLMReasoningFinding]) -> Dict[str, List[LLMReasoningFinding]]:
        """Group reasoning findings by priority tier for SLA-driven triage."""
        grouped: Dict[str, List[LLMReasoningFinding]] = {}
        for f in findings:
            grouped.setdefault(f.severity.priority.value, []).append(f)
        return grouped

    @classmethod
    def generate_executive_summary(cls, findings: List[LLMReasoningFinding]) -> Dict[str, Any]:
        """Generate structured high-level executive metrics for LLM agent coordinators."""
        total = len(findings)
        failed = [f for f in findings if f.compliance_status == LLMComplianceStatus.FAILED]
        passed = [f for f in findings if f.compliance_status == LLMComplianceStatus.PASSED]
        critical = [f for f in failed if f.severity.level == LLMSeverityLevel.CRITICAL]
        high = [f for f in failed if f.severity.level == LLMSeverityLevel.HIGH]
        medium = [f for f in failed if f.severity.level == LLMSeverityLevel.MEDIUM]
        low = [f for f in failed if f.severity.level == LLMSeverityLevel.LOW]

        # Count affected services
        service_counts: Dict[str, int] = {}
        for f in failed:
            service_counts[f.resource.service] = service_counts.get(f.resource.service, 0) + 1

        # Average risk score among failed findings
        avg_score = (
            round(sum(f.severity.score for f in failed) / len(failed), 1)
            if failed else 0.0
        )

        return {
            "total_findings": total,
            "failed_findings": len(failed),
            "passed_findings": len(passed),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "average_risk_score": avg_score,
            "affected_services": service_counts,
        }

    @classmethod
    def parse_findings(cls, raw_list: List[Dict[str, Any]]) -> List[LLMReasoningFinding]:
        """Convert a list of raw ASFF findings into simplified LLM reasoning objects."""
        findings: List[LLMReasoningFinding] = []
        for raw in raw_list:
            try:
                findings.append(cls.parse_finding(raw))
            except Exception:
                continue
        return findings

    @classmethod
    def parse_asff_file(cls, file_path: Union[str, Path]) -> List[LLMReasoningFinding]:
        """Read and parse an ASFF JSON or NDJSON file."""
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
                    findings_raw = data.get("Findings", [data])
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

    @classmethod
    def to_llm_reasoning_prompt(cls, findings: List[LLMReasoningFinding], max_findings: int = 15) -> str:
        """
        Generate a comprehensive, token-optimized context document tailored for LLM reasoning.
        Directly inject into LangGraph, Gemini, Claude, or GPT prompt chains.
        """
        total = len(findings)
        failed = [f for f in findings if f.compliance_status == LLMComplianceStatus.FAILED]
        critical = [f for f in failed if f.severity.level == LLMSeverityLevel.CRITICAL]
        high = [f for f in failed if f.severity.level == LLMSeverityLevel.HIGH]

        prompt_parts = [
            "# CLOUD SECURITY AUDIT FINDINGS (LLM REASONING CONTEXT)",
            f"- Total Evaluated: {total} | Failed: {len(failed)} | Critical: {len(critical)} | High: {len(high)}",
            "",
            "## PRIORITY SECURITY FINDINGS FOR MITIGATION:",
            "",
        ]

        # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW
        severity_order = {
            LLMSeverityLevel.CRITICAL: 0,
            LLMSeverityLevel.HIGH: 1,
            LLMSeverityLevel.MEDIUM: 2,
            LLMSeverityLevel.LOW: 3,
            LLMSeverityLevel.INFORMATIONAL: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.severity.level, 99), -f.severity.score))

        for f in sorted_findings[:max_findings]:
            prompt_parts.append(f.to_llm_prompt_block())
            prompt_parts.append("")

        return "\n".join(prompt_parts)
