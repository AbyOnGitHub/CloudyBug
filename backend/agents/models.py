from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class InjectionDetectionResult(BaseModel):
    """Telemetry capturing detected adversarial prompt injection patterns."""
    model_config = ConfigDict(extra="forbid")

    is_malicious: bool = Field(default=False, description="Flag indicating if prompt injection was detected")
    threat_score: float = Field(default=0.0, description="Risk score from 0.0 to 100.0")
    detected_patterns: List[str] = Field(default_factory=list, description="Specific injection patterns identified")
    original_text_sample: str = Field(default="", description="Snippet of raw untrusted text")
    sanitized_text_sample: str = Field(default="", description="Sanitized, inert text output")


class SanitizedIngressRule(BaseModel):
    """Strictly typed security group ingress rule."""
    model_config = ConfigDict(extra="forbid")

    protocol: str = Field(default="tcp", description="Network protocol (tcp, udp, icmp, -1)")
    from_port: Optional[int] = Field(default=None, description="Starting port range")
    to_port: Optional[int] = Field(default=None, description="Ending port range")
    cidr_blocks: List[str] = Field(default_factory=list, description="Permitted IPv4 CIDR blocks")
    is_unrestricted_ssh: bool = Field(default=False, description="Flag if port 22 is open to 0.0.0.0/0")


class SanitizedSecurityGroup(BaseModel):
    """Sanitized and validated EC2 Security Group metadata."""
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(description="Security Group ID (e.g. sg-3423)")
    resource_name: str = Field(description="Sanitized group name")
    arn: str = Field(description="AWS ARN")
    vpc_id: Optional[str] = Field(default=None, description="VPC ID")
    ingress_rules: List[SanitizedIngressRule] = Field(default_factory=list, description="Parsed ingress rules")
    has_unrestricted_ssh: bool = Field(default=False, description="Whether port 22 is exposed to 0.0.0.0/0")
    sanitized_description: str = Field(default="", description="Neutralized description stripped of instructions")
    injection_detected: bool = Field(default=False, description="Whether an injection payload was neutralized in this resource")


class SanitizedS3Bucket(BaseModel):
    """Sanitized and validated S3 Bucket configuration."""
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(description="Bucket identifier")
    bucket_name: str = Field(description="Sanitized bucket name")
    arn: str = Field(description="Bucket ARN")
    region: str = Field(default="us-east-1", description="Bucket region")
    default_encryption_enabled: bool = Field(default=False, description="SSE-S3 or KMS enabled")
    public_access_blocked: bool = Field(default=False, description="All 4 public access blocks enabled")
    sanitized_tags: Dict[str, str] = Field(default_factory=dict, description="Sanitized key-value tags")
    injection_detected: bool = Field(default=False, description="Whether an injection payload was neutralized in tags or name")


class SanitizedIAMRole(BaseModel):
    """Sanitized and validated IAM Role permissions."""
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(description="Role identifier")
    role_name: str = Field(description="Sanitized role name")
    arn: str = Field(description="Role ARN")
    has_administrator_access: bool = Field(default=False, description="Whether AdministratorAccess policy is attached")
    attached_policies: List[str] = Field(default_factory=list, description="List of attached policy names/ARNs")
    sanitized_description: str = Field(default="", description="Neutralized description text")
    injection_detected: bool = Field(default=False, description="Whether an injection payload was neutralized in role metadata")


class SanitizedResource(BaseModel):
    """Generic container for sanitized cloud resource metadata."""
    model_config = ConfigDict(extra="forbid")

    resource_id: str
    resource_type: str
    service: str
    status: str
    details: Dict[str, Any]
    injection_detected: bool = False


class SanitizedCloudPayload(BaseModel):
    """
    The STRICT JSON communication contract between the Quarantined LLM and Privileged LLM.
    No raw markdown, control characters, or unvalidated strings are allowed through.
    """
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="2026-10-05.strict-json-v1", description="Schema specification version")
    sanitizer_agent: str = Field(default="Quarantined-LLM-Sanitizer/v1", description="Identifier of the isolated sanitizer")
    timestamp: str = Field(description="ISO-8601 generation timestamp")
    total_resources_scanned: int = Field(default=0, description="Count of evaluated cloud assets")
    total_injections_neutralized: int = Field(default=0, description="Count of adversarial payloads stripped")
    security_groups: List[SanitizedSecurityGroup] = Field(default_factory=list)
    s3_buckets: List[SanitizedS3Bucket] = Field(default_factory=list)
    iam_roles: List[SanitizedIAMRole] = Field(default_factory=list)
    injection_audit_log: List[InjectionDetectionResult] = Field(default_factory=list)


class OrchestrationAction(BaseModel):
    """Actionable remediation generated by the Privileged LLM."""
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(description="Unique action ID")
    target_resource: str = Field(description="Target resource ID (e.g. sg-3423)")
    service: str = Field(description="AWS Service (EC2, S3, IAM)")
    action_type: str = Field(description="Remediation type")
    reasoning: str = Field(description="Privileged LLM cognitive justification")
    cli_command: str = Field(description="Synthesized remediation AWS CLI command")
    requires_human_approval: bool = Field(default=True, description="Whether execution requires human approval")


class DualAgentAuditResponse(BaseModel):
    """Response returned to user from the Dual-Agent execution pipeline."""
    status: str = Field(default="SUCCESS")
    user_intent: str = Field(description="Original user request processed by Privileged LLM")
    sanitization_summary: Dict[str, Any] = Field(description="Metrics from Quarantined LLM")
    reasoning_trace: List[Dict[str, Any]] = Field(description="Chain-of-thought trace from Privileged LLM")
    orchestration_plan: List[OrchestrationAction] = Field(description="Actions derived by Privileged LLM")
    sanitized_payload: SanitizedCloudPayload = Field(description="Structured JSON passed between agents")
    requires_approval: bool = Field(default=True)
