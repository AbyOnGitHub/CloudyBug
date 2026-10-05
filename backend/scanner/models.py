from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ComplianceStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    NOT_AVAILABLE = "NOT_AVAILABLE"


# ==========================================
# AWS Security Finding Format (ASFF) Models
# ==========================================

class ASFFSeverity(BaseModel):
    Label: SeverityLevel = SeverityLevel.INFORMATIONAL
    Normalized: Optional[int] = 0
    Original: Optional[str] = None


class ASFFResource(BaseModel):
    Type: str = "Other"
    Id: str
    Partition: Optional[str] = "aws"
    Region: Optional[str] = "us-east-1"
    Tags: Optional[Dict[str, str]] = None
    Details: Optional[Dict[str, Any]] = None


class ASFFCompliance(BaseModel):
    Status: ComplianceStatus = ComplianceStatus.NOT_AVAILABLE
    RelatedRequirements: Optional[List[str]] = Field(default_factory=list)
    StatusReasons: Optional[List[Dict[str, str]]] = None


class ASFFRecommendation(BaseModel):
    Text: str = ""
    Url: Optional[str] = None


class ASFFRemediation(BaseModel):
    Recommendation: Optional[ASFFRecommendation] = None


class ASFFFinding(BaseModel):
    SchemaVersion: str = "2018-10-08"
    Id: str
    ProductArn: str = "arn:aws:securityhub:us-east-1::product/prowler/prowler"
    GeneratorId: str = "prowler"
    AwsAccountId: str = "000000000000"
    Types: Optional[List[str]] = Field(default_factory=list)
    FirstObservedAt: Optional[str] = None
    UpdatedAt: Optional[str] = None
    CreatedAt: Optional[str] = None
    Severity: ASFFSeverity = Field(default_factory=ASFFSeverity)
    Title: str = ""
    Description: str = ""
    Resources: List[ASFFResource] = Field(default_factory=list)
    Compliance: Optional[ASFFCompliance] = None
    Remediation: Optional[ASFFRemediation] = None


# ==========================================
# Normalized Structured Findings Models
# ==========================================

class NormalizedFinding(BaseModel):
    """
    Normalized security finding as extracted and structured from raw ASFF.
    Guarantees presence of required fields:
    - severity
    - resource_id
    - resource_type
    - recommendation
    - compliance_status
    """
    id: str = Field(description="Internal unique identifier for the finding")
    finding_id: str = Field(description="Original ASFF Finding ID / ARN")
    title: str = Field(description="Short title or rule name")
    description: str = Field(description="Detailed description of the check and finding")
    severity: SeverityLevel = Field(description="Severity classification: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    severity_score: int = Field(default=0, description="Normalized score 0-100")
    resource_id: str = Field(description="Target resource ARN or identifier (e.g. arn:aws:s3:::bucket-name)")
    resource_type: str = Field(description="AWS resource type, e.g. AwsS3Bucket, AwsIamRole, AwsEc2SecurityGroup")
    region: str = Field(default="us-east-1", description="AWS Region")
    account_id: str = Field(default="000000000000", description="AWS Account ID")
    compliance_status: ComplianceStatus = Field(description="Compliance check outcome: PASSED, FAILED, WARNING")
    compliance_frameworks: List[str] = Field(default_factory=list, description="Related compliance frameworks e.g. CIS, AWS-FSBP")
    recommendation: str = Field(description="Actionable guidance on how to remediate the vulnerability")
    recommendation_url: Optional[str] = Field(default=None, description="URL link to official remediation documentation")
    generator_id: str = Field(default="", description="Prowler check ID e.g. s3_bucket_default_encryption")
    created_at: str = Field(description="Timestamp finding was recorded")
    raw_asff: Optional[Dict[str, Any]] = Field(default=None, description="Raw AWS Security Finding Format object")


# ==========================================
# API Request / Response Models
# ==========================================

class ScanRequest(BaseModel):
    services: Optional[List[str]] = Field(
        default=["s3", "iam", "ec2"],
        description="AWS services to scan against LocalStack (e.g. ['s3', 'iam', 'ec2'])"
    )
    severity_filter: Optional[List[SeverityLevel]] = Field(
        default=None,
        description="Filter findings to only specified severities"
    )
    compliance_status_filter: Optional[List[ComplianceStatus]] = Field(
        default=None,
        description="Filter findings by compliance status (e.g. ['FAILED'])"
    )
    run_graph_analysis: bool = Field(
        default=True,
        description="Execute the LangGraph Automated Security Triage workflow on scan findings"
    )
    mock_mode: Optional[bool] = Field(
        default=None,
        description="Force simulation/mock mode or auto-detect LocalStack"
    )
    endpoint_url: Optional[str] = Field(
        default=None,
        description="Override LocalStack endpoint URL (defaults to settings.LOCALSTACK_ENDPOINT)"
    )


class ScanSummary(BaseModel):
    total_findings: int = 0
    passed: int = 0
    failed: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    pass_percentage: float = 0.0
    risk_score: float = 0.0  # 0 to 100 risk scale
    scanned_services: List[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0


class ScanResponse(BaseModel):
    status: str = "success"
    scan_id: str
    timestamp: str
    target_endpoint: str
    summary: ScanSummary
    findings: List[NormalizedFinding]
    graph_analysis: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: str
    localstack_endpoint: str
    localstack_connected: bool
    prowler_cli_available: bool
    engine_mode: str
    timestamp: str
