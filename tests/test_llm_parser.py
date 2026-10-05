import pytest
from starlette.testclient import TestClient

from backend.scanner.llm_parser import (
    LLMASFFParser,
    LLMSeverity,
    LLMSeverityLevel,
    PriorityTier,
    RiskCategory,
    LLMComplianceStatus,
    LLMReasoningFinding,
    LLMResourceMetadata,
)
from backend.scanner.utils import build_asff_finding, get_sample_asff_findings
from backend.api.main import app

client = TestClient(app)


def test_severity_mapping():
    # Test string input
    sev_crit = LLMSeverity.from_raw("CRITICAL")
    assert sev_crit.level == LLMSeverityLevel.CRITICAL
    assert sev_crit.score == 90
    assert sev_crit.priority == PriorityTier.P0_IMMEDIATE

    # Test dict input with custom score
    sev_dict = LLMSeverity.from_raw({"Label": "HIGH", "Normalized": 75})
    assert sev_dict.level == LLMSeverityLevel.HIGH
    assert sev_dict.score == 75
    assert sev_dict.priority == PriorityTier.P1_URGENT

    # Test synonyms
    sev_warn = LLMSeverity.from_raw("WARNING")
    assert sev_warn.level == LLMSeverityLevel.MEDIUM
    assert sev_warn.priority == PriorityTier.P2_ELEVATED

    sev_info = LLMSeverity.from_raw("INFO")
    assert sev_info.level == LLMSeverityLevel.INFORMATIONAL
    assert sev_info.priority == PriorityTier.P3_HYGIENE


def test_resource_metadata_extraction():
    # S3 Resource
    s3_raw = {
        "Id": "arn:aws:s3:::my-production-logs-bucket",
        "Type": "AwsS3Bucket",
        "Region": "us-east-1",
        "Tags": {"Environment": "Production"},
    }
    meta_s3 = LLMResourceMetadata.from_raw(s3_raw)
    assert meta_s3.name == "my-production-logs-bucket"
    assert meta_s3.service == "s3"
    assert meta_s3.resource_type == "AwsS3Bucket"
    assert meta_s3.tags.get("Environment") == "Production"

    # IAM Role Resource with Account ID embedded in ARN
    iam_raw = {
        "Id": "arn:aws:iam::123456789012:role/cloud-admin-role",
        "Type": "AwsIamRole",
        "Region": "us-east-1",
    }
    meta_iam = LLMResourceMetadata.from_raw(iam_raw)
    assert meta_iam.name == "cloud-admin-role"
    assert meta_iam.service == "iam"
    assert meta_iam.account_id == "123456789012"

    # EC2 Security Group
    ec2_raw = {
        "Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef",
        "Type": "AwsEc2SecurityGroup",
        "Region": "us-east-1",
    }
    meta_ec2 = LLMResourceMetadata.from_raw(ec2_raw)
    assert meta_ec2.name == "sg-0123456789abcdef"
    assert meta_ec2.service == "ec2"


def test_remediation_and_risk_classification():
    raw_finding = build_asff_finding(
        finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3-public",
        generator_id="prowler-s3_bucket_public_access_block",
        title="S3 Bucket does not have Public Access Block enabled",
        description="Public access settings missing",
        severity_label="CRITICAL",
        resource_id="arn:aws:s3:::vulnerable-customer-data-bucket",
        resource_type="AwsS3Bucket",
        compliance_status="FAILED",
        recommendation_text="Enable S3 Public Access Block immediately.",
        recommendation_url="https://docs.aws.amazon.com/s3",
    )

    llm_finding = LLMASFFParser.parse_finding(raw_finding)

    assert isinstance(llm_finding, LLMReasoningFinding)
    assert llm_finding.risk_category == RiskCategory.DATA_EXPOSURE
    assert llm_finding.compliance_status == LLMComplianceStatus.FAILED

    # Check auto-generated remediation snippets
    assert llm_finding.remediation.suggested_cli_command is not None
    assert "put-public-access-block" in llm_finding.remediation.suggested_cli_command
    assert llm_finding.remediation.suggested_terraform_snippet is not None
    assert "aws_s3_bucket_public_access_block" in llm_finding.remediation.suggested_terraform_snippet


def test_timestamps_and_pydantic_validation():
    raw_finding = build_asff_finding(
        finding_id="finding-test-1",
        generator_id="check-1",
        title="  Overly Permissive IAM Role   ",  # Has extra whitespace to test validator
        description="Description text",
        severity_label="HIGH",
        resource_id="arn:aws:iam::000000000000:role/insecure-role",
        resource_type="AwsIamRole",
        compliance_status="FAILED",
        recommendation_text="Scope role permissions.",
    )

    llm_finding = LLMASFFParser.parse_finding(raw_finding)

    # Whitespace validator test
    assert llm_finding.title == "Overly Permissive IAM Role"

    # Timestamps test
    assert llm_finding.timestamps.detected_at == "2026-10-04T12:00:00Z"
    assert "T" in llm_finding.timestamps.parsed_at

    # Dictionary serialization without None
    as_dict = llm_finding.to_llm_dict()
    assert isinstance(as_dict, dict)
    assert as_dict["severity"]["level"] == "HIGH"
    assert as_dict["resource"]["name"] == "insecure-role"


def test_llm_prompt_block_generation():
    sample_raw = get_sample_asff_findings()
    findings = LLMASFFParser.parse_findings(sample_raw)

    assert len(findings) == 6

    # Test single block
    first_block = findings[0].to_llm_prompt_block()
    assert "### [" in first_block
    assert "Resource" in first_block
    assert "Fix" in first_block

    # Test complete reasoning prompt document
    full_prompt = LLMASFFParser.to_llm_reasoning_prompt(findings)
    assert "# CLOUD SECURITY AUDIT FINDINGS (LLM REASONING CONTEXT)" in full_prompt
    assert "PRIORITY SECURITY FINDINGS FOR MITIGATION" in full_prompt


def test_api_llm_endpoints():
    # 1. Test /parse/llm
    sample_raw = get_sample_asff_findings()[:2]
    res = client.post("/parse/llm", json=sample_raw)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["count"] == 2
    assert "llm_findings" in data
    assert "prompt_context" in data

    # 2. Test /scan/llm
    scan_res = client.post("/scan/llm", json={"services": ["s3"], "mock_mode": True})
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "success"
    assert "llm_findings" in scan_data
    assert len(scan_data["llm_findings"]) > 0
    assert "prompt_context" in scan_data


def test_mitre_attack_and_specialized_formatters():
    raw_finding = build_asff_finding(
        finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3-public-bucket",
        generator_id="prowler-s3_bucket_public_access_block",
        title="S3 Bucket allows public read",
        description="Public access block configuration is missing",
        severity_label="CRITICAL",
        resource_id="arn:aws:s3:::sensitive-customer-records",
        resource_type="AwsS3Bucket",
        compliance_status="FAILED",
        recommendation_text="Apply S3 block public access.",
    )

    llm_finding = LLMASFFParser.parse_finding(raw_finding)

    # 1. MITRE ATT&CK technique mapping
    assert llm_finding.mitre_attack is not None
    assert "T1530" in llm_finding.mitre_attack

    # 2. Claude/Anthropic XML output
    xml_output = llm_finding.to_anthropic_xml()
    assert "<security_finding" in xml_output
    assert "<title>S3 Bucket allows public read</title>" in xml_output
    assert "<mitre_technique>T1530: Data from Cloud Storage Object</mitre_technique>" in xml_output
    assert "<cli_command>aws s3api put-public-access-block" in xml_output
    assert "</security_finding>" in xml_output

    # 3. Agent Tool Call arguments output
    tool_args = llm_finding.to_tool_call_args()
    assert tool_args["finding_id"] == "arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3-public-bucket"
    assert tool_args["resource_name"] == "sensitive-customer-records"
    assert tool_args["severity"] == "CRITICAL"
    assert tool_args["priority"] == "P0_IMMEDIATE"
    assert tool_args["mitre_attack"] == "T1530: Data from Cloud Storage Object"


def test_parser_aggregation_and_summary_metrics():
    sample_raw = get_sample_asff_findings()
    findings = LLMASFFParser.parse_findings(sample_raw)

    # 1. Filter by severity
    high_and_crit = LLMASFFParser.filter_by_severity(findings, min_severity=LLMSeverityLevel.HIGH)
    assert len(high_and_crit) > 0
    assert all(f.severity.level in [LLMSeverityLevel.HIGH, LLMSeverityLevel.CRITICAL] for f in high_and_crit)

    # 2. Group by service
    grouped_svc = LLMASFFParser.group_by_service(findings)
    assert "s3" in grouped_svc
    assert "iam" in grouped_svc
    assert "ec2" in grouped_svc

    # 3. Group by priority
    grouped_prio = LLMASFFParser.group_by_priority(findings)
    assert PriorityTier.P0_IMMEDIATE.value in grouped_prio or PriorityTier.P1_URGENT.value in grouped_prio

    # 4. Generate Executive Summary
    summary = LLMASFFParser.generate_executive_summary(findings)
    assert summary["total_findings"] == len(findings)
    assert summary["failed_findings"] > 0
    assert summary["critical_count"] > 0
    assert summary["average_risk_score"] > 0.0
    assert "s3" in summary["affected_services"]

