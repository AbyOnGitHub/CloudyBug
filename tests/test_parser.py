import pytest
from backend.scanner.parser import ASFFParser
from backend.scanner.models import SeverityLevel, ComplianceStatus, NormalizedFinding
from backend.scanner.utils import build_asff_finding


def test_parse_single_asff_finding():
    raw = build_asff_finding(
        finding_id="arn:aws:securityhub:us-east-1:123456789012:finding/test-1",
        generator_id="prowler-s3_bucket_default_encryption",
        title="S3 Bucket does not have default encryption enabled",
        description="Ensure bucket is encrypted",
        severity_label="HIGH",
        resource_id="arn:aws:s3:::my-bucket",
        resource_type="AwsS3Bucket",
        compliance_status="FAILED",
        recommendation_text="Enable SSE-S3 encryption on bucket.",
        recommendation_url="https://docs.aws.amazon.com/s3",
    )

    norm = ASFFParser.parse_finding(raw)

    assert isinstance(norm, NormalizedFinding)
    # Check required fields
    assert norm.severity == SeverityLevel.HIGH
    assert norm.resource_id == "arn:aws:s3:::my-bucket"
    assert norm.resource_type == "AwsS3Bucket"
    assert norm.recommendation == "Enable SSE-S3 encryption on bucket."
    assert norm.compliance_status == ComplianceStatus.FAILED
    assert norm.severity_score == 70
    assert norm.recommendation_url == "https://docs.aws.amazon.com/s3"


def test_parse_multiple_findings():
    raw_list = [
        build_asff_finding(
            finding_id=f"arn:aws:securityhub:us-east-1:000000000000:finding/id-{i}",
            generator_id=f"gen-{i}",
            title=f"Test Finding {i}",
            description=f"Description {i}",
            severity_label="CRITICAL" if i % 2 == 0 else "LOW",
            resource_id=f"arn:aws:s3:::bucket-{i}",
            resource_type="AwsS3Bucket",
            compliance_status="FAILED" if i % 2 == 0 else "PASSED",
            recommendation_text=f"Fix recommendation {i}",
        )
        for i in range(4)
    ]

    parsed = ASFFParser.parse_findings(raw_list)
    assert len(parsed) == 4
    assert parsed[0].severity == SeverityLevel.CRITICAL
    assert parsed[0].compliance_status == ComplianceStatus.FAILED
    assert parsed[1].severity == SeverityLevel.LOW
    assert parsed[1].compliance_status == ComplianceStatus.PASSED


def test_filter_findings():
    raw_list = [
        build_asff_finding(
            finding_id="1", generator_id="g1", title="S3 Risk", description="",
            severity_label="CRITICAL", resource_id="arn:aws:s3:::b1", resource_type="AwsS3Bucket",
            compliance_status="FAILED", recommendation_text="Fix S3"
        ),
        build_asff_finding(
            finding_id="2", generator_id="g2", title="IAM Pass", description="",
            severity_label="LOW", resource_id="arn:aws:iam::1:role/r1", resource_type="AwsIamRole",
            compliance_status="PASSED", recommendation_text="Ok"
        ),
    ]

    findings = ASFFParser.parse_findings(raw_list)

    # Filter by severity
    critical_only = ASFFParser.filter_findings(findings, severities=[SeverityLevel.CRITICAL])
    assert len(critical_only) == 1
    assert critical_only[0].severity == SeverityLevel.CRITICAL

    # Filter by compliance status
    failed_only = ASFFParser.filter_findings(findings, compliance_statuses=[ComplianceStatus.FAILED])
    assert len(failed_only) == 1
    assert failed_only[0].compliance_status == ComplianceStatus.FAILED


def test_summarize_findings():
    raw_list = [
        build_asff_finding(
            finding_id="1", generator_id="g1", title="Critical Fail", description="",
            severity_label="CRITICAL", resource_id="res1", resource_type="AwsS3Bucket",
            compliance_status="FAILED", recommendation_text="Fix"
        ),
        build_asff_finding(
            finding_id="2", generator_id="g2", title="High Fail", description="",
            severity_label="HIGH", resource_id="res2", resource_type="AwsEc2SecurityGroup",
            compliance_status="FAILED", recommendation_text="Fix"
        ),
        build_asff_finding(
            finding_id="3", generator_id="g3", title="Pass", description="",
            severity_label="LOW", resource_id="res3", resource_type="AwsS3Bucket",
            compliance_status="PASSED", recommendation_text="Ok"
        ),
    ]

    findings = ASFFParser.parse_findings(raw_list)
    summary = ASFFParser.summarize_findings(findings, scanned_services=["s3", "ec2"], duration=0.45)

    assert summary.total_findings == 3
    assert summary.failed == 2
    assert summary.passed == 1
    assert summary.critical == 1
    assert summary.high == 1
    assert summary.pass_percentage == 33.33
    assert summary.risk_score > 0
