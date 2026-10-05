import boto3
import urllib.request
import json
import logging
from typing import Dict, Any, Optional, List
from botocore.config import Config
from backend.core.config import settings

logger = logging.getLogger("prowler_service.utils")


def get_localstack_session(
    endpoint_url: Optional[str] = None,
    region_name: Optional[str] = None,
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> boto3.Session:
    """Create a configured boto3 session targeting LocalStack credentials."""
    return boto3.Session(
        aws_access_key_id=access_key or settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=secret_key or settings.AWS_SECRET_ACCESS_KEY,
        region_name=region_name or settings.AWS_DEFAULT_REGION,
    )


def get_localstack_client(
    service_name: str,
    endpoint_url: Optional[str] = None,
    region_name: Optional[str] = None,
):
    """
    Get a boto3 client pointing to LocalStack.
    Configured with endpoint_url, path-style S3 addressing, and custom retries.
    """
    url = endpoint_url or settings.LOCALSTACK_ENDPOINT
    boto_config = Config(
        s3={"addressing_style": "path"},
        retries={"max_attempts": 2, "mode": "standard"},
    )
    return boto3.client(
        service_name,
        endpoint_url=url,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=region_name or settings.AWS_DEFAULT_REGION,
        config=boto_config,
    )


def check_localstack_connection(endpoint_url: Optional[str] = None, timeout: float = 1.5) -> bool:
    """
    Check if LocalStack is reachable and responding at the endpoint.
    Queries the LocalStack health endpoint: /_localstack/health
    """
    url = (endpoint_url or settings.LOCALSTACK_ENDPOINT).rstrip("/") + "/_localstack/health"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ProwlerService/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status == 200
    except Exception:
        # Try fallback root endpoint
        try:
            root_url = (endpoint_url or settings.LOCALSTACK_ENDPOINT).rstrip("/")
            req = urllib.request.Request(root_url, headers={"User-Agent": "ProwlerService/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status in (200, 404, 405)
        except Exception:
            return False


def build_asff_finding(
    finding_id: str,
    generator_id: str,
    title: str,
    description: str,
    severity_label: str,
    resource_id: str,
    resource_type: str,
    compliance_status: str,
    recommendation_text: str,
    recommendation_url: Optional[str] = None,
    frameworks: Optional[List[str]] = None,
    region: str = "us-east-1",
    account_id: str = "000000000000",
) -> Dict[str, Any]:
    """Helper utility to construct a spec-compliant AWS Security Finding Format (ASFF) dictionary."""
    normalized_scores = {
        "CRITICAL": 90,
        "HIGH": 70,
        "MEDIUM": 40,
        "LOW": 20,
        "INFORMATIONAL": 0,
    }

    return {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": "arn:aws:securityhub:us-east-1::product/prowler/prowler",
        "GeneratorId": generator_id,
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "FirstObservedAt": "2026-10-04T12:00:00Z",
        "CreatedAt": "2026-10-04T12:00:00Z",
        "UpdatedAt": "2026-10-04T12:00:00Z",
        "Severity": {
            "Label": severity_label.upper(),
            "Normalized": normalized_scores.get(severity_label.upper(), 0),
        },
        "Title": title,
        "Description": description,
        "Resources": [
            {
                "Type": resource_type,
                "Id": resource_id,
                "Partition": "aws",
                "Region": region,
            }
        ],
        "Compliance": {
            "Status": compliance_status.upper(),
            "RelatedRequirements": frameworks or ["CIS AWS Foundations Benchmark", "AWS Foundational Security Best Practices"],
        },
        "Remediation": {
            "Recommendation": {
                "Text": recommendation_text,
                "Url": recommendation_url or "https://docs.aws.amazon.com/",
            }
        },
    }


def get_sample_asff_findings() -> List[Dict[str, Any]]:
    """
    Generate representative ASFF findings for realistic LocalStack security evaluation.
    Used for instant demonstrations, development testing, and fallback resilience.
    """
    return [
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_default_encryption-vulnerable-bucket",
            generator_id="prowler-s3_bucket_default_encryption",
            title="S3 Bucket does not have default server-side encryption enabled",
            description="Ensure that Amazon S3 buckets have default encryption enabled using SSE-S3 or AWS KMS keys to protect data at rest.",
            severity_label="HIGH",
            resource_id="arn:aws:s3:::vulnerable-customer-data-bucket",
            resource_type="AwsS3Bucket",
            compliance_status="FAILED",
            recommendation_text="Enable default encryption for the S3 bucket using AWS KMS or AES-256 (SSE-S3) via AWS CLI or Terraform.",
            recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
            frameworks=["CIS AWS Benchmark 1.4 - 2.1.1", "AWS FSBP - S3.4"],
        ),
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_public_access_block-vulnerable-bucket",
            generator_id="prowler-s3_bucket_public_access_block",
            title="S3 Bucket does not have Public Access Block enabled",
            description="Amazon S3 Public Access Block settings prevent the application of any public policies or ACLs on the bucket.",
            severity_label="CRITICAL",
            resource_id="arn:aws:s3:::vulnerable-customer-data-bucket",
            resource_type="AwsS3Bucket",
            compliance_status="FAILED",
            recommendation_text="Enable S3 Block Public Access at the bucket or account level to prevent unintentional data leakage.",
            recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            frameworks=["CIS AWS Benchmark 1.4 - 2.1.5", "PCI-DSS v3.2.1"],
        ),
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-iam_role_administrator_access-admin_role",
            generator_id="prowler-iam_role_administrator_access",
            title="IAM Role has overly permissive AdministratorAccess policy attached",
            description="IAM policies should grant least privilege rather than wildcard Action: '*' on Resource: '*'.",
            severity_label="CRITICAL",
            resource_id="arn:aws:iam::000000000000:role/insecure-app-admin-role",
            resource_type="AwsIamRole",
            compliance_status="FAILED",
            recommendation_text="Detach AdministratorAccess from the role and define scoped permissions adhering to the principle of least privilege.",
            recommendation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
            frameworks=["CIS AWS Benchmark 1.4 - 1.16", "SOC2 CC6.1"],
        ),
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-ec2_security_group_open_ssh_port-sg-3423",
            generator_id="prowler-ec2_security_group_open_ssh_port",
            title="Security Group 'sg-3423' allows unrestricted ingress SSH traffic (0.0.0.0/0 to Port 22)",
            description="Security group 'sg-3423' permits unrestricted ingress from 0.0.0.0/0 to Port 22 (SSH).",
            severity_label="HIGH",
            resource_id="arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423",
            resource_type="AwsEc2SecurityGroup",
            compliance_status="FAILED",
            recommendation_text="Restrict SSH: Revoke 0.0.0.0/0 on Port 22 and restrict SSH ingress to authorized bastion or VPN CIDRs.",
            recommendation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
            frameworks=["CIS AWS Benchmark 1.4 - 5.2", "NIST 800-53"],
        ),
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_default_encryption-secure-backup-bucket",
            generator_id="prowler-s3_bucket_default_encryption",
            title="S3 Bucket has default server-side encryption enabled",
            description="Bucket encryption is configured with AES-256 SSE-S3.",
            severity_label="LOW",
            resource_id="arn:aws:s3:::secure-encrypted-backup-bucket",
            resource_type="AwsS3Bucket",
            compliance_status="PASSED",
            recommendation_text="Maintain existing SSE-S3 encryption policy.",
            recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
            frameworks=["CIS AWS Benchmark 1.4 - 2.1.1"],
        ),
        build_asff_finding(
            finding_id="arn:aws:securityhub:us-east-1:000000000000:finding/prowler-ec2_ebs_volume_encryption-vol-default",
            generator_id="prowler-ec2_ebs_volume_encryption",
            title="EBS Default Encryption is not enabled in region us-east-1",
            description="EBS default encryption ensures all newly created EBS volumes and snapshot copies are encrypted at rest.",
            severity_label="MEDIUM",
            resource_id="arn:aws:ec2:us-east-1:000000000000:account-attributes/ebs-encryption",
            resource_type="AwsEc2RegionalSetting",
            compliance_status="FAILED",
            recommendation_text="Enable EBS default encryption for the region: aws ec2 enable-ebs-encryption-by-default --region us-east-1",
            recommendation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
            frameworks=["AWS FSBP - EC2.7"],
        ),
    ]
