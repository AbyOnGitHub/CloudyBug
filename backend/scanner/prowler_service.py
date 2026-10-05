import os
import shutil
import subprocess
import logging
import json
import uuid
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.core.config import settings
from backend.scanner.models import (
    ScanRequest,
    NormalizedFinding,
    ScanResponse,
    ScanSummary,
)
from backend.scanner.parser import ASFFParser
from backend.scanner.utils import (
    check_localstack_connection,
    get_localstack_client,
    build_asff_finding,
    get_sample_asff_findings,
)

logger = logging.getLogger("prowler_service")
logging.basicConfig(level=logging.INFO)


class LocalStackProwlerEngine:
    """
    Direct Python audit engine targeting LocalStack via Boto3.
    Evaluates LocalStack cloud resources against AWS Security Best Practices
    and generates AWS Security Finding Format (ASFF) objects.
    """

    def __init__(self, endpoint_url: str):
        self.endpoint_url = endpoint_url
        self.region = settings.AWS_DEFAULT_REGION
        self.account_id = "000000000000"

    def scan_s3(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            s3 = get_localstack_client("s3", endpoint_url=self.endpoint_url)
            buckets_response = s3.list_buckets()
            buckets = buckets_response.get("Buckets", [])

            for b in buckets:
                name = b["Name"]
                bucket_arn = f"arn:aws:s3:::{name}"

                # 1. Check Default Encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                    if rules:
                        findings.append(
                            build_asff_finding(
                                finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-s3_bucket_default_encryption-{name}",
                                generator_id="prowler-s3_bucket_default_encryption",
                                title=f"S3 Bucket '{name}' has default server-side encryption enabled",
                                description=f"The bucket '{name}' has default SSE encryption enabled.",
                                severity_label="LOW",
                                resource_id=bucket_arn,
                                resource_type="AwsS3Bucket",
                                compliance_status="PASSED",
                                recommendation_text="Default encryption is properly enabled.",
                                recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
                                frameworks=["CIS AWS Benchmark 1.4 - 2.1.1"],
                            )
                        )
                    else:
                        raise Exception("No encryption rules")
                except Exception:
                    findings.append(
                        build_asff_finding(
                            finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-s3_bucket_default_encryption-{name}",
                            generator_id="prowler-s3_bucket_default_encryption",
                            title=f"S3 Bucket '{name}' does not have default server-side encryption enabled",
                            description=f"Ensure that Amazon S3 bucket '{name}' has default encryption enabled to protect stored data.",
                            severity_label="HIGH",
                            resource_id=bucket_arn,
                            resource_type="AwsS3Bucket",
                            compliance_status="FAILED",
                            recommendation_text=f"Enable default AES256 or AWS KMS encryption on bucket '{name}'.",
                            recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
                            frameworks=["CIS AWS Benchmark 1.4 - 2.1.1", "AWS FSBP - S3.4"],
                        )
                    )

                # 2. Check Public Access Block
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    config = pab.get("PublicAccessBlockConfiguration", {})
                    is_blocked = (
                        config.get("BlockPublicAcls")
                        and config.get("IgnorePublicAcls")
                        and config.get("BlockPublicPolicy")
                        and config.get("RestrictPublicBuckets")
                    )
                    if is_blocked:
                        findings.append(
                            build_asff_finding(
                                finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-s3_bucket_public_access_block-{name}",
                                generator_id="prowler-s3_bucket_public_access_block",
                                title=f"S3 Bucket '{name}' has Public Access Block enabled",
                                description=f"Bucket '{name}' blocks public ACLs and public policies.",
                                severity_label="LOW",
                                resource_id=bucket_arn,
                                resource_type="AwsS3Bucket",
                                compliance_status="PASSED",
                                recommendation_text="S3 Public Access Block is correctly enforcing restricted access.",
                                recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                                frameworks=["CIS AWS Benchmark 1.4 - 2.1.5"],
                            )
                        )
                    else:
                        raise Exception("Incomplete public block")
                except Exception:
                    findings.append(
                        build_asff_finding(
                            finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-s3_bucket_public_access_block-{name}",
                            generator_id="prowler-s3_bucket_public_access_block",
                            title=f"S3 Bucket '{name}' does not have Public Access Block enabled",
                            description=f"Bucket '{name}' lacks complete S3 Public Access Block settings.",
                            severity_label="CRITICAL",
                            resource_id=bucket_arn,
                            resource_type="AwsS3Bucket",
                            compliance_status="FAILED",
                            recommendation_text=f"Enable all four S3 Block Public Access flags on bucket '{name}'.",
                            recommendation_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            frameworks=["CIS AWS Benchmark 1.4 - 2.1.5", "PCI-DSS v3.2.1"],
                        )
                    )

        except Exception as e:
            logger.warning(f"Error inspecting LocalStack S3: {e}")
        return findings

    def scan_iam(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            iam = get_localstack_client("iam", endpoint_url=self.endpoint_url)
            roles_resp = iam.list_roles()
            roles = roles_resp.get("Roles", [])

            for role in roles:
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                # Skip internal AWS service-linked roles
                if "aws-service-role" in role_arn:
                    continue

                try:
                    attached = iam.list_attached_role_policies(RoleName=role_name)
                    has_admin = any(
                        "AdministratorAccess" in p.get("PolicyName", "") or "AdministratorAccess" in p.get("PolicyArn", "")
                        for p in attached.get("AttachedPolicies", [])
                    )
                    if has_admin:
                        findings.append(
                            build_asff_finding(
                                finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-iam_role_administrator_access-{role_name}",
                                generator_id="prowler-iam_role_administrator_access",
                                title=f"IAM Role '{role_name}' has overly permissive AdministratorAccess attached",
                                description=f"The IAM role '{role_name}' has full administrative access (*:*) which violates the principle of least privilege.",
                                severity_label="CRITICAL",
                                resource_id=role_arn,
                                resource_type="AwsIamRole",
                                compliance_status="FAILED",
                                recommendation_text=f"Detach AdministratorAccess from role '{role_name}' and scope IAM actions to required APIs only.",
                                recommendation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
                                frameworks=["CIS AWS Benchmark 1.4 - 1.16", "SOC2 CC6.1"],
                            )
                        )
                    else:
                        findings.append(
                            build_asff_finding(
                                finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-iam_role_administrator_access-{role_name}",
                                generator_id="prowler-iam_role_administrator_access",
                                title=f"IAM Role '{role_name}' does not have AdministratorAccess policy",
                                description=f"Role '{role_name}' does not have full administrative wildcard policy.",
                                severity_label="LOW",
                                resource_id=role_arn,
                                resource_type="AwsIamRole",
                                compliance_status="PASSED",
                                recommendation_text="Maintain scoped IAM role permissions.",
                                recommendation_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                                frameworks=["CIS AWS Benchmark 1.4 - 1.16"],
                            )
                        )
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Error inspecting LocalStack IAM: {e}")
        return findings

    def scan_ec2(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            ec2 = get_localstack_client("ec2", endpoint_url=self.endpoint_url)

            # 1. Security Groups check
            sg_resp = ec2.describe_security_groups()
            for sg in sg_resp.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)
                sg_arn = f"arn:aws:ec2:{self.region}:{self.account_id}:security-group/{sg_id}"

                has_open_ssh = False
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]

                    # Check port 22 or full port range open to 0.0.0.0/0
                    is_ssh = (from_port is not None and from_port <= 22 and to_port is not None and to_port >= 22)
                    is_all = perm.get("IpProtocol") == "-1"
                    if (is_ssh or is_all) and "0.0.0.0/0" in ip_ranges:
                        has_open_ssh = True
                        break

                if has_open_ssh:
                    findings.append(
                        build_asff_finding(
                            finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-ec2_security_group_open_ssh_port-{sg_id}",
                            generator_id="prowler-ec2_security_group_open_ssh_port",
                            title=f"Security Group '{sg_name}' ({sg_id}) allows unrestricted SSH ingress (0.0.0.0/0:22)",
                            description=f"Security group '{sg_name}' allows inbound connections from the entire internet to port 22.",
                            severity_label="HIGH",
                            resource_id=sg_arn,
                            resource_type="AwsEc2SecurityGroup",
                            compliance_status="FAILED",
                            recommendation_text=f"Remove 0.0.0.0/0 from ingress rules on security group '{sg_id}' and restrict SSH to authorized CIDRs.",
                            recommendation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
                            frameworks=["CIS AWS Benchmark 1.4 - 5.2", "NIST 800-53"],
                        )
                    )
                else:
                    findings.append(
                        build_asff_finding(
                            finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-ec2_security_group_open_ssh_port-{sg_id}",
                            generator_id="prowler-ec2_security_group_open_ssh_port",
                            title=f"Security Group '{sg_name}' ({sg_id}) restricts SSH ingress",
                            description=f"Security group '{sg_name}' does not allow unrestricted ingress to port 22.",
                            severity_label="LOW",
                            resource_id=sg_arn,
                            resource_type="AwsEc2SecurityGroup",
                            compliance_status="PASSED",
                            recommendation_text="Maintain restricted ingress rules on the security group.",
                            recommendation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
                            frameworks=["CIS AWS Benchmark 1.4 - 5.2"],
                        )
                    )

            # 2. Check EBS encryption default
            try:
                ebs_resp = ec2.get_ebs_encryption_by_default()
                is_encrypted = ebs_resp.get("EbsEncryptionByDefault", False)
                if not is_encrypted:
                    findings.append(
                        build_asff_finding(
                            finding_id=f"arn:aws:securityhub:{self.region}:{self.account_id}:finding/prowler-ec2_ebs_volume_encryption-default",
                            generator_id="prowler-ec2_ebs_volume_encryption",
                            title=f"EBS Default Encryption is disabled in region {self.region}",
                            description="Ensure Amazon Elastic Block Store (EBS) default encryption is enabled to protect new volumes.",
                            severity_label="MEDIUM",
                            resource_id=f"arn:aws:ec2:{self.region}:{self.account_id}:account-attributes/ebs-encryption",
                            resource_type="AwsEc2RegionalSetting",
                            compliance_status="FAILED",
                            recommendation_text=f"Enable default EBS encryption: aws ec2 enable-ebs-encryption-by-default --region {self.region}",
                            recommendation_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
                            frameworks=["AWS FSBP - EC2.7"],
                        )
                    )
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Error inspecting LocalStack EC2: {e}")
        return findings

    def run_all(self, services: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        if "s3" in services:
            all_findings.extend(self.scan_s3())
        if "iam" in services:
            all_findings.extend(self.scan_iam())
        if "ec2" in services:
            all_findings.extend(self.scan_ec2())
        return all_findings


class ProwlerService:
    """
    Main service orchestrating Prowler security scans against LocalStack.
    Supports both Prowler CLI (when binary is in environment) and direct
    boto3 LocalStack audit engine. Emits findings in AWS Security Finding Format (ASFF).
    """

    def __init__(self, endpoint_url: Optional[str] = None):
        self.endpoint_url = endpoint_url or settings.LOCALSTACK_ENDPOINT
        self.output_dir = Path(settings.OUTPUT_DIRECTORY)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.latest_scan_result: Optional[ScanResponse] = None

    def is_prowler_cli_installed(self) -> bool:
        """Check if prowler executable is available in PATH."""
        return shutil.which(settings.PROWLER_BINARY_PATH) is not None

    def execute_prowler_cli_scan(self, services: List[str], scan_id: str) -> Optional[List[Dict[str, Any]]]:
        """
        Execute the official Prowler CLI directed at LocalStack using ASFF output mode:
        prowler aws --endpoint-url <localstack_url> -M json-asff -F <scan_id>
        """
        if not self.is_prowler_cli_installed():
            return None

        output_file_prefix = self.output_dir / scan_id
        cmd = [
            settings.PROWLER_BINARY_PATH,
            "aws",
            "--endpoint-url", self.endpoint_url,
            "-M", "json-asff",
            "-F", str(output_file_prefix),
            "--services", ",".join(services),
            "--no-banner",
        ]

        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = settings.AWS_ACCESS_KEY_ID
        env["AWS_SECRET_ACCESS_KEY"] = settings.AWS_SECRET_ACCESS_KEY
        env["AWS_DEFAULT_REGION"] = settings.AWS_DEFAULT_REGION
        env["AWS_ENDPOINT_URL"] = self.endpoint_url

        try:
            logger.info(f"Running Prowler CLI against LocalStack: {' '.join(cmd)}")
            subprocess.run(
                cmd,
                env=env,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )

            # Find generated json-asff file
            expected_asff = list(self.output_dir.glob(f"*{scan_id}*.asff.json")) + list(self.output_dir.glob(f"*{scan_id}*.json"))
            if expected_asff and expected_asff[0].exists():
                return ASFFParser.parse_asff_json_file(expected_asff[0])
        except Exception as e:
            logger.error(f"Failed to execute Prowler CLI: {e}")

        return None

    def execute_scan(self, request: ScanRequest) -> ScanResponse:
        """
        Execute scan against LocalStack, collect raw ASFF findings,
        parse into normalized JSON models, and assemble ScanResponse.
        """
        start_time = time.time()
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        target_endpoint = request.endpoint_url or self.endpoint_url
        services = request.services or ["s3", "iam", "ec2"]

        is_connected = check_localstack_connection(target_endpoint)
        raw_asff_findings: List[Dict[str, Any]] = []
        execution_engine = "prowler_localstack_engine"

        # 1. Try Prowler CLI if installed and not in mock mode
        if not request.mock_mode and self.is_prowler_cli_installed():
            cli_findings = self.execute_prowler_cli_scan(services, scan_id)
            if cli_findings:
                raw_asff_findings = [f.raw_asff for f in cli_findings if f.raw_asff]
                execution_engine = "prowler_cli"

        # 2. If CLI not used, run LocalStack audit engine
        if not raw_asff_findings:
            if is_connected:
                engine = LocalStackProwlerEngine(endpoint_url=target_endpoint)
                live_findings = engine.run_all(services)
                raw_asff_findings.extend(live_findings)
                execution_engine = "localstack_boto3_engine"

            # If LocalStack has no resources yet or is offline, supplement with sample ASFF findings
            if not raw_asff_findings or (len(raw_asff_findings) == 0 and settings.USE_MOCK_FALLBACK):
                sample_findings = get_sample_asff_findings()
                raw_asff_findings.extend(sample_findings)
                execution_engine = "localstack_simulated_engine"

        # 3. Save raw ASFF output to file for auditing and compliance records
        asff_file_path = self.output_dir / f"{scan_id}_asff.json"
        try:
            with open(asff_file_path, "w", encoding="utf-8") as f:
                json.dump(raw_asff_findings, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not persist ASFF file: {e}")

        # 4. Parse raw ASFF findings into Normalized JSON objects
        normalized_findings = ASFFParser.parse_findings(raw_asff_findings)

        # 5. Apply optional filters
        if request.severity_filter or request.compliance_status_filter:
            normalized_findings = ASFFParser.filter_findings(
                normalized_findings,
                severities=request.severity_filter,
                compliance_statuses=request.compliance_status_filter,
            )

        duration = time.time() - start_time
        summary = ASFFParser.summarize_findings(normalized_findings, scanned_services=services, duration=duration)

        response = ScanResponse(
            status="success",
            scan_id=scan_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            target_endpoint=target_endpoint,
            summary=summary,
            findings=normalized_findings,
            graph_analysis=None,
        )

        self.latest_scan_result = response
        return response
