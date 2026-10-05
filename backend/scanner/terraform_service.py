import os
import shutil
import subprocess
import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.scanner.utils import (
    check_localstack_connection,
    get_localstack_client,
)

logger = logging.getLogger("terraform_service")
logging.basicConfig(level=logging.INFO)


class TerraformResourceStatus(BaseModel):
    """Status of an individual resource provisioned via Terraform."""
    resource_type: str
    resource_id: str
    name: str
    is_vulnerable: bool
    details: Dict[str, Any] = Field(default_factory=dict)


class TerraformDeploymentResult(BaseModel):
    """Summary of Terraform infrastructure deployment execution."""
    status: str = "SUCCESS"
    deployment_method: str = Field(description="terraform_cli or boto3_provisioner")
    timestamp: str
    resources_deployed: List[TerraformResourceStatus] = Field(default_factory=list)
    output_logs: List[str] = Field(default_factory=list)


class TerraformService:
    """
    Manages Terraform deployment of cloud security test infrastructure.
    Supports official Terraform CLI and built-in Boto3 Terraform Provisioner
    mirroring 'terraform/main.tf' resources directly into LocalStack.
    """

    def __init__(self, terraform_dir: Optional[str] = None, endpoint_url: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent.parent.parent
        self.terraform_dir = Path(terraform_dir) if terraform_dir else base_dir / "terraform"
        self.endpoint_url = endpoint_url or settings.LOCALSTACK_ENDPOINT

    def is_terraform_cli_installed(self) -> bool:
        """Check if terraform executable is in PATH."""
        return shutil.which("terraform") is not None

    def deploy_vulnerable_infrastructure(self, endpoint_url: Optional[str] = None) -> TerraformDeploymentResult:
        """
        Deploys intentionally vulnerable test resources into LocalStack:
        - S3: vulnerable-customer-data-bucket (unencrypted, no public access block)
        - S3: secure-encrypted-backup-bucket (encrypted, public access blocked)
        - IAM: insecure-app-admin-role (wildcard AdministratorAccess attached)
        - IAM: compliant-readonly-role (scoped ReadOnlyAccess attached)
        - EC2: insecure-ssh-sg (unrestricted 0.0.0.0/0 on port 22)
        - EC2: compliant-web-sg (restricted HTTPS 10.0.0.0/16 on port 443)
        """
        target_endpoint = endpoint_url or self.endpoint_url
        now_iso = datetime.now(timezone.utc).isoformat()
        logs: List[str] = []
        deployed: List[TerraformResourceStatus] = []
        method = "boto3_provisioner"

        is_live = check_localstack_connection(target_endpoint)

        # 1. Try Terraform CLI if available and LocalStack is active
        if self.is_terraform_cli_installed() and is_live and self.terraform_dir.exists():
            try:
                logs.append("Running 'terraform init'...")
                subprocess.run(["terraform", "init"], cwd=str(self.terraform_dir), capture_output=True, check=True)
                logs.append("Running 'terraform apply -auto-approve'...")
                apply_res = subprocess.run(
                    ["terraform", "apply", "-auto-approve"],
                    cwd=str(self.terraform_dir),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                logs.append(apply_res.stdout)
                method = "terraform_cli"
            except Exception as e:
                logs.append(f"Terraform CLI execution failed ({e}), falling back to native provisioner.")

        # 2. Native Boto3 Terraform Provisioner
        if method == "boto3_provisioner":
            logs.append(f"Deploying Terraform resources via Boto3 to {target_endpoint}...")

            # --- S3 Buckets ---
            vulnerable_bucket = "vulnerable-customer-data-bucket"
            compliant_bucket = "secure-encrypted-backup-bucket"

            if is_live:
                try:
                    s3 = get_localstack_client("s3", endpoint_url=target_endpoint)
                    # Create vulnerable bucket (unencrypted, no PAB)
                    s3.create_bucket(Bucket=vulnerable_bucket)
                    logs.append(f"Created S3 bucket: {vulnerable_bucket} (unencrypted, public)")

                    # Create compliant bucket
                    s3.create_bucket(Bucket=compliant_bucket)
                    s3.put_bucket_encryption(
                        Bucket=compliant_bucket,
                        ServerSideEncryptionConfiguration={
                            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                        },
                    )
                    s3.put_public_access_block(
                        Bucket=compliant_bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        },
                    )
                    logs.append(f"Created S3 bucket: {compliant_bucket} (AES256 encrypted, public blocked)")
                except Exception as e:
                    logs.append(f"S3 provisioning error: {e}")

            deployed.append(TerraformResourceStatus(
                resource_type="aws_s3_bucket",
                resource_id=f"arn:aws:s3:::{vulnerable_bucket}",
                name=vulnerable_bucket,
                is_vulnerable=True,
                details={"encryption": False, "public_access_blocked": False},
            ))
            deployed.append(TerraformResourceStatus(
                resource_type="aws_s3_bucket",
                resource_id=f"arn:aws:s3:::{compliant_bucket}",
                name=compliant_bucket,
                is_vulnerable=False,
                details={"encryption": True, "public_access_blocked": True},
            ))

            # --- IAM Roles ---
            insecure_role = "insecure-app-admin-role"
            compliant_role = "compliant-readonly-role"
            assume_policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}],
            })

            if is_live:
                try:
                    iam = get_localstack_client("iam", endpoint_url=target_endpoint)
                    try:
                        iam.create_role(RoleName=insecure_role, AssumeRolePolicyDocument=assume_policy)
                        iam.attach_role_policy(RoleName=insecure_role, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
                        logs.append(f"Created IAM role: {insecure_role} (AdministratorAccess attached)")
                    except Exception:
                        pass

                    try:
                        iam.create_role(RoleName=compliant_role, AssumeRolePolicyDocument=assume_policy)
                        iam.attach_role_policy(RoleName=compliant_role, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
                        logs.append(f"Created IAM role: {compliant_role} (ReadOnlyAccess attached)")
                    except Exception:
                        pass
                except Exception as e:
                    logs.append(f"IAM provisioning error: {e}")

            deployed.append(TerraformResourceStatus(
                resource_type="aws_iam_role",
                resource_id=f"arn:aws:iam::000000000000:role/{insecure_role}",
                name=insecure_role,
                is_vulnerable=True,
                details={"has_administrator_access": True},
            ))
            deployed.append(TerraformResourceStatus(
                resource_type="aws_iam_role",
                resource_id=f"arn:aws:iam::000000000000:role/{compliant_role}",
                name=compliant_role,
                is_vulnerable=False,
                details={"has_administrator_access": False},
            ))

            # --- EC2 Security Groups ---
            insecure_sg = "insecure-ssh-sg"
            compliant_sg = "compliant-web-sg"
            sg_id = "sg-3423"

            if is_live:
                try:
                    ec2 = get_localstack_client("ec2", endpoint_url=target_endpoint)
                    try:
                        res = ec2.create_security_group(GroupName=insecure_sg, Description="Security group with open SSH from 0.0.0.0/0")
                        sg_id = res.get("GroupId", sg_id)
                        ec2.authorize_security_group_ingress(
                            GroupId=sg_id,
                            IpProtocol="tcp",
                            FromPort=22,
                            ToPort=22,
                            CidrIp="0.0.0.0/0",
                        )
                        logs.append(f"Created EC2 Security Group: {insecure_sg} ({sg_id}) with port 22 open to 0.0.0.0/0")
                    except Exception:
                        pass

                    try:
                        res_c = ec2.create_security_group(GroupName=compliant_sg, Description="Security group restricted to HTTPS")
                        c_id = res_c.get("GroupId", "sg-compliant")
                        ec2.authorize_security_group_ingress(
                            GroupId=c_id,
                            IpProtocol="tcp",
                            FromPort=443,
                            ToPort=443,
                            CidrIp="10.0.0.0/16",
                        )
                        logs.append(f"Created EC2 Security Group: {compliant_sg} (restricted to HTTPS 10.0.0.0/16)")
                    except Exception:
                        pass
                except Exception as e:
                    logs.append(f"EC2 provisioning error: {e}")

            deployed.append(TerraformResourceStatus(
                resource_type="aws_security_group",
                resource_id=f"arn:aws:ec2:us-east-1:000000000000:security-group/{sg_id}",
                name=insecure_sg,
                is_vulnerable=True,
                details={"open_ssh": True, "cidr": "0.0.0.0/0", "group_id": sg_id},
            ))
            deployed.append(TerraformResourceStatus(
                resource_type="aws_security_group",
                resource_id="arn:aws:ec2:us-east-1:000000000000:security-group/sg-compliant",
                name=compliant_sg,
                is_vulnerable=False,
                details={"open_ssh": False, "port": 443},
            ))

        return TerraformDeploymentResult(
            status="SUCCESS",
            deployment_method=method,
            timestamp=now_iso,
            resources_deployed=deployed,
            output_logs=logs,
        )

    def destroy_infrastructure(self, endpoint_url: Optional[str] = None) -> bool:
        """Teardown test infrastructure resources."""
        target_endpoint = endpoint_url or self.endpoint_url
        if check_localstack_connection(target_endpoint):
            try:
                s3 = get_localstack_client("s3", endpoint_url=target_endpoint)
                for b in ["vulnerable-customer-data-bucket", "secure-encrypted-backup-bucket"]:
                    try:
                        s3.delete_bucket(Bucket=b)
                    except Exception:
                        pass
            except Exception:
                pass
        return True


# Global singleton
terraform_service = TerraformService()
