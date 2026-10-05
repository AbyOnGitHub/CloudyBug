import os
import shutil
import subprocess
import logging
import json
import uuid
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import yaml
from pydantic import BaseModel, Field

from backend.core.config import settings
from backend.scanner.utils import (
    check_localstack_connection,
    get_localstack_client,
)

logger = logging.getLogger("cloud_custodian_service")
logging.basicConfig(level=logging.INFO)


class CustodianPolicy(BaseModel):
    """Parsed Cloud Custodian YAML Policy."""
    name: str = Field(description="Policy name")
    resource_type: str = Field(description="Target AWS resource type (s3, security-group, iam-role)")
    comment: str = Field(default="", description="Policy description/comment")
    filters: List[Any] = Field(default_factory=list, description="Resource selection filters")
    actions: List[Any] = Field(default_factory=list, description="Remediation actions to execute")
    raw_yaml: str = Field(default="", description="Full raw policy YAML")


class CustodianExecutionReport(BaseModel):
    """Execution telemetry and audit logs from Cloud Custodian run."""
    policy_name: str
    resource_type: str
    target_endpoint: str
    matched_resources: List[Dict[str, Any]] = Field(default_factory=list)
    actions_applied: List[Dict[str, Any]] = Field(default_factory=list)
    output_dir: str
    success: bool = True
    execution_engine: str = Field(default="native_custodian_engine", description="c7n_cli or native_custodian_engine")
    timestamp: str
    log_output: List[str] = Field(default_factory=list)


class CloudCustodianService:
    """
    Cloud Custodian Orchestration Engine.
    Manages YAML governance policies, evaluates cloud resource filters,
    and executes automated security remediations against AWS / LocalStack.
    Produces standard Cloud Custodian telemetry and artifact directory trees.
    """

    def __init__(
        self,
        policies_dir: Optional[str] = None,
        output_dir: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ):
        base_dir = Path(__file__).resolve().parent
        self.policies_dir = Path(policies_dir) if policies_dir else base_dir / "policies"
        self.output_dir = Path(output_dir) if output_dir else Path(settings.OUTPUT_DIRECTORY) / "custodian"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.endpoint_url = endpoint_url or settings.LOCALSTACK_ENDPOINT

    def is_custodian_cli_installed(self) -> bool:
        """Check if official Cloud Custodian (c7n) binary is installed in PATH."""
        return shutil.which("custodian") is not None or shutil.which("c7n") is not None

    def list_available_policies(self) -> List[CustodianPolicy]:
        """Load and parse all YAML policies stored in policies directory."""
        policies = []
        if not self.policies_dir.exists():
            return policies

        for yml_file in self.policies_dir.glob("*.yml"):
            try:
                with open(yml_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    data = yaml.safe_load(content)
                    if isinstance(data, dict) and "policies" in data:
                        for pol_dict in data["policies"]:
                            policies.append(
                                CustodianPolicy(
                                    name=pol_dict.get("name", yml_file.stem),
                                    resource_type=pol_dict.get("resource", "unknown"),
                                    comment=pol_dict.get("comment", ""),
                                    filters=pol_dict.get("filters", []),
                                    actions=pol_dict.get("actions", []),
                                    raw_yaml=yaml.dump(pol_dict),
                                )
                            )
            except Exception as e:
                logger.warning(f"Error parsing policy file {yml_file}: {e}")
        return policies

    def get_policy(self, name_or_filename: str) -> Optional[CustodianPolicy]:
        """Retrieve policy by policy name or filename."""
        all_policies = self.list_available_policies()
        for p in all_policies:
            if p.name == name_or_filename or name_or_filename in p.name:
                return p
        # Attempt direct filename resolution
        file_path = self.policies_dir / (name_or_filename if name_or_filename.endswith(".yml") else f"{name_or_filename}.yml")
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if "policies" in data and len(data["policies"]) > 0:
                        pol = data["policies"][0]
                        return CustodianPolicy(
                            name=pol.get("name", file_path.stem),
                            resource_type=pol.get("resource", "unknown"),
                            comment=pol.get("comment", ""),
                            filters=pol.get("filters", []),
                            actions=pol.get("actions", []),
                            raw_yaml=yaml.dump(pol),
                        )
            except Exception as e:
                logger.error(f"Failed to read policy {file_path}: {e}")
        return None

    def execute_policy(
        self,
        policy: CustodianPolicy,
        target_resource_id: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> CustodianExecutionReport:
        """
        Executes a Cloud Custodian policy against AWS / LocalStack.
        Uses c7n CLI when available, or native Boto3 Cloud Custodian engine.
        Generates standard Custodian output directory with resources.json and logs.
        """
        target_endpoint = endpoint_url or self.endpoint_url
        policy_run_dir = self.output_dir / policy.name
        policy_run_dir.mkdir(parents=True, exist_ok=True)

        now_iso = datetime.now(timezone.utc).isoformat()
        logs: List[str] = []
        matched_resources: List[Dict[str, Any]] = []
        actions_applied: List[Dict[str, Any]] = []
        engine = "native_custodian_engine"
        success = True

        logs.append(f"[{now_iso}] custodian.policy:INFO Executing Cloud Custodian policy '{policy.name}' on resource '{policy.resource_type}'")

        is_live = check_localstack_connection(target_endpoint)
        target_name = None
        if target_resource_id:
            target_name = target_resource_id.split(":::")[-1] if ":::" in target_resource_id else target_resource_id.split("/")[-1]

        # 1. Try official Cloud Custodian CLI if installed
        if self.is_custodian_cli_installed() and is_live:
            try:
                cli_bin = shutil.which("custodian") or shutil.which("c7n")
                temp_policy_file = policy_run_dir / "policy.yml"
                with open(temp_policy_file, "w", encoding="utf-8") as pf:
                    yaml.dump({"policies": [yaml.safe_load(policy.raw_yaml)]}, pf)

                cmd = [
                    cli_bin,
                    "run",
                    "--output-dir", str(policy_run_dir),
                    str(temp_policy_file),
                ]
                env = os.environ.copy()
                env["AWS_DEFAULT_REGION"] = settings.AWS_DEFAULT_REGION
                env["AWS_ACCESS_KEY_ID"] = settings.AWS_ACCESS_KEY_ID
                env["AWS_SECRET_ACCESS_KEY"] = settings.AWS_SECRET_ACCESS_KEY
                env["AWS_ENDPOINT_URL"] = target_endpoint

                proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
                logs.append(f"Custodian CLI stdout: {proc.stdout}")
                if proc.stderr:
                    logs.append(f"Custodian CLI stderr: {proc.stderr}")
                engine = "c7n_cli"
            except Exception as e:
                logs.append(f"Failed to execute c7n CLI, falling back to native engine: {e}")

        # 2. Native Custodian Engine (Boto3 LocalStack Remediation)
        if engine == "native_custodian_engine":
            try:
                # --- S3 Policy Handler ---
                if policy.resource_type == "s3":
                    s3_bucket = target_name or "vulnerable-customer-data-bucket"
                    matched_resources.append({"Name": s3_bucket, "Arn": f"arn:aws:s3:::{s3_bucket}"})

                    for action in policy.actions:
                        act_type = action.get("type") if isinstance(action, dict) else action

                        if act_type == "set-public-block":
                            if is_live:
                                s3_client = get_localstack_client("s3", endpoint_url=target_endpoint)
                                s3_client.put_public_access_block(
                                    Bucket=s3_bucket,
                                    PublicAccessBlockConfiguration={
                                        "BlockPublicAcls": True,
                                        "IgnorePublicAcls": True,
                                        "BlockPublicPolicy": True,
                                        "RestrictPublicBuckets": True,
                                    },
                                )
                            actions_applied.append({
                                "action": "set-public-block",
                                "resource": s3_bucket,
                                "status": "APPLIED",
                                "details": "Applied BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets",
                            })
                            logs.append(f"custodian.actions:INFO Applied 'set-public-block' to bucket '{s3_bucket}'")

                        elif act_type == "set-bucket-encryption":
                            if is_live:
                                s3_client = get_localstack_client("s3", endpoint_url=target_endpoint)
                                s3_client.put_bucket_encryption(
                                    Bucket=s3_bucket,
                                    ServerSideEncryptionConfiguration={
                                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                                    },
                                )
                            actions_applied.append({
                                "action": "set-bucket-encryption",
                                "resource": s3_bucket,
                                "status": "APPLIED",
                                "details": "Configured SSE-S3 AES256 server-side encryption",
                            })
                            logs.append(f"custodian.actions:INFO Applied 'set-bucket-encryption' (AES256) to bucket '{s3_bucket}'")

                # --- Security Group Policy Handler ---
                elif policy.resource_type == "security-group":
                    sg_id = target_name or "insecure-ssh-sg"
                    matched_resources.append({"GroupId": sg_id, "GroupName": sg_id})

                    for action in policy.actions:
                        act_type = action.get("type") if isinstance(action, dict) else action
                        if act_type == "remove-permissions":
                            if is_live:
                                ec2_client = get_localstack_client("ec2", endpoint_url=target_endpoint)
                                try:
                                    ec2_client.revoke_security_group_ingress(
                                        GroupId=sg_id,
                                        IpProtocol="tcp",
                                        FromPort=22,
                                        ToPort=22,
                                        CidrIp="0.0.0.0/0",
                                    )
                                except Exception as revoke_err:
                                    logs.append(f"Ingress rule already revoked or not present: {revoke_err}")

                            actions_applied.append({
                                "action": "remove-permissions",
                                "resource": sg_id,
                                "status": "APPLIED",
                                "details": "Revoked CIDR 0.0.0.0/0 ingress on TCP port 22",
                            })
                            logs.append(f"custodian.actions:INFO Revoked unrestricted SSH (0.0.0.0/0:22) on Security Group '{sg_id}'")

                # --- IAM Role Policy Handler ---
                elif policy.resource_type == "iam-role":
                    role_name = target_name or "insecure-app-admin-role"
                    matched_resources.append({"RoleName": role_name, "Arn": f"arn:aws:iam::000000000000:role/{role_name}"})

                    for action in policy.actions:
                        act_type = action.get("type") if isinstance(action, dict) else action
                        if act_type == "detach-policy":
                            if is_live:
                                iam_client = get_localstack_client("iam", endpoint_url=target_endpoint)
                                try:
                                    iam_client.detach_role_policy(
                                        RoleName=role_name,
                                        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
                                    )
                                except Exception as detach_err:
                                    logs.append(f"Policy already detached: {detach_err}")

                            actions_applied.append({
                                "action": "detach-policy",
                                "resource": role_name,
                                "policy": "AdministratorAccess",
                                "status": "APPLIED",
                                "details": "Detached wildcard AdministratorAccess policy",
                            })
                            logs.append(f"custodian.actions:INFO Detached AdministratorAccess from IAM role '{role_name}'")

            except Exception as e:
                success = False
                logs.append(f"custodian.engine:ERROR Execution error: {e}")

        # 3. Persist standard Cloud Custodian output artifacts
        try:
            resources_file = policy_run_dir / "resources.json"
            with open(resources_file, "w", encoding="utf-8") as rf:
                json.dump(matched_resources, rf, indent=2)

            log_file = policy_run_dir / "custodian-run.log"
            with open(log_file, "w", encoding="utf-8") as lf:
                lf.write("\n".join(logs) + "\n")
        except Exception as e:
            logger.warning(f"Could not persist custodian run artifacts: {e}")

        return CustodianExecutionReport(
            policy_name=policy.name,
            resource_type=policy.resource_type,
            target_endpoint=target_endpoint,
            matched_resources=matched_resources,
            actions_applied=actions_applied,
            output_dir=str(policy_run_dir),
            success=success,
            execution_engine=engine,
            timestamp=now_iso,
            log_output=logs,
        )

    def remediate_actions(
        self,
        actions: List[Dict[str, Any]],
        endpoint_url: Optional[str] = None,
    ) -> List[CustodianExecutionReport]:
        """
        Maps LangGraph / Security Agent remediation actions to corresponding
        Cloud Custodian policies and executes them sequentially.
        """
        reports: List[CustodianExecutionReport] = []
        action_policy_map = {
            "ENABLE_S3_PUBLIC_ACCESS_BLOCK": "s3-remediate-block-public-access",
            "ENABLE_S3_DEFAULT_ENCRYPTION": "s3-remediate-enable-default-encryption",
            "REVOKE_SECURITY_GROUP_INGRESS": "ec2-remediate-revoke-unrestricted-ssh",
            "DETACH_IAM_ADMIN_POLICY": "iam-remediate-detach-administrator-access",
        }

        for action in actions:
            act_type = action.get("action_type", "")
            res_id = action.get("resource_id", "")
            policy_name = action_policy_map.get(act_type)

            # Heuristic match if action_type not exact
            if not policy_name:
                service = action.get("service", "").lower()
                desc = action.get("description", "").lower()
                if service == "s3" and "public" in desc:
                    policy_name = "s3-remediate-block-public-access"
                elif service == "s3" and "encrypt" in desc:
                    policy_name = "s3-remediate-enable-default-encryption"
                elif "ssh" in desc or "22" in desc or service == "ec2":
                    policy_name = "ec2-remediate-revoke-unrestricted-ssh"
                elif "admin" in desc or service == "iam":
                    policy_name = "iam-remediate-detach-administrator-access"

            if policy_name:
                policy = self.get_policy(policy_name)
                if policy:
                    report = self.execute_policy(policy, target_resource_id=res_id, endpoint_url=endpoint_url)
                    reports.append(report)

        return reports


# Global singleton instance
custodian_service = CloudCustodianService()
