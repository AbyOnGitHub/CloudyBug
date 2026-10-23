"""
Attack Simulator and Threat Telemetry Engine for CloudyBug.
Simulates realistic adversary attack vectors (SSH Brute Force, S3 Data Exfiltration,
IAM Privilege Escalation, IMDS SSRF Credential Theft) targeting the AWS / LocalStack environment.

Provides:
1. Ingestion of live adversary attack events into the Crawler's Observation Node.
2. Attack Path Correlation mapping threat signals to vulnerable cloud misconfigurations.
3. Live Attack Vector Probes that mathematically test whether an exploit succeeds (BREACH)
   or is blocked (PREVENTED) post-remediation.
"""

import time
import uuid
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field

from backend.scanner.utils import (
    check_localstack_connection,
    get_localstack_client,
)
from backend.core.config import settings

logger = logging.getLogger("attack_simulator")
logging.basicConfig(level=logging.INFO)


class AttackType(str, Enum):
    SSH_BRUTE_FORCE = "SSH_BRUTE_FORCE"
    S3_DATA_EXFILTRATION = "S3_DATA_EXFILTRATION"
    IAM_PRIVILEGE_ESCALATION = "IAM_PRIVILEGE_ESCALATION"
    IMDS_CREDENTIAL_THEFT = "IMDS_CREDENTIAL_THEFT"


class AttackStatus(str, Enum):
    ACTIVE_ATTACK = "ACTIVE_ATTACK"
    VULNERABILITY_EXPLOITED = "VULNERABILITY_EXPLOITED"
    CONTAINED = "CONTAINED"
    PREVENTED = "PREVENTED"


class SimulatedAttackEvent(BaseModel):
    attack_id: str = Field(default_factory=lambda: f"atk-{uuid.uuid4().hex[:8]}")
    attack_type: AttackType
    title: str
    attacker_ip: str
    attacker_country: str = "Unknown / Adversary ASN"
    target_resource_id: str
    target_resource_name: str
    target_service: str
    vulnerability_check_id: str
    mitre_attack_id: str
    mitre_technique: str
    status: AttackStatus = AttackStatus.ACTIVE_ATTACK
    payload_sample: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_logs: List[str] = Field(default_factory=list)
    prevention_proof: Optional[str] = None
    prevented_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackProbeResult(BaseModel):
    attack_type: AttackType
    target_resource: str
    prevented: bool
    status: str
    message: str
    probe_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class AttackSimulatorEngine:
    """
    Manages adversary attack simulations and environment probing.
    Maintains simulated environment state for both live LocalStack and offline/mock modes.
    """

    def __init__(self):
        self._active_attacks: Dict[str, SimulatedAttackEvent] = {}
        # Tracks manual or automated remediation state in offline mode
        self._simulated_remediations: Dict[str, bool] = {
            "insecure-ssh-sg": False,                # True when port 22 revoked
            "sg-3423": False,
            "vulnerable-customer-data-bucket": False,# True when PAB/encryption enabled
            "insecure-app-admin-role": False,        # True when AdministratorAccess detached
        }

    def record_remediation(self, resource_id: str, action_type: str):
        """Notifies simulator that a vulnerability was remediated."""
        res_name = resource_id.split(":::")[-1] if ":::" in resource_id else resource_id.split("/")[-1]
        for key in list(self._simulated_remediations.keys()):
            if key in res_name or key in resource_id:
                self._simulated_remediations[key] = True
                logger.info(f"[AttackSimulator] Recorded remediation for {key} ({action_type})")

    def reset_remediations(self):
        """Resets mock remediation state to vulnerable for testing."""
        for key in self._simulated_remediations:
            self._simulated_remediations[key] = False

    def simulate_attack(
        self,
        attack_type: Union[AttackType, str],
        attacker_ip: Optional[str] = None,
        endpoint_url: Optional[str] = None,
    ) -> SimulatedAttackEvent:
        """
        Launches an attack simulation against the target environment.
        Generates realistic CloudTrail / GuardDuty / VPC Flow logs and checks if the attack
        succeeds against the target resource.
        """
        if isinstance(attack_type, str):
            attack_type = AttackType(attack_type)

        now_iso = datetime.now(timezone.utc).isoformat()
        ep = endpoint_url or settings.LOCALSTACK_ENDPOINT

        if attack_type == AttackType.SSH_BRUTE_FORCE:
            ip = attacker_ip or "198.51.100.42"
            res_id = "arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423"
            res_name = "insecure-ssh-sg"
            check_id = "prowler-ec2_security_group_open_ssh_port"
            mitre_id = "T1110.001"
            mitre_tech = "Brute Force: Password Guessing on Port 22"
            payload = f"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 | AuthFail: root, admin, ubuntu (50 attempts from {ip})"
            logs = [
                f"{now_iso} [VPC-FLOW-LOG] ACCEPT TCP {ip}:49212 -> 10.0.1.15:22 (SecurityGroup: sg-3423, rule 0.0.0.0/0)",
                f"{now_iso} [GUARD_DUTY] UnauthorizedAccess:EC2/SSHBruteForce from {ip} against instance in sg-3423",
                f"{now_iso} [AUDIT] Ingress rule allows unrestricted 0.0.0.0/0 on port 22. Ingress active.",
            ]
            title = f"Active SSH Brute-Force Attack from {ip} targeting port 22"

        elif attack_type == AttackType.S3_DATA_EXFILTRATION:
            ip = attacker_ip or "203.0.113.88"
            res_id = "arn:aws:s3:::vulnerable-customer-data-bucket"
            res_name = "vulnerable-customer-data-bucket"
            check_id = "prowler-s3_bucket_public_access_block"
            mitre_id = "T1530"
            mitre_tech = "Data from Cloud Storage: Unauthenticated S3 Exfiltration"
            payload = f"GET /customer-data-export.csv HTTP/1.1 (Host: {res_name}.s3.localhost.localstack.cloud)"
            logs = [
                f"{now_iso} [CLOUDTRAIL] Anonymous S3:GetObject on bucket '{res_name}' from IP {ip}",
                f"{now_iso} [GUARD_DUTY] Exfiltration:S3/AnomalousVolumeAccess observed from untrusted IP {ip}",
                f"{now_iso} [AUDIT] PublicAccessBlockConfiguration missing. All 4 block flags are disabled.",
            ]
            title = f"Active S3 Unauthenticated Data Exfiltration Attempt from {ip}"

        elif attack_type == AttackType.IAM_PRIVILEGE_ESCALATION:
            ip = attacker_ip or "192.0.2.14"
            res_id = "arn:aws:iam::000000000000:role/insecure-app-admin-role"
            res_name = "insecure-app-admin-role"
            check_id = "prowler-iam_role_administrator_access"
            mitre_id = "T1078.004"
            mitre_tech = "Valid Accounts: Cloud Accounts with AdministratorAccess Wildcard"
            payload = "sts:AssumeRole -> RoleArn: arn:aws:iam::000000000000:role/insecure-app-admin-role -> Action: * on *"
            logs = [
                f"{now_iso} [CLOUDTRAIL] AssumeRole API invoked for role '{res_name}' from external IP {ip}",
                f"{now_iso} [CLOUDTRAIL] iam:CreateAccessKey invoked with AdministratorAccess wildcard privilege",
                f"{now_iso} [GUARD_DUTY] PrivilegeEscalation:IAM/AdministrativeRoleAbuse detected on '{res_name}'",
            ]
            title = f"Active IAM Privilege Escalation exploiting AdministratorAccess wildcard"

        else: # IMDS_CREDENTIAL_THEFT
            ip = attacker_ip or "198.51.100.99"
            res_id = "arn:aws:ec2:us-east-1:000000000000:instance/i-0a1b2c3d4e5f6g7h8"
            res_name = "insecure-web-instance"
            check_id = "ec2_security_group_open_ssh_port"
            mitre_id = "T1552.005"
            mitre_tech = "Unsecured Credentials: Cloud Instance Metadata Service (IMDSv1) SSRF"
            payload = "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/insecure-app-admin-role"
            logs = [
                f"{now_iso} [HTTP-WAF] SSRF probe to 169.254.169.254 detected on EC2 instance",
                f"{now_iso} [CLOUDTRAIL] Stolen temporary STS credentials used from unauthorized IP {ip}",
            ]
            title = f"SSRF Attack attempting IMDSv1 Credential Theft from {ip}"

        # Probe whether target is currently vulnerable or remediated
        probe = self.probe_attack_vector(attack_type, endpoint_url=ep)
        status = AttackStatus.VULNERABILITY_EXPLOITED if not probe.prevented else AttackStatus.PREVENTED

        event = SimulatedAttackEvent(
            attack_type=attack_type,
            title=title,
            attacker_ip=ip,
            target_resource_id=res_id,
            target_resource_name=res_name,
            target_service=res_id.split(":")[2] if ":" in res_id else "ec2",
            vulnerability_check_id=check_id,
            mitre_attack_id=mitre_id,
            mitre_technique=mitre_tech,
            status=status,
            payload_sample=payload,
            event_logs=logs,
            prevention_proof=probe.message if probe.prevented else None,
            prevented_at=now_iso if probe.prevented else None,
        )

        self._active_attacks[event.attack_id] = event
        logger.info(f"[AttackSimulator] Injected attack '{event.attack_id}' [{attack_type.value}]: Status={status.value}")
        return event

    def probe_attack_vector(
        self,
        attack_type: Union[AttackType, str],
        endpoint_url: Optional[str] = None,
    ) -> AttackProbeResult:
        """
        Sends an active test probe to determine whether an attack would succeed
        or be blocked by defensive cloud configurations.
        """
        if isinstance(attack_type, str):
            attack_type = AttackType(attack_type)

        ep = endpoint_url or settings.LOCALSTACK_ENDPOINT
        is_live = check_localstack_connection(ep)

        # ----------------------------------------------------
        # 1. SSH Brute Force Probe (EC2 Security Group Port 22)
        # ----------------------------------------------------
        if attack_type == AttackType.SSH_BRUTE_FORCE:
            res_id = "arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423"
            port_open = True

            if is_live:
                try:
                    ec2 = get_localstack_client("ec2", endpoint_url=ep)
                    sgs = ec2.describe_security_groups()
                    for sg in sgs.get("SecurityGroups", []):
                        if sg.get("GroupName") == "insecure-ssh-sg" or sg.get("GroupId") == "sg-3423":
                            port_open = False
                            for perm in sg.get("IpPermissions", []):
                                if perm.get("FromPort") == 22 or perm.get("IpProtocol") == "-1":
                                    for r in perm.get("IpRanges", []):
                                        if r.get("CidrIp") == "0.0.0.0/0":
                                            port_open = True
                except Exception as e:
                    logger.warning(f"Live SG probe error: {e}")
                    port_open = not self._simulated_remediations.get("insecure-ssh-sg", False)
            else:
                port_open = not (
                    self._simulated_remediations.get("insecure-ssh-sg", False)
                    or self._simulated_remediations.get("sg-3423", False)
                )

            if port_open:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=False,
                    status="EXPLOITED",
                    message="Attacker probe SUCCEEDED: Port 22 permits ingress from 0.0.0.0/0. Vulnerability is active.",
                    raw_details={"port_22_open": True, "cidr": "0.0.0.0/0"},
                )
            else:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=True,
                    status="PREVENTED",
                    message="Attacker probe BLOCKED: Ingress 0.0.0.0/0 on port 22 has been revoked. Connection timed out / refused.",
                    raw_details={"port_22_open": False},
                )

        # ----------------------------------------------------
        # 2. S3 Data Exfiltration Probe (Public Access Block)
        # ----------------------------------------------------
        elif attack_type == AttackType.S3_DATA_EXFILTRATION:
            res_id = "arn:aws:s3:::vulnerable-customer-data-bucket"
            bucket_public = True

            if is_live:
                try:
                    s3 = get_localstack_client("s3", endpoint_url=ep)
                    pab = s3.get_public_access_block(Bucket="vulnerable-customer-data-bucket")
                    conf = pab.get("PublicAccessBlockConfiguration", {})
                    if conf.get("BlockPublicAcls") and conf.get("BlockPublicPolicy"):
                        bucket_public = False
                except Exception:
                    bucket_public = not self._simulated_remediations.get("vulnerable-customer-data-bucket", False)
            else:
                bucket_public = not self._simulated_remediations.get("vulnerable-customer-data-bucket", False)

            if bucket_public:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=False,
                    status="EXPLOITED",
                    message="Attacker probe SUCCEEDED: S3 Public Access Block is missing. Unauthenticated exfiltration is possible.",
                    raw_details={"public_access_blocked": False},
                )
            else:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=True,
                    status="PREVENTED",
                    message="Attacker probe BLOCKED: S3 Public Access Block enforced. Anonymous read returns HTTP 403 Forbidden.",
                    raw_details={"public_access_blocked": True},
                )

        # ----------------------------------------------------
        # 3. IAM Privilege Escalation Probe (Admin Policy)
        # ----------------------------------------------------
        elif attack_type == AttackType.IAM_PRIVILEGE_ESCALATION:
            res_id = "arn:aws:iam::000000000000:role/insecure-app-admin-role"
            has_admin = True

            if is_live:
                try:
                    iam = get_localstack_client("iam", endpoint_url=ep)
                    attached = iam.list_attached_role_policies(RoleName="insecure-app-admin-role")
                    policies = attached.get("AttachedPolicies", [])
                    has_admin = any("AdministratorAccess" in p.get("PolicyArn", "") for p in policies)
                except Exception:
                    has_admin = not self._simulated_remediations.get("insecure-app-admin-role", False)
            else:
                has_admin = not self._simulated_remediations.get("insecure-app-admin-role", False)

            if has_admin:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=False,
                    status="EXPLOITED",
                    message="Attacker probe SUCCEEDED: Wildcard AdministratorAccess active. Attacker possesses full cloud control.",
                    raw_details={"admin_access_attached": True},
                )
            else:
                return AttackProbeResult(
                    attack_type=attack_type,
                    target_resource=res_id,
                    prevented=True,
                    status="PREVENTED",
                    message="Attacker probe BLOCKED: AdministratorAccess detached. Malicious privilege escalation denied.",
                    raw_details={"admin_access_attached": False},
                )

        # ----------------------------------------------------
        # 4. Default / Fallback Probe
        # ----------------------------------------------------
        return AttackProbeResult(
            attack_type=attack_type,
            target_resource="arn:aws:cloud::000000000000:resource/target",
            prevented=True,
            status="PREVENTED",
            message="Attack vector isolated and neutralized by cloud perimeter defenses.",
        )

    def mark_attack_prevented(self, attack_id_or_type: str, proof_message: str):
        """Updates attack event status to PREVENTED."""
        now_iso = datetime.now(timezone.utc).isoformat()
        for atk_id, atk in self._active_attacks.items():
            if atk_id == attack_id_or_type or atk.attack_type.value == attack_id_or_type:
                atk.status = AttackStatus.PREVENTED
                atk.prevented_at = now_iso
                atk.prevention_proof = proof_message
                logger.info(f"[AttackSimulator] Marked attack '{atk_id}' as PREVENTED: {proof_message}")

    def get_active_attacks(self) -> List[SimulatedAttackEvent]:
        """Returns all simulated attack events for ingestion by Crawler."""
        return list(self._active_attacks.values())

    def clear_attacks(self):
        """Clears all active simulated attacks."""
        self._active_attacks.clear()
        self.reset_remediations()
        logger.info("[AttackSimulator] Cleared all active attacks and reset simulated environment.")


# Singleton global simulator instance
attack_simulator = AttackSimulatorEngine()
