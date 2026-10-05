import uuid
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.agents.models import (
    SanitizedCloudPayload,
    OrchestrationAction,
    DualAgentAuditResponse,
)
from backend.agents.quarantined_llm import QuarantinedSanitizerAgent

logger = logging.getLogger("dual_agent.privileged_llm")


class SecurityBoundaryViolationError(Exception):
    """Raised when communication from untrusted domains violates the strict JSON boundary."""
    pass


class PrivilegedOrchestratorAgent:
    """
    Privileged LLM Agent.
    - Receives user instructions and goals from FastAPI.
    - Performs reasoning, risk prioritization, and tool orchestration.
    - NEVER touches raw Cloud API metadata directly.
    - Consumes ONLY strictly validated JSON schemas from the Quarantined LLM.
    - Formulates actionable remediation plans and enforces Human Approval gating.
    """

    def __init__(self, quarantined_agent: Optional[QuarantinedSanitizerAgent] = None):
        self.agent_id = "privileged-orchestrator-agent-v1"
        self.quarantined_agent = quarantined_agent or QuarantinedSanitizerAgent()

    def validate_incoming_payload(self, raw_payload: Any) -> SanitizedCloudPayload:
        """
        Enforce strict JSON invariant boundary:
        Payload MUST be a validated instance of SanitizedCloudPayload or valid strict JSON.
        """
        if isinstance(raw_payload, SanitizedCloudPayload):
            return raw_payload

        if isinstance(raw_payload, str):
            try:
                # Must parse as valid JSON
                parsed_json = json.loads(raw_payload)
                return SanitizedCloudPayload.model_validate(parsed_json)
            except Exception as e:
                raise SecurityBoundaryViolationError(
                    f"Strict JSON boundary rejected invalid quarantined payload: {e}"
                )

        if isinstance(raw_payload, dict):
            try:
                return SanitizedCloudPayload.model_validate(raw_payload)
            except Exception as e:
                raise SecurityBoundaryViolationError(
                    f"Strict JSON boundary rejected invalid quarantined payload dictionary: {e}"
                )

        raise SecurityBoundaryViolationError(
            f"Expected structured JSON or SanitizedCloudPayload, received {type(raw_payload)}"
        )

    async def orchestrate_security_audit(
        self,
        user_intent: str = "Perform cloud security audit and formulate remediation plan",
        target_services: Optional[List[str]] = None,
        injected_mock_data: Optional[Dict[str, Any]] = None,
    ) -> DualAgentAuditResponse:
        """
        Execute the Dual-Agent audit pipeline:
        1. Privileged LLM requests sanitized cloud metadata from Quarantined LLM.
        2. Strict JSON boundary validates data integrity.
        3. Privileged LLM performs cognitive reasoning and tool orchestration.
        4. Broadcasts NDJSON events to connected WebSocket clients.
        """
        services = target_services or ["ec2", "iam", "s3"]
        now_iso = datetime.now(timezone.utc).isoformat()
        from backend.api.websocket_manager import manager

        logger.info(f"[{self.agent_id}] Initiating orchestration for user intent: '{user_intent}'")

        # Broadcast start of privileged reasoning
        await manager.broadcast_ndjson({
            "event": "DUAL_AGENT_STARTED",
            "orchestrator": self.agent_id,
            "user_intent": user_intent,
            "message": "Privileged LLM orchestrating cloud security audit...",
            "timestamp": now_iso,
        })

        # Step 1: Delegate cloud metadata ingestion to Quarantined LLM
        logger.info(f"[{self.agent_id}] Calling Quarantined LLM to sanitize cloud APIs...")
        quarantined_output = self.quarantined_agent.fetch_and_sanitize_cloud_metadata(
            services=services, injected_mock_data=injected_mock_data
        )

        # Step 2: Validate strict JSON boundary
        sanitized_payload = self.validate_incoming_payload(quarantined_output)
        logger.info(
            f"[{self.agent_id}] Ingested {sanitized_payload.total_resources_scanned} sanitized resources. "
            f"Prompt injections neutralized: {sanitized_payload.total_injections_neutralized}"
        )

        await manager.broadcast_ndjson({
            "event": "QUARANTINE_SANITIZATION_COMPLETE",
            "sanitizer": sanitized_payload.sanitizer_agent,
            "total_scanned": sanitized_payload.total_resources_scanned,
            "injections_neutralized": sanitized_payload.total_injections_neutralized,
            "message": f"Quarantined LLM neutralized {sanitized_payload.total_injections_neutralized} prompt injections.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Step 3: Privileged LLM Reasoning & Planning
        reasoning_trace: List[Dict[str, Any]] = []
        orchestration_plan: List[OrchestrationAction] = []

        # Trace 1: Observation
        reasoning_trace.append({
            "agent": "PrivilegedLLM",
            "node": "Observation",
            "thought": (
                f"Ingested {sanitized_payload.total_resources_scanned} validated cloud resources via strict JSON boundary. "
                f"Zero prompt injection tokens entered the privileged context window."
            ),
            "decision": "DATA_INGESTION_SECURE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Trace 2: Reasoning on Security Groups
        for sg in sanitized_payload.security_groups:
            if sg.has_unrestricted_ssh:
                action_id = f"act-{uuid.uuid4().hex[:6]}"
                plan_item = OrchestrationAction(
                    action_id=action_id,
                    target_resource=sg.resource_id,
                    service="EC2",
                    action_type="REVOKE_SECURITY_GROUP_INGRESS",
                    reasoning=f"Security Group '{sg.resource_name}' permits ingress 0.0.0.0/0 on port 22 (SSH). Threat: brute force.",
                    cli_command=f"aws ec2 revoke-security-group-ingress --group-id {sg.resource_id} --protocol tcp --port 22 --cidr 0.0.0.0/0",
                    requires_human_approval=True,
                )
                orchestration_plan.append(plan_item)

        # Trace 3: Reasoning on S3 Buckets
        for bucket in sanitized_payload.s3_buckets:
            if not bucket.public_access_blocked:
                action_id = f"act-{uuid.uuid4().hex[:6]}"
                plan_item = OrchestrationAction(
                    action_id=action_id,
                    target_resource=bucket.bucket_name,
                    service="S3",
                    action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
                    reasoning=f"S3 Bucket '{bucket.bucket_name}' has incomplete public access block settings.",
                    cli_command=f'aws s3api put-public-access-block --bucket {bucket.bucket_name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
                    requires_human_approval=True,
                )
                orchestration_plan.append(plan_item)

        # Trace 4: Reasoning on IAM Roles
        for role in sanitized_payload.iam_roles:
            if role.has_administrator_access:
                action_id = f"act-{uuid.uuid4().hex[:6]}"
                plan_item = OrchestrationAction(
                    action_id=action_id,
                    target_resource=role.role_name,
                    service="IAM",
                    action_type="DETACH_IAM_ADMIN_POLICY",
                    reasoning=f"IAM Role '{role.role_name}' has AdministratorAccess policy (*:* wildcard).",
                    cli_command=f"aws iam detach-role-policy --role-name {role.role_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    requires_human_approval=True,
                )
                orchestration_plan.append(plan_item)

        # Trace 5: Risk Assessment & Final Plan Synthesis
        reasoning_trace.append({
            "agent": "PrivilegedLLM",
            "node": "RiskAssessment",
            "thought": (
                f"Synthesized {len(orchestration_plan)} high-priority remediation actions. "
                f"Gated execution behind human authorization to preserve infrastructure safety."
            ),
            "decision": "PLAN_READY_AWAITING_APPROVAL",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Broadcast orchestration plan ready as NDJSON
        await manager.broadcast_ndjson({
            "event": "ORCHESTRATION_PLAN_READY",
            "total_actions": len(orchestration_plan),
            "actions": [a.model_dump() for a in orchestration_plan],
            "message": f"Privileged LLM formulated {len(orchestration_plan)} remediation actions awaiting approval.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        response = DualAgentAuditResponse(
            status="SUCCESS",
            user_intent=user_intent,
            sanitization_summary={
                "sanitizer_agent": sanitized_payload.sanitizer_agent,
                "total_resources_scanned": sanitized_payload.total_resources_scanned,
                "injections_neutralized": sanitized_payload.total_injections_neutralized,
                "threat_detections": [d.model_dump() for d in sanitized_payload.injection_audit_log],
            },
            reasoning_trace=reasoning_trace,
            orchestration_plan=orchestration_plan,
            sanitized_payload=sanitized_payload,
            requires_approval=len(orchestration_plan) > 0,
        )

        return response
