"""
Dual-Agent Architecture Package:
- Privileged LLM: Reasoning and Tool Orchestrator
- Quarantined LLM: Isolated Cloud Metadata Sanitizer & Prompt Injection Firewall
- Strict JSON Communication Boundary
"""

from backend.agents.models import (
    SanitizedCloudPayload,
    SanitizedResource,
    SanitizedSecurityGroup,
    SanitizedS3Bucket,
    SanitizedIAMRole,
    InjectionDetectionResult,
    DualAgentAuditResponse,
)
from backend.agents.quarantined_llm import QuarantinedSanitizerAgent
from backend.agents.privileged_llm import PrivilegedOrchestratorAgent
from backend.agents.dual_agent_coordinator import DualAgentCoordinator, dual_agent_coordinator

__all__ = [
    "QuarantinedSanitizerAgent",
    "PrivilegedOrchestratorAgent",
    "DualAgentCoordinator",
    "dual_agent_coordinator",
    "SanitizedCloudPayload",
    "SanitizedResource",
    "SanitizedSecurityGroup",
    "SanitizedS3Bucket",
    "SanitizedIAMRole",
    "InjectionDetectionResult",
    "DualAgentAuditResponse",
]
