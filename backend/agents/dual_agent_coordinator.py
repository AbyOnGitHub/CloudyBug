import logging
from typing import List, Dict, Any, Optional

from backend.agents.models import DualAgentAuditResponse, SanitizedCloudPayload
from backend.agents.quarantined_llm import QuarantinedSanitizerAgent
from backend.agents.privileged_llm import PrivilegedOrchestratorAgent

logger = logging.getLogger("dual_agent.coordinator")


class DualAgentCoordinator:
    """
    Coordinates the Dual-Agent Architecture:
      User
        ↓
      FastAPI
        ↓
      Privileged LLM (Reasoning & Tool Orchestration)
        ↓
      Quarantined LLM (Metadata Sanitization & Prompt Injection Defense)
        ↓
      Cloud APIs (LocalStack / AWS)
    """

    def __init__(self):
        self.quarantined_agent = QuarantinedSanitizerAgent()
        self.privileged_agent = PrivilegedOrchestratorAgent(
            quarantined_agent=self.quarantined_agent
        )

    async def execute_user_request(
        self,
        user_request: str = "Scan cloud infrastructure for security posture violations and propose remediation",
        services: Optional[List[str]] = None,
        injected_mock_data: Optional[Dict[str, Any]] = None,
    ) -> DualAgentAuditResponse:
        """Process user request through Privileged LLM -> Quarantined LLM -> Cloud APIs."""
        logger.info(f"DualAgentCoordinator processing: '{user_request}'")
        return await self.privileged_agent.orchestrate_security_audit(
            user_intent=user_request,
            target_services=services,
            injected_mock_data=injected_mock_data,
        )

    def test_quarantine_sanitizer(
        self,
        raw_metadata: Dict[str, Any],
    ) -> SanitizedCloudPayload:
        """Directly evaluate raw untrusted metadata through the Quarantined LLM firewall."""
        return self.quarantined_agent.fetch_and_sanitize_cloud_metadata(
            injected_mock_data=raw_metadata
        )


# Global singleton instance
dual_agent_coordinator = DualAgentCoordinator()
