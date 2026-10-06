import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger("opa_service")
logging.basicConfig(level=logging.INFO)

class OPAService:
    """
    Open Policy Agent (OPA) Integration.
    Evaluates proposed infrastructure modifications against Rego policies
    before they are presented to the user or executed.
    """
    def __init__(self):
        self.policy_dir = Path(__file__).parent / "policies"
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        self.policy_path = self.policy_dir / "agent_policy.rego"

    def validate_action(self, action: str, resource_metadata: Dict[str, Any]) -> bool:
        """
        Validates an infrastructure modification against OPA Rego policies.
        Returns True if the action is permitted, False otherwise.
        """
        input_data = {
            "action": action,
            **resource_metadata
        }
        
        try:
            # In a real environment, we would use the `opa` CLI or a REST API to an OPA server.
            # Example: opa eval -d policy.rego -i input.json "data.cloud.security.agent.allow"
            if self._is_opa_installed():
                return self._evaluate_with_cli(input_data)
            else:
                logger.warning("OPA CLI not found. Using fallback Rego evaluation logic.")
                return self._fallback_eval(input_data)
        except Exception as e:
            logger.error(f"OPA evaluation failed: {e}")
            return False

    def _is_opa_installed(self) -> bool:
        import shutil
        return shutil.which("opa") is not None

    def _evaluate_with_cli(self, input_data: Dict[str, Any]) -> bool:
        input_file = self.policy_dir / "temp_input.json"
        with open(input_file, "w") as f:
            json.dump(input_data, f)
            
        cmd = [
            "opa", "eval",
            "-d", str(self.policy_path),
            "-i", str(input_file),
            "data.cloud.security.agent.allow"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if input_file.exists():
            input_file.unlink()
            
        if result.returncode == 0:
            output = json.loads(result.stdout)
            try:
                is_allowed = output.get("result", [])[0].get("expressions", [])[0].get("value", False)
                return is_allowed
            except IndexError:
                return False
        return False

    def _fallback_eval(self, input_data: Dict[str, Any]) -> bool:
        """Fallback Python logic representing the Rego rules if OPA is not installed."""
        action = input_data.get("action", "")
        
        # Deny attaching AdministratorAccess
        if action == "iam:AttachRolePolicy" and "AdministratorAccess" in input_data.get("policy_arn", ""):
            return False
            
        # Deny deleting resources in production
        if action.startswith("s3:Delete") and input_data.get("environment") == "production":
            return False
            
        return True
