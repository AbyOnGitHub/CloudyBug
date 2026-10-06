import json
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any

from backend.scanner.models import NormalizedFinding

logger = logging.getLogger("trivy_service")
logging.basicConfig(level=logging.INFO)

class TrivyService:
    """
    Trivy Integration for deep inspection of container images and Infrastructure-as-Code.
    """
    def __init__(self):
        self.output_dir = Path("backend/scanner/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _is_trivy_installed(self) -> bool:
        import shutil
        return shutil.which("trivy") is not None

    def scan_iac(self, target_dir: str) -> List[NormalizedFinding]:
        """
        Scans a local directory containing Terraform/CloudFormation files using Trivy.
        Converts results to NormalizedFinding.
        """
        findings = []
        if not self._is_trivy_installed():
            logger.warning("Trivy is not installed. Skipping IaC scan.")
            return findings
            
        cmd = [
            "trivy", "config",
            "--format", "json",
            target_dir
        ]
        
        try:
            logger.info(f"Running Trivy IaC scan on {target_dir}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0 and result.stdout == "":
                logger.error(f"Trivy scan failed: {result.stderr}")
                return findings
                
            report = json.loads(result.stdout)
            for res in report.get("Results", []):
                target = res.get("Target", "Unknown")
                for vuln in res.get("Misconfigurations", []):
                    finding = NormalizedFinding(
                        id=f"trivy-{vuln.get('ID')}",
                        finding_id=f"trivy-iac-{vuln.get('ID')}",
                        title=vuln.get("Title", "Unknown Misconfiguration"),
                        description=vuln.get("Description", ""),
                        severity=vuln.get("Severity", "LOW").upper(),
                        severity_score=self._map_severity(vuln.get("Severity", "LOW")),
                        resource_id=target,
                        resource_type="InfrastructureAsCode",
                        region="local",
                        account_id="000000000000",
                        compliance_status="FAILED",
                        compliance_frameworks=["Trivy Built-in"],
                        recommendation=vuln.get("Resolution", "Fix the misconfiguration in code."),
                        recommendation_url=vuln.get("PrimaryURL", ""),
                        generator_id="trivy-scanner",
                        created_at="" # will be populated in route or defaults
                    )
                    findings.append(finding)
        except Exception as e:
            logger.error(f"Error during Trivy scan: {e}")
            
        return findings

    def _map_severity(self, severity: str) -> int:
        mapping = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 40,
            "LOW": 10,
            "UNKNOWN": 0
        }
        return mapping.get(severity.upper(), 0)
