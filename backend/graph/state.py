from typing import TypedDict, List, Dict, Any, Optional


class AttackVector(TypedDict):
    category: str
    severity: str
    affected_resources_count: int
    description: str
    sample_resources: List[str]


class PrioritizedIssue(TypedDict):
    rank: int
    title: str
    severity: str
    resource_id: str
    resource_type: str
    blast_radius: str
    compliance_framework: str
    urgency: str


class RemediationItem(TypedDict):
    issue_title: str
    resource_id: str
    cli_command: str
    terraform_fix: str
    manual_steps: str
    estimated_time_minutes: int


class SecurityTriageState(TypedDict, total=False):
    # Input findings
    findings: List[Dict[str, Any]]

    # Processed states
    total_findings: int
    failed_count: int
    passed_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    # Analysis results
    risk_score: float
    risk_rating: str
    attack_vectors: List[AttackVector]
    prioritized_queue: List[PrioritizedIssue]
    remediation_plans: List[RemediationItem]
    executive_summary: str
    status: str
