"""
LangGraph State schema for Autonomous Cloud Security Assistant.
Maintains state across Observation, Reasoning, RiskAssessment,
HumanApproval, ExecuteRemediation, VerifyFix, and Finish nodes.

Explicitly tracks:
- vulnerabilities
- recommendations
- cloud_resources
- approval_status
- execution_history (accumulated across node transitions)
- reasoning_trace (accumulated across node transitions)
- timestamps (accumulated per-stage transition timestamps)
"""

import operator
from typing import TypedDict, List, Dict, Any, Optional, Annotated
from pydantic import BaseModel, Field


def merge_dict(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Reducer that merges dictionary updates across state transitions."""
    res = dict(a) if a else {}
    if b:
        res.update(b)
    return res


class VulnerabilityItem(TypedDict, total=False):
    """Normalized security vulnerability record."""
    id: str
    check_id: str
    title: str
    description: str
    severity: str
    severity_score: int
    compliance_status: str
    resource_id: str
    resource_type: str
    service: str
    mitre_attack: Optional[str]


class CloudResourceItem(TypedDict, total=False):
    """Cloud asset metadata tracked during evaluation."""
    arn: str
    name: str
    service: str
    resource_type: str
    region: str
    account_id: str
    tags: Dict[str, str]


class RecommendationItem(TypedDict, total=False):
    """Remediation proposal with actionable code."""
    id: str
    resource_id: str
    resource_type: str
    service: str
    action_type: str  # e.g. "ENABLE_S3_PUBLIC_ACCESS_BLOCK", "DETACH_IAM_ADMIN_POLICY"
    description: str
    cli_command: str
    terraform_snippet: str
    status: str       # "PENDING", "EXECUTED", "FAILED", "VERIFIED"


class RemediationAction(RecommendationItem):
    """Alias for backwards compatibility with earlier graph references."""
    pass


class ApprovalStatus(TypedDict, total=False):
    """Human approval state record."""
    status: str          # "PENDING", "APPROVED", "REJECTED"
    is_approved: bool
    approver: Optional[str]
    feedback: Optional[str]
    decided_at: Optional[str]


class ExecutionResult(TypedDict, total=False):
    """Outcome of a single executed remediation."""
    action_id: str
    resource_id: str
    success: bool
    message: str
    output: Optional[str]


class ExecutionHistoryItem(TypedDict, total=False):
    """Audit log entry appended for each state transition event."""
    event: str
    node: str
    timestamp: str
    success: bool
    details: Dict[str, Any]


class ReasoningTraceItem(TypedDict, total=False):
    """Step-by-step reasoning log recorded at each node."""
    node: str
    timestamp: str
    thought: str
    decision: Optional[str]
    findings_considered: int


class VerificationResult(TypedDict, total=False):
    """Resource post-fix verification result."""
    resource_id: str
    service: str
    check_name: str
    is_compliant: bool
    status: str       # "PASSED", "FAILED"
    details: str


class StateTimestamps(TypedDict, total=False):
    """Lifecycle timestamp records for every graph phase."""
    started_at: str
    observed_at: str
    reasoned_at: str
    assessed_at: str
    approval_paused_at: str
    approved_at: str
    executed_at: str
    verified_at: str
    completed_at: str


class SecurityAssistantState(TypedDict, total=False):
    """
    Custom LangGraph State schema for Autonomous Cloud Security Assistant.
    Supports checkpoint persistence via AsyncPostgresSaver in PostgreSQL.
    """
    # Core User-Requested Attributes
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    cloud_resources: List[Dict[str, Any]]
    approval_status: Dict[str, Any]
    execution_history: Annotated[List[Dict[str, Any]], operator.add]
    reasoning_trace: Annotated[List[Dict[str, Any]], operator.add]
    timestamps: Annotated[Dict[str, str], merge_dict]

    # Session & Runtime Context
    session_id: str
    thread_id: str
    endpoint_url: str
    target_services: List[str]

    # Node 1: Observation
    raw_findings: List[Dict[str, Any]]
    observed_findings: List[Dict[str, Any]]
    total_observed: int
    failed_observed: int
    passed_observed: int

    # Node 2: Reasoning
    need_fix: bool
    reasoning_summary: str
    identified_issues: List[str]

    # Node 3: RiskAssessment
    risk_score: float
    risk_category: str
    blast_radius: str
    remediation_plan: List[RemediationAction]

    # Node 4: HumanApproval
    human_approval_payload: Dict[str, Any]
    is_approved: bool
    approver: str
    approver_feedback: str
    approval_timestamp: str

    # Node 5: ExecuteRemediation
    executed_actions: List[ExecutionResult]
    execution_errors: List[str]
    executed_at: str

    # Node 6: VerifyFix
    verification_results: List[VerificationResult]
    verification_passed: bool
    verified_at: str

    # Node 7: Finish
    final_status: str  # "FIXED", "CLEAN", "REJECTED", "PARTIAL"
    final_report: str
    completed_at: str


class SecurityStateModel(BaseModel):
    """
    Validated Pydantic v2 model representing the custom LangGraph State.
    Ensures rigorous validation for external APIs, checkpoints, and client deserialization.
    """
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list, description="Active security vulnerabilities")
    recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Actionable remediation proposals")
    cloud_resources: List[Dict[str, Any]] = Field(default_factory=list, description="Target cloud infrastructure assets")
    approval_status: Dict[str, Any] = Field(default_factory=dict, description="Human authorization state")
    execution_history: List[Dict[str, Any]] = Field(default_factory=list, description="Audit trail of state transitions")
    reasoning_trace: List[Dict[str, Any]] = Field(default_factory=list, description="Cognitive reasoning steps per node")
    timestamps: Dict[str, str] = Field(default_factory=dict, description="ISO lifecycle timestamps per node")

    session_id: Optional[str] = Field(default=None, description="Current workflow session ID")
    thread_id: Optional[str] = Field(default=None, description="PostgreSQL checkpointer thread identifier")
    final_status: Optional[str] = Field(default=None, description="Terminal status: FIXED, CLEAN, REJECTED, PARTIAL")
    final_report: Optional[str] = Field(default=None, description="Complete executive audit summary")

    @classmethod
    def from_graph_state(cls, state: Dict[str, Any]) -> "SecurityStateModel":
        """Convert runtime LangGraph TypedDict state into a strongly-validated Pydantic model."""
        valid_keys = cls.model_fields.keys()
        payload = {k: v for k, v in state.items() if k in valid_keys and v is not None}
        return cls(**payload)

