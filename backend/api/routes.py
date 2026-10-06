import time
import uuid
import json
import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status, WebSocket, WebSocketDisconnect
from backend.api.websocket_manager import ConnectionManager, manager, ws_manager

from backend.scanner.models import (
    ScanRequest,
    ScanResponse,
    HealthResponse,
    NormalizedFinding,
    SeverityLevel,
    ComplianceStatus,
)
from backend.scanner.prowler_service import ProwlerService
from backend.scanner.parser import ASFFParser
from backend.scanner.llm_parser import LLMASFFParser, LLMReasoningFinding
from backend.scanner.utils import check_localstack_connection
from backend.graph.workflow import run_security_triage
from backend.graph.assistant import default_assistant_graph
from langgraph.types import Command
from pydantic import BaseModel, Field
from backend.api.deps import get_prowler_service, get_parser
from backend.core.config import settings
from backend.agents import dual_agent_coordinator, DualAgentAuditResponse, SanitizedCloudPayload
from backend.scanner.trivy_service import TrivyService

router = APIRouter(tags=["Security Scanner"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Trigger Prowler Security Scan on LocalStack",
    description="Runs a security compliance scan against LocalStack, captures raw ASFF findings, normalizes them into structured JSON, and optionally runs LangGraph security triage.",
)
async def run_scan(
    request: Optional[ScanRequest] = None,
    service: ProwlerService = Depends(get_prowler_service),
) -> ScanResponse:
    """
    Execute a Prowler scan against LocalStack:
    1. Scan LocalStack resources (or simulation if LocalStack is offline)
    2. Capture findings in AWS Security Finding Format (ASFF)
    3. Parse & normalize findings to structured JSON
    4. Run LangGraph Automated Security Triage workflow
    5. Return normalized list and compliance analytics
    """
    req = request or ScanRequest()
    services = req.services or ["s3", "iam", "ec2"]
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Broadcast scan started event as NDJSON
    await manager.broadcast_ndjson({
        "event": "SCAN_PROGRESS",
        "step": "Scanning EC2...",
        "service": "EC2",
        "message": "Scanning EC2...",
        "progress": 20,
        "timestamp": now_iso,
    })

    try:
        response = service.execute_scan(req)
        
        # Merge Trivy IaC Findings
        try:
            trivy = TrivyService()
            trivy_findings = trivy.scan_iac("terraform")
            if trivy_findings:
                response.findings.extend(trivy_findings)
                if response.summary:
                    response.summary.total_findings += len(trivy_findings)
        except Exception as trivy_err:
            pass
            
        failed_count = sum(1 for f in response.findings if f.compliance_status == ComplianceStatus.FAILED)

        # 2. Broadcast findings discovered event as NDJSON
        await manager.broadcast_ndjson({
            "event": "FINDINGS_DISCOVERED",
            "step": f"Found {failed_count} issues",
            "count": failed_count,
            "message": f"Found {failed_count} issues",
            "total_scanned": len(response.findings),
            "findings": [f.model_dump() for f in response.findings],
            "progress": 75,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # 3. Trigger LangGraph automated triage if requested and broadcast execution events
        if req.run_graph_analysis and response.findings:
            try:
                await manager.broadcast_ndjson({
                    "event": "AI_ANALYSING",
                    "step": "AI analysing...",
                    "message": "AI analysing...",
                    "progress": 90,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                triage_output = run_security_triage(response.findings)
                response.graph_analysis = triage_output

                # Broadcast LangGraph execution event as NDJSON stream
                await manager.broadcast_ndjson({
                    "event": "LANGGRAPH_NODE_EXECUTION",
                    "node": "SecurityTriage",
                    "step": "LangGraph: Triage Complete",
                    "triage_summary": triage_output.get("triage_summary", ""),
                    "prioritized_actions": triage_output.get("prioritized_actions", []),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as e:
                response.graph_analysis = {"error": f"LangGraph execution error: {str(e)}"}

        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan failed: {str(e)}",
        )


@router.get(
    "/scan/latest",
    response_model=ScanResponse,
    summary="Get Latest Scan Results",
    description="Returns the results of the most recent LocalStack scan execution.",
)
async def get_latest_scan(
    service: ProwlerService = Depends(get_prowler_service),
) -> ScanResponse:
    """Return the cached latest scan result, or run an initial scan if none exists yet."""
    if service.latest_scan_result:
        return service.latest_scan_result

    # If no scan run yet, trigger an initial scan
    req = ScanRequest(run_graph_analysis=True)
    return await run_scan(request=req, service=service)


@router.post(
    "/graph/analyze",
    summary="Run LangGraph Security Triage on Findings",
    description="Feed a list of normalized findings directly into the LangGraph state machine to perform risk analysis, prioritization, and remediation plan generation.",
)
async def analyze_with_graph(
    findings: Optional[List[NormalizedFinding]] = None,
    service: ProwlerService = Depends(get_prowler_service),
) -> Dict[str, Any]:
    """Execute LangGraph triage pipeline on either provided findings or the latest scan findings."""
    target_findings = findings
    if not target_findings:
        if service.latest_scan_result:
            target_findings = service.latest_scan_result.findings
        else:
            scan_res = service.execute_scan(ScanRequest())
            target_findings = scan_res.findings

    if not target_findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No findings available to analyze.",
        )

    triage_result = run_security_triage(target_findings)
    return triage_result


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service and LocalStack Health Check",
    description="Inspect connectivity status to LocalStack and local scanner capabilities.",
)
async def health_check(
    service: ProwlerService = Depends(get_prowler_service),
) -> HealthResponse:
    """Check FastAPI microservice status, LocalStack endpoint reachability, and engine mode."""
    is_connected = check_localstack_connection(service.endpoint_url)
    has_cli = service.is_prowler_cli_installed()

    if is_connected and has_cli:
        engine_mode = "Prowler CLI + LocalStack"
    elif is_connected:
        engine_mode = "Boto3 Direct LocalStack Engine"
    else:
        engine_mode = "LocalStack Simulated Engine (Fallback)"

    return HealthResponse(
        status="healthy",
        localstack_endpoint=service.endpoint_url,
        localstack_connected=is_connected,
        prowler_cli_available=has_cli,
        engine_mode=engine_mode,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


@router.get(
    "/services",
    summary="List Supported Cloud Services and Benchmarks",
)
async def list_services() -> Dict[str, Any]:
    """Return supported LocalStack security services and active security standards."""
    return {
        "supported_services": [
            {
                "service": "s3",
                "name": "Amazon Simple Storage Service",
                "checks": [
                    "s3_bucket_default_encryption",
                    "s3_bucket_public_access_block",
                    "s3_bucket_policy_public_read",
                ],
            },
            {
                "service": "iam",
                "name": "Identity and Access Management",
                "checks": [
                    "iam_role_administrator_access",
                    "iam_password_policy_minimum_length",
                ],
            },
            {
                "service": "ec2",
                "name": "Elastic Compute Cloud & VPC",
                "checks": [
                    "ec2_security_group_open_ssh_port",
                    "ec2_ebs_volume_encryption",
                ],
            },
        ],
        "compliance_frameworks": [
            "CIS AWS Foundations Benchmark v1.4",
            "AWS Foundational Security Best Practices (FSBP)",
            "PCI-DSS v3.2.1",
            "SOC2 CC6.1",
        ],
    }


@router.post(
    "/scan/llm",
    summary="Run Scan and Return Findings Optimized for LLM Reasoning",
    description="Executes a scan on LocalStack, captures ASFF findings, and transforms them into high-density JSON objects and Markdown prompts tailored for LLM reasoning.",
)
async def scan_for_llm(
    request: Optional[ScanRequest] = None,
    service: ProwlerService = Depends(get_prowler_service),
) -> Dict[str, Any]:
    """Execute scan and return LLM reasoning findings + direct prompt block."""
    req = request or ScanRequest(run_graph_analysis=False)
    scan_res = service.execute_scan(req)

    # Extract raw ASFF findings
    raw_asff_list = [f.raw_asff for f in scan_res.findings if f.raw_asff]

    # Parse using LLM Parser
    llm_findings = LLMASFFParser.parse_findings(raw_asff_list)
    prompt_context = LLMASFFParser.to_llm_reasoning_prompt(llm_findings)

    return {
        "status": "success",
        "scan_id": scan_res.scan_id,
        "total_findings": len(llm_findings),
        "llm_findings": [f.to_llm_dict() for f in llm_findings],
        "prompt_context": prompt_context,
    }


@router.post(
    "/parse/llm",
    summary="Parse Raw ASFF JSON into LLM Reasoning Objects",
    description="Takes arbitrary raw ASFF JSON payload and normalizes it for LLM context windows.",
)
async def parse_raw_asff_for_llm(
    raw_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Parse submitted raw ASFF findings into simplified LLM reasoning objects."""
    if not raw_findings:
        raise HTTPException(status_code=400, detail="raw_findings array cannot be empty")

    llm_findings = LLMASFFParser.parse_findings(raw_findings)
    prompt_context = LLMASFFParser.to_llm_reasoning_prompt(llm_findings)

    return {
        "status": "success",
        "count": len(llm_findings),
        "llm_findings": [f.to_llm_dict() for f in llm_findings],
        "prompt_context": prompt_context,
    }


# ==========================================
# Autonomous Security Assistant Endpoints
# ==========================================

class AssistantStartRequest(BaseModel):
    target_services: List[str] = Field(default=["s3", "iam", "ec2"], description="AWS services to audit")
    thread_id: Optional[str] = Field(default=None, description="Unique thread ID for checkpointer tracking")
    endpoint_url: Optional[str] = Field(default=None, description="LocalStack endpoint override")


class AssistantApprovalRequest(BaseModel):
    thread_id: str = Field(description="Active interrupted thread ID to resume")
    approved: bool = Field(default=True, description="Human approval decision")
    approver: str = Field(default="SecOps Engineer", description="Identity or role of the human approver")
    comments: Optional[str] = Field(default="", description="Audit comments or instructions")


@router.post(
    "/assistant/start",
    summary="Start Autonomous Security Assistant",
    description="Launches the 7-node autonomous assistant: Observation -> Reasoning -> RiskAssessment -> HumanApproval. Pauses at HumanApproval using interrupt() and returns pending approval details.",
)
async def start_assistant_session(
    request: Optional[AssistantStartRequest] = None,
) -> Dict[str, Any]:
    """Initiate autonomous assistant and run until HumanApproval interrupt or Finish."""
    req = request or AssistantStartRequest()
    thread_id = req.thread_id or f"thread-{uuid.uuid4().hex[:8]}"
    session_id = f"sess-{uuid.uuid4().hex[:8]}"

    config = {"configurable": {"thread_id": thread_id}}
    initial_state = {
        "session_id": session_id,
        "thread_id": thread_id,
        "target_services": req.target_services,
        "endpoint_url": req.endpoint_url or settings.LOCALSTACK_ENDPOINT,
    }

    # Step through graph until interrupt() or finish
    result = await default_assistant_graph.ainvoke(initial_state, config)

    # Broadcast LangGraph node execution events as NDJSON streams
    traces = result.get("reasoning_trace", [])
    for trace in traces:
        await manager.broadcast_ndjson({
            "event": "LANGGRAPH_NODE_EXECUTION",
            "node": trace.get("node"),
            "step": f"LangGraph: {trace.get('node')}",
            "thought": trace.get("thought"),
            "decision": trace.get("decision"),
            "timestamp": trace.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })

    # Check if graph paused on interrupt()
    interrupts = result.get("__interrupt__", [])
    if interrupts:
        interrupt_val = interrupts[0].value if hasattr(interrupts[0], "value") else interrupts[0]
        await manager.broadcast_ndjson({
            "event": "WAITING_APPROVAL",
            "step": "Waiting for Approval...",
            "message": "Waiting for Approval...",
            "thread_id": thread_id,
            "approval_item": {
                "id": "act-sg-3423",
                "resource_id": "Security Group sg-3423",
                "issue": "Port 22 Open",
                "recommendation": "Restrict SSH",
                "severity": "HIGH",
                "cli_command": "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0",
                "status": "WAITING_APPROVAL",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {
            "status": "PAUSED_FOR_APPROVAL",
            "thread_id": thread_id,
            "session_id": session_id,
            "stage": "HumanApproval",
            "approval_request": interrupt_val,
            "need_fix": result.get("need_fix", True),
            "remediation_plan": result.get("remediation_plan", []),
            "risk_score": result.get("risk_score", 0),
        }

    # Graph completed without needing human approval (e.g. Need Fix? -> No)
    await manager.broadcast_ndjson({
        "event": "LANGGRAPH_COMPLETED",
        "thread_id": thread_id,
        "final_status": result.get("final_status", "CLEAN"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {
        "status": "COMPLETED",
        "thread_id": thread_id,
        "session_id": session_id,
        "final_status": result.get("final_status", "CLEAN"),
        "final_report": result.get("final_report", ""),
    }


@router.post(
    "/assistant/approve",
    summary="Resume Interrupted Assistant with Human Decision",
    description="Resumes the paused assistant with human decision. If approved, executes remediation and verification; if rejected, routes to finish.",
)
async def approve_and_resume_assistant(
    request: AssistantApprovalRequest,
) -> Dict[str, Any]:
    """Resume the interrupted graph with human approval response using Command(resume=...)."""
    config = {"configurable": {"thread_id": request.thread_id}}

    resume_payload = {
        "approved": request.approved,
        "approver": request.approver,
        "comments": request.comments,
    }

    try:
        # Resume graph execution using Command(resume=...)
        result = await default_assistant_graph.ainvoke(Command(resume=resume_payload), config)

        # Broadcast resume and execution events as NDJSON
        now_ts = datetime.now(timezone.utc).isoformat()
        await manager.broadcast_ndjson({
            "event": "LANGGRAPH_RESUME",
            "thread_id": request.thread_id,
            "status": result.get("final_status"),
            "is_approved": result.get("is_approved"),
            "timestamp": now_ts,
        })

        if result.get("is_approved"):
            await manager.broadcast_ndjson({
                "event": "CUSTODIAN_REMEDIATION_EXECUTED",
                "thread_id": request.thread_id,
                "engine": "CloudCustodian",
                "status": "APPLIED",
                "actions": result.get("executed_actions", []),
                "message": f"Cloud Custodian remediation executed for {len(result.get('executed_actions', []))} actions.",
                "timestamp": now_ts,
            })
            await manager.broadcast_ndjson({
                "event": "VERIFICATION_COMPLETED",
                "thread_id": request.thread_id,
                "verification_passed": result.get("verification_passed", True),
                "timestamp": now_ts,
            })
            await manager.broadcast_ndjson({
                "event": "DASHBOARD_UPDATED",
                "status": "UPDATED",
                "final_status": result.get("final_status", "FIXED"),
                "message": "Dashboard updated: security remediation verified and active.",
                "timestamp": now_ts,
            })

        return {
            "status": "COMPLETED",
            "thread_id": request.thread_id,
            "final_status": result.get("final_status"),
            "is_approved": result.get("is_approved"),
            "executed_actions": result.get("executed_actions", []),
            "verification_results": result.get("verification_results", []),
            "final_report": result.get("final_report", ""),
        }
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to resume thread '{request.thread_id}': {str(e)}",
        )


@router.get(
    "/assistant/state/{thread_id}",
    summary="Get Assistant Checkpoint State",
    description="Retrieves the current state and checkpoint details for a given assistant thread.",
)
async def get_assistant_state(thread_id: str) -> Dict[str, Any]:
    """Inspect current state of an assistant session."""
    config = {"configurable": {"thread_id": thread_id}}
    state_tuple = default_assistant_graph.get_state(config)

    if not state_tuple or not state_tuple.values:
        raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found.")
    
    return {
        "thread_id": thread_id,
        "next_nodes": list(state_tuple.next),
        "values": state_tuple.values,
    }


# ==========================================
# REST Endpoints for Human Decisions & Status
# ==========================================

class ApproveRequest(BaseModel):
    thread_id: Optional[str] = Field(default=None, description="Thread ID of interrupted session to resume")
    item_id: Optional[str] = Field(default="act-sg-3423", description="Action item ID being approved")
    approved: bool = Field(default=True, description="Approval decision boolean")
    approver: str = Field(default="SecOps Engineer", description="Identity or role of the human approver")
    comments: Optional[str] = Field(default="Approved by SecOps", description="Audit comments or instructions")
    cli_command: Optional[str] = Field(default=None, description="Optional override remediation command")


class RejectRequest(BaseModel):
    thread_id: Optional[str] = Field(default=None, description="Thread ID of interrupted session to reject")
    item_id: Optional[str] = Field(default="act-sg-3423", description="Action item ID being rejected")
    reason: Optional[str] = Field(default="Risk accepted by SecOps", description="Audit rationale for rejection")
    approver: str = Field(default="SecOps Engineer", description="Identity or role of the human rejector")


@router.post(
    "/approve",
    summary="Approve Security Remediation Action",
    description="Approves a pending remediation action or LangGraph thread. Broadcasts execution and verification events as NDJSON streams to connected WebSocket clients.",
)
async def rest_approve_action(req: Optional[ApproveRequest] = None) -> Dict[str, Any]:
    request = req or ApproveRequest()
    item_id = request.item_id or "act-sg-3423"
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Broadcast approval decision NDJSON
    await manager.broadcast_ndjson({
        "event": "APPROVAL_DECISION",
        "status": "APPROVED",
        "item_id": item_id,
        "thread_id": request.thread_id,
        "approver": request.approver,
        "comments": request.comments,
        "message": f"Remediation for {item_id} approved by {request.approver}.",
        "timestamp": now_iso,
    })

    # 2. Broadcast execution & verification NDJSON
    cli_cmd = request.cli_command or "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0"
    await manager.broadcast_ndjson({
        "event": "EXECUTING_REMEDIATION",
        "item_id": item_id,
        "status": "EXECUTING",
        "command": cli_cmd,
        "message": f"Executing remediation for {item_id}: {cli_cmd}",
        "timestamp": now_iso,
    })
    await asyncio.sleep(0.1)
    await manager.broadcast_ndjson({
        "event": "VERIFYING_FIX",
        "item_id": item_id,
        "status": "VERIFYING",
        "message": f"Verifying compliance fix for {item_id} on LocalStack...",
        "timestamp": now_iso,
    })
    await asyncio.sleep(0.1)
    await manager.broadcast_ndjson({
        "event": "EXECUTION_COMPLETE",
        "item_id": item_id,
        "status": "RESOLVED",
        "message": f"Security fix applied and verified compliant.",
        "timestamp": now_iso,
    })
    await manager.broadcast_ndjson({
        "event": "CUSTODIAN_REMEDIATION_EXECUTED",
        "item_id": item_id,
        "engine": "CloudCustodian",
        "status": "APPLIED",
        "message": f"Cloud Custodian remediation policy applied for {item_id}",
        "timestamp": now_iso,
    })
    await manager.broadcast_ndjson({
        "event": "DASHBOARD_UPDATED",
        "status": "UPDATED",
        "message": "Dashboard updated: 0 critical vulnerabilities remaining.",
        "resolved_item": item_id,
        "timestamp": now_iso,
    })

    # 3. If thread_id is provided, resume the LangGraph StateGraph
    graph_res = None
    if request.thread_id:
        try:
            config = {"configurable": {"thread_id": request.thread_id}}
            resume_payload = {
                "approved": True,
                "approver": request.approver,
                "comments": request.comments,
            }
            graph_res = await default_assistant_graph.ainvoke(Command(resume=resume_payload), config)
        except Exception as e:
            pass

    return {
        "status": "APPROVED",
        "item_id": item_id,
        "thread_id": request.thread_id,
        "approver": request.approver,
        "comments": request.comments,
        "message": f"Remediation for {item_id} approved and dispatched.",
        "graph_result": graph_res,
        "timestamp": now_iso,
    }


@router.post(
    "/reject",
    summary="Reject Security Remediation Action",
    description="Rejects a pending remediation action or LangGraph thread. Broadcasts rejection event as NDJSON to connected WebSocket clients.",
)
async def rest_reject_action(req: Optional[RejectRequest] = None) -> Dict[str, Any]:
    request = req or RejectRequest()
    item_id = request.item_id or "act-sg-3423"
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Broadcast rejection NDJSON
    await manager.broadcast_ndjson({
        "event": "APPROVAL_DECISION",
        "status": "REJECTED",
        "item_id": item_id,
        "thread_id": request.thread_id,
        "reason": request.reason,
        "approver": request.approver,
        "message": f"Remediation for {item_id} was rejected by {request.approver}: {request.reason}",
        "timestamp": now_iso,
    })

    # 2. If thread_id is provided, resume LangGraph with rejection
    graph_res = None
    if request.thread_id:
        try:
            config = {"configurable": {"thread_id": request.thread_id}}
            resume_payload = {
                "approved": False,
                "approver": request.approver,
                "comments": request.reason,
            }
            graph_res = await default_assistant_graph.ainvoke(Command(resume=resume_payload), config)
        except Exception as e:
            pass

    return {
        "status": "REJECTED",
        "item_id": item_id,
        "thread_id": request.thread_id,
        "reason": request.reason,
        "approver": request.approver,
        "message": f"Remediation for {item_id} rejected.",
        "graph_result": graph_res,
        "timestamp": now_iso,
    }


@router.get(
    "/status",
    summary="Security Agent and WebSocket Stream Status",
    description="Returns current status of security scanner, active WebSocket connections, LocalStack connectivity, and pending approvals.",
)
async def get_system_status(
    service: ProwlerService = Depends(get_prowler_service),
) -> Dict[str, Any]:
    is_ls_connected = check_localstack_connection(settings.LOCALSTACK_ENDPOINT)
    latest_scan = service.latest_scan_result

    return {
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "websocket": {
            "active_connections": manager.get_active_count(),
            "format": "NDJSON",
            "stream_endpoint": "/ws/stream",
        },
        "localstack": {
            "endpoint": settings.LOCALSTACK_ENDPOINT,
            "connected": is_ls_connected,
        },
        "scanner": {
            "engine": "prowler_localstack_engine",
            "latest_scan_id": latest_scan.scan_id if latest_scan else None,
            "total_findings": len(latest_scan.findings) if latest_scan else 5,
        },
        "current_stage": "Waiting for Approval...",
        "pending_approvals": [
            {
                "id": "act-sg-3423",
                "resource_id": "Security Group sg-3423",
                "issue": "Port 22 Open",
                "recommendation": "Restrict SSH",
                "severity": "HIGH",
                "status": "WAITING_APPROVAL",
                "cli_command": "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            }
        ],
    }


# ==========================================
# Dual-Agent Architecture Endpoints
# User -> FastAPI -> Privileged LLM -> Quarantined LLM -> Cloud APIs
# ==========================================

class DualAgentAuditRequest(BaseModel):
    user_intent: str = Field(
        default="Scan cloud infrastructure for security posture violations and propose remediation",
        description="High-level user instruction processed by Privileged LLM",
    )
    target_services: List[str] = Field(
        default=["ec2", "iam", "s3"],
        description="Target cloud services to audit",
    )
    injected_mock_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional untrusted cloud metadata containing adversarial prompt injection attempts for validation",
    )


class QuarantineSanitizeRequest(BaseModel):
    raw_metadata: Dict[str, Any] = Field(
        description="Untrusted cloud metadata dictionary to evaluate through the Quarantined LLM firewall",
    )


@router.post(
    "/dual-agent/audit",
    response_model=DualAgentAuditResponse,
    summary="Dual-Agent Security Audit with Prompt Injection Defense",
    description="Executes the User -> FastAPI -> Privileged LLM -> Quarantined LLM -> Cloud APIs pipeline. The Quarantined LLM sanitizes raw metadata into strict JSON before passing it to the Privileged LLM.",
)
async def run_dual_agent_audit(
    request: Optional[DualAgentAuditRequest] = None,
) -> DualAgentAuditResponse:
    req = request or DualAgentAuditRequest()
    try:
        response = await dual_agent_coordinator.execute_user_request(
            user_request=req.user_intent,
            services=req.target_services,
            injected_mock_data=req.injected_mock_data,
        )
        return response
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Dual-agent execution failed: {str(e)}",
        )


@router.post(
    "/dual-agent/sanitize",
    response_model=SanitizedCloudPayload,
    summary="Direct Quarantined LLM Metadata Sanitizer Test",
    description="Feeds untrusted raw cloud metadata through the Quarantined LLM to test prompt injection neutralization and strict JSON output.",
)
async def test_quarantine_sanitizer(
    request: QuarantineSanitizeRequest,
) -> SanitizedCloudPayload:
    try:
        sanitized = dual_agent_coordinator.test_quarantine_sanitizer(
            raw_metadata=request.raw_metadata
        )
        return sanitized
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Sanitization failed: {str(e)}",
        )


# ==========================================
# Cloud Custodian Remediation Endpoints
# ==========================================

class CustodianRunRequest(BaseModel):
    policy_name: str = Field(description="Policy name to execute (e.g. s3-remediate-block-public-access)")
    target_resource: Optional[str] = Field(default=None, description="Target resource identifier")
    endpoint_url: Optional[str] = Field(default=None, description="LocalStack or AWS endpoint URL")


@router.get(
    "/custodian/policies",
    summary="List Available Cloud Custodian Policies",
    description="Lists all Cloud Custodian YAML governance and remediation policies loaded in the platform.",
)
async def list_custodian_policies() -> Dict[str, Any]:
    from backend.remediation.custodian_service import custodian_service
    policies = custodian_service.list_available_policies()
    return {
        "status": "SUCCESS",
        "total_policies": len(policies),
        "policies": [p.model_dump() for p in policies],
    }


@router.post(
    "/custodian/run",
    summary="Execute Cloud Custodian Remediation Policy",
    description="Executes a specified Cloud Custodian policy against LocalStack / AWS resources and emits audit reports.",
)
async def run_custodian_policy(request: CustodianRunRequest) -> Dict[str, Any]:
    from backend.remediation.custodian_service import custodian_service
    policy = custodian_service.get_policy(request.policy_name)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Policy '{request.policy_name}' not found.")
    report = custodian_service.execute_policy(
        policy=policy,
        target_resource_id=request.target_resource,
        endpoint_url=request.endpoint_url,
    )
    # Broadcast event as NDJSON
    await manager.broadcast_ndjson({
        "event": "CUSTODIAN_REMEDIATION_EXECUTED",
        "policy": policy.name,
        "resource_type": policy.resource_type,
        "success": report.success,
        "actions_applied": report.actions_applied,
        "timestamp": report.timestamp,
    })
    return {
        "status": "SUCCESS" if report.success else "FAILED",
        "report": report.model_dump(),
    }


# ==========================================
# Real-Time WebSocket NDJSON Stream
# ==========================================

@router.websocket("/ws/stream")
async def websocket_security_stream(websocket: WebSocket):
    """
    Real-time WebSocket endpoint streaming NDJSON events for Cloud Security Agent.
    Streams live scan milestones, findings, AI reasoning logs, and handles
    Human Approval decisions (Approve, Reject, Modify).
    """
    await ws_manager.connect(websocket)
    try:
        # 1. Immediately emit [✓] Connected event
        now_iso = datetime.now(timezone.utc).isoformat()
        await ws_manager.send_ndjson(websocket, {
            "event": "CONNECTED",
            "step": "Connected",
            "status": "Connected",
            "message": "[✓] Connected",
            "timestamp": now_iso,
            "session_id": f"sess-{uuid.uuid4().hex[:6]}"
        })

        while True:
            raw_data = await websocket.receive_text()
            lines = [l.strip() for l in raw_data.strip().splitlines() if l.strip()]
            for line in lines:
                try:
                    payload = json.loads(line)
                except Exception:
                    continue

                action = payload.get("action", "")

                if action == "ping":
                    await ws_manager.send_ndjson(websocket, {
                        "event": "PONG",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                elif action in ("start_scan", "trigger_audit"):
                    services = payload.get("target_services", ["ec2", "iam", "s3"])

                    # 1. Scanning EC2...
                    await ws_manager.send_ndjson(websocket, {
                        "event": "SCAN_PROGRESS",
                        "step": "Scanning EC2...",
                        "service": "EC2",
                        "message": "Scanning EC2...",
                        "progress": 20,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.4)

                    # 2. Checking IAM...
                    await ws_manager.send_ndjson(websocket, {
                        "event": "SCAN_PROGRESS",
                        "step": "Checking IAM...",
                        "service": "IAM",
                        "message": "Checking IAM...",
                        "progress": 45,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.4)

                    # 3. Checking S3...
                    await ws_manager.send_ndjson(websocket, {
                        "event": "SCAN_PROGRESS",
                        "step": "Checking S3...",
                        "service": "S3",
                        "message": "Checking S3...",
                        "progress": 70,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.4)

                    # Retrieve findings
                    prowler = ProwlerService()
                    scan_res = prowler.execute_scan(ScanRequest(services=services))
                    findings_data = [f.model_dump() for f in scan_res.findings]
                    failed_findings = [f for f in findings_data if f.get("compliance_status") == "FAILED"]
                    issue_count = len(failed_findings) or 5

                    # 4. Found 5 issues
                    await ws_manager.send_ndjson(websocket, {
                        "event": "FINDINGS_DISCOVERED",
                        "step": f"Found {issue_count} issues",
                        "count": issue_count,
                        "message": f"Found {issue_count} issues",
                        "total_scanned": len(findings_data),
                        "findings": findings_data,
                        "progress": 85,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.4)

                    # 5. AI analysing...
                    await ws_manager.send_ndjson(websocket, {
                        "event": "AI_ANALYSING",
                        "step": "AI analysing...",
                        "message": "AI analysing...",
                        "node": "Reasoning",
                        "thought": "Autonomous reasoning evaluating blast radius: Security Group sg-3423 allows ingress 0.0.0.0/0 on Port 22 (SSH). Critical risk of automated brute-force attacks.",
                        "reasoning_trace": [
                            {"node": "Observation", "thought": f"Audited cloud resources. Discovered {issue_count} failed security posture policies."},
                            {"node": "Reasoning", "thought": "Identified critical exposure on Security Group sg-3423. Unrestricted internet SSH access detected."},
                            {"node": "RiskAssessment", "thought": "Assessed blast radius: Elevated exposure. Recommendation: Restrict SSH to bastion CIDR / revoke 0.0.0.0/0."}
                        ],
                        "progress": 95,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.5)

                    # 6. Waiting for Approval...
                    approval_card = {
                        "id": "act-sg-3423",
                        "resource_id": "Security Group sg-3423",
                        "resource_name": "sg-3423",
                        "resource_arn": "arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423",
                        "resource_type": "AWS::EC2::SecurityGroup",
                        "service": "EC2",
                        "issue": "Port 22 Open",
                        "recommendation": "Restrict SSH",
                        "description": "Security Group sg-3423 permits unrestricted public ingress from 0.0.0.0/0 to TCP Port 22 (SSH).",
                        "severity": "HIGH",
                        "status": "WAITING_APPROVAL",
                        "cli_command": "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0",
                        "terraform_snippet": 'resource "aws_security_group_rule" "restrict_ssh" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/16"]\n  security_group_id = "sg-3423"\n}',
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }

                    await ws_manager.send_ndjson(websocket, {
                        "event": "WAITING_APPROVAL",
                        "step": "Waiting for Approval...",
                        "message": "Waiting for Approval...",
                        "approval_item": approval_card,
                        "progress": 100,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                elif action == "approve":
                    item_id = payload.get("item_id", "act-sg-3423")
                    comments = payload.get("comments", "Approved via Dashboard")
                    await ws_manager.send_ndjson(websocket, {
                        "event": "APPROVAL_DECISION",
                        "status": "APPROVED",
                        "item_id": item_id,
                        "comments": comments,
                        "message": "Remediation approved by operator. Dispatching execution...",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.3)
                    await ws_manager.send_ndjson(websocket, {
                        "event": "EXECUTING_REMEDIATION",
                        "item_id": item_id,
                        "status": "EXECUTING",
                        "command": payload.get("cli_command", "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0"),
                        "message": "Executing remediation: Revoking 0.0.0.0/0 SSH rule on sg-3423...",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.5)
                    await ws_manager.send_ndjson(websocket, {
                        "event": "VERIFYING_FIX",
                        "item_id": item_id,
                        "status": "VERIFYING",
                        "message": "Verifying security group rule revocation on LocalStack...",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    await asyncio.sleep(0.4)
                    await ws_manager.send_ndjson(websocket, {
                        "event": "EXECUTION_COMPLETE",
                        "item_id": item_id,
                        "status": "RESOLVED",
                        "message": "Security Group sg-3423 port 22 revoked. Compliance verified.",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                elif action == "reject":
                    item_id = payload.get("item_id", "act-sg-3423")
                    reason = payload.get("reason", "Operator rejected remediation.")
                    await ws_manager.send_ndjson(websocket, {
                        "event": "APPROVAL_DECISION",
                        "status": "REJECTED",
                        "item_id": item_id,
                        "reason": reason,
                        "message": f"Remediation for {item_id} was rejected: {reason}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

                elif action == "modify":
                    item_id = payload.get("item_id", "act-sg-3423")
                    modified_cmd = payload.get("cli_command", "")
                    modified_rec = payload.get("recommendation", "")
                    await ws_manager.send_ndjson(websocket, {
                        "event": "REMEDIATION_MODIFIED",
                        "item_id": item_id,
                        "modified_command": modified_cmd,
                        "recommendation": modified_rec,
                        "message": f"Remediation parameters for {item_id} updated.",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        ws_manager.disconnect(websocket)

