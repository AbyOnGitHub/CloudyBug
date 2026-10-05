import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from backend.api.main import app
from backend.core.config import settings
from backend.scanner.terraform_service import terraform_service, TerraformService
from backend.scanner.prowler_service import ProwlerService
from backend.scanner.models import ScanRequest, ComplianceStatus
from backend.scanner.llm_parser import LLMASFFParser
from backend.graph.assistant import (
    build_security_assistant,
    default_assistant_graph,
)
from backend.remediation.custodian_service import (
    custodian_service,
    CloudCustodianService,
)


# ==============================================================================
# Complete 10-Stage End-to-End Integration Test Suite
#
# Pipeline:
#   Terraform -> LocalStack -> Prowler -> Parser -> LangGraph ->
#   Reasoning -> Approval -> Cloud Custodian -> Verification -> Dashboard Update
# ==============================================================================

@pytest.mark.asyncio
async def test_full_agentic_cloud_security_e2e_pipeline():
    """
    Comprehensive end-to-end integration test executing all 10 stages:
    1. Deploy vulnerable infrastructure via Terraform
    2. Verify resource presence on LocalStack
    3. Execute Prowler security scan
    4. Parse ASFF findings to LLM reasoning models
    5. Ingest into LangGraph StateGraph (Observation Node)
    6. Perform Reasoning & Risk Assessment (score calculation, plan formulation)
    7. Trigger Human Approval (pause on interrupt(), inspect, submit resume approval)
    8. Execute Cloud Custodian remediation policies
    9. Verify compliance restoration on remediated resources
    10. Confirm Dashboard updates and real-time NDJSON event streaming
    """

    # -------------------------------------------------------------------------
    # STAGE 1 & 2: Terraform Infrastructure Deployment & LocalStack Verification
    # -------------------------------------------------------------------------
    deploy_result = terraform_service.deploy_vulnerable_infrastructure()
    assert deploy_result.status == "SUCCESS"
    assert len(deploy_result.resources_deployed) >= 4

    # Confirm vulnerable resources were provisioned
    vulnerable_s3 = next((r for r in deploy_result.resources_deployed if "vulnerable-customer-data-bucket" in r.name), None)
    assert vulnerable_s3 is not None
    assert vulnerable_s3.is_vulnerable is True

    insecure_sg = next((r for r in deploy_result.resources_deployed if "insecure-ssh-sg" in r.name), None)
    assert insecure_sg is not None
    assert insecure_sg.is_vulnerable is True

    insecure_role = next((r for r in deploy_result.resources_deployed if "insecure-app-admin-role" in r.name), None)
    assert insecure_role is not None
    assert insecure_role.is_vulnerable is True

    # -------------------------------------------------------------------------
    # STAGE 3: Prowler Security Scan
    # -------------------------------------------------------------------------
    prowler = ProwlerService()
    scan_req = ScanRequest(services=["s3", "iam", "ec2"], run_graph_analysis=False)
    scan_response = prowler.execute_scan(scan_req)

    assert scan_response.status == "success"
    assert len(scan_response.findings) > 0

    failed_findings = [f for f in scan_response.findings if f.compliance_status == ComplianceStatus.FAILED]
    assert len(failed_findings) >= 3, "Prowler must detect multiple failed security controls on vulnerable resources"

    # Confirm critical vulnerability types are discovered
    finding_titles = [f.title.lower() for f in failed_findings]
    assert any("encryption" in t or "public" in t for t in finding_titles)
    assert any("ssh" in t or "22" in t for t in finding_titles)
    assert any("administratoraccess" in t or "admin" in t for t in finding_titles)

    # -------------------------------------------------------------------------
    # STAGE 4: Parser Module (ASFF to LLM Structured Representation)
    # -------------------------------------------------------------------------
    raw_asff_list = [f.raw_asff for f in scan_response.findings if f.raw_asff]
    assert len(raw_asff_list) > 0

    llm_findings = LLMASFFParser.parse_findings(raw_asff_list)
    assert len(llm_findings) == len(raw_asff_list)

    # Verify severity mapping, metadata extraction, MITRE ATT&CK tags, and recommendations
    critical_llm_findings = [f for f in llm_findings if f.compliance_status.value == "FAILED"]
    for f in critical_llm_findings:
        assert f.severity.level.value in ["HIGH", "CRITICAL", "MEDIUM", "LOW"]
        assert f.severity.score > 0
        assert f.resource.arn != "" or f.resource.name != ""
        assert f.remediation.recommendation_summary != ""
        assert f.remediation.suggested_cli_command != ""

    # -------------------------------------------------------------------------
    # STAGE 5 & 6: LangGraph StateGraph, Reasoning, & Risk Assessment Nodes
    # -------------------------------------------------------------------------
    checkpointer = MemorySaver()
    graph = build_security_assistant(checkpointer=checkpointer)

    thread_id = "e2e-security-thread-10-stage"
    config = {"configurable": {"thread_id": thread_id}}

    initial_state = {
        "session_id": "e2e-session-active",
        "thread_id": thread_id,
        "target_services": ["s3", "iam", "ec2"],
        "reasoning_trace": [],
        "execution_history": [],
        "timestamps": {},
    }

    # Execute graph: Observation -> Reasoning -> RiskAssessment -> HumanApproval (interrupt)
    interrupted_result = await graph.ainvoke(initial_state, config)
    assert "__interrupt__" in interrupted_result

    # Inspect checkpointed state at interruption point
    current_snapshot = graph.get_state(config)
    state_at_interrupt = current_snapshot.values

    # Verify Reasoning Assessment
    assert state_at_interrupt["need_fix"] is True
    assert "reasoning_summary" in state_at_interrupt
    assert state_at_interrupt["failed_observed"] > 0

    # Verify Risk Assessment calculations
    assert state_at_interrupt["risk_score"] >= 60.0
    assert state_at_interrupt["risk_category"] in ["HIGH", "CRITICAL"]
    assert state_at_interrupt["blast_radius"] != ""

    # Verify Remediation Plan synthesis
    remediation_plan = state_at_interrupt["remediation_plan"]
    assert len(remediation_plan) >= 2
    action_types = [a["action_type"] for a in remediation_plan]
    assert any("S3" in at for at in action_types)
    assert any("REVOKE" in at or "SECURITY_GROUP" in at for at in action_types)

    # -------------------------------------------------------------------------
    # STAGE 7: Human Approval Node (Pause on interrupt and authorized resumption)
    # -------------------------------------------------------------------------
    interrupt_payload = interrupted_result["__interrupt__"][0].value
    assert interrupt_payload["event"] == "HUMAN_APPROVAL_REQUIRED"
    assert interrupt_payload["risk_score"] == state_at_interrupt["risk_score"]
    assert len(interrupt_payload["remediation_plan"]) == len(remediation_plan)

    approval_decision = {
        "approved": True,
        "approver": "SecOps Principal Architect",
        "comments": "E2E automated approval: authorized Cloud Custodian remediation.",
    }

    # Resume graph execution with approval Command
    final_execution_result = await graph.ainvoke(Command(resume=approval_decision), config)

    # -------------------------------------------------------------------------
    # STAGE 8: Cloud Custodian Remediation Execution
    # -------------------------------------------------------------------------
    assert final_execution_result["is_approved"] is True
    assert final_execution_result["approver"] == "SecOps Principal Architect"

    executed_actions = final_execution_result["executed_actions"]
    assert len(executed_actions) > 0
    assert all(a["success"] is True for a in executed_actions)

    # Verify Cloud Custodian policy execution artifacts
    # Policies applied: s3-remediate-block-public-access, ec2-remediate-revoke-unrestricted-ssh, etc.
    custodian_output_dir = Path(settings.OUTPUT_DIRECTORY) / "custodian"
    assert custodian_output_dir.exists()

    # -------------------------------------------------------------------------
    # STAGE 9: Verification Node (Confirm Vulnerability Fixed)
    # -------------------------------------------------------------------------
    verification_results = final_execution_result["verification_results"]
    assert len(verification_results) > 0
    assert final_execution_result["verification_passed"] is True
    assert final_execution_result["final_status"] == "FIXED"

    # Confirm executive report generated
    final_report = final_execution_result["final_report"]
    assert "Autonomous Cloud Security Assistant Report" in final_report
    assert "**Status:** `FIXED`" in final_report
    assert "SecOps Principal Architect" in final_report

    # -------------------------------------------------------------------------
    # STAGE 10: Dashboard Update & Real-Time NDJSON WebSocket Event Stream
    # -------------------------------------------------------------------------
    client = TestClient(app)
    with client.websocket_connect("/ws/stream") as ws:
        # Initial greeting event
        conn_raw = ws.receive_text()
        assert conn_raw.endswith("\n")
        conn_event = json.loads(conn_raw.strip())
        assert conn_event["event"] == "CONNECTED"

        # Trigger REST Approval which broadcasts live NDJSON stream to Dashboard
        approve_resp = client.post("/approve", json={
            "item_id": "act-sg-3423",
            "approver": "SecOps Principal Architect",
            "comments": "Approved via E2E Dashboard test.",
        })
        assert approve_resp.status_code == 200

        # Verify stream received all dashboard events in strict NDJSON format
        received_events = []
        for _ in range(6):
            raw_line = ws.receive_text()
            assert raw_line.endswith("\n")
            event_data = json.loads(raw_line.strip())
            received_events.append(event_data["event"])

        assert "APPROVAL_DECISION" in received_events
        assert "EXECUTING_REMEDIATION" in received_events
        assert "VERIFYING_FIX" in received_events
        assert "EXECUTION_COMPLETE" in received_events
        assert "CUSTODIAN_REMEDIATION_EXECUTED" in received_events
        assert "DASHBOARD_UPDATED" in received_events

        # Check latest system status endpoint reflects operational status
        status_resp = client.get("/status")
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert status_data["status"] == "online"
        assert status_data["websocket"]["format"] == "NDJSON"


# ==============================================================================
# Additional Integration Tests for Error Paths & Policy Governance
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_rejection_path_prevents_custodian_remediation():
    """Verify that when human rejects the remediation plan, execution halts at Finish."""
    checkpointer = MemorySaver()
    graph = build_security_assistant(checkpointer=checkpointer)

    thread_id = "e2e-reject-thread-01"
    config = {"configurable": {"thread_id": thread_id}}

    initial_state = {
        "session_id": "e2e-reject-session",
        "thread_id": thread_id,
        "target_services": ["s3"],
        "reasoning_trace": [],
        "execution_history": [],
        "timestamps": {},
    }

    # Step 1: Run until HumanApproval interrupt
    interrupted_result = await graph.ainvoke(initial_state, config)
    assert "__interrupt__" in interrupted_result

    # Step 2: Reject the plan
    rejection_decision = {
        "approved": False,
        "approver": "Risk Compliance Officer",
        "comments": "Maintenance window closed. Remediation postponed.",
    }
    result = await graph.ainvoke(Command(resume=rejection_decision), config)

    # Step 3: Verify execution halted, no actions executed, final status is REJECTED
    assert result["is_approved"] is False
    assert result["final_status"] == "REJECTED"
    assert result.get("executed_actions") is None or len(result.get("executed_actions", [])) == 0
    assert "REJECTED" in result["final_report"]


def test_cloud_custodian_policy_validity_and_execution():
    """Verify all Cloud Custodian YAML policies are structurally sound and executable."""
    service = CloudCustodianService()
    policies = service.list_available_policies()
    assert len(policies) >= 4, "Should have loaded S3, EC2, and IAM policies"

    policy_names = [p.name for p in policies]
    assert "s3-remediate-block-public-access" in policy_names
    assert "s3-remediate-enable-default-encryption" in policy_names
    assert "ec2-remediate-revoke-unrestricted-ssh" in policy_names
    assert "iam-remediate-detach-administrator-access" in policy_names

    # Test direct execution of S3 block public access policy
    s3_policy = service.get_policy("s3-remediate-block-public-access")
    assert s3_policy is not None
    assert s3_policy.resource_type == "s3"

    report = service.execute_policy(s3_policy, target_resource_id="vulnerable-customer-data-bucket")
    assert report.success is True
    assert report.policy_name == "s3-remediate-block-public-access"
    assert len(report.actions_applied) > 0
    assert report.actions_applied[0]["action"] == "set-public-block"

    # Confirm report artifacts were written to disk
    run_dir = Path(report.output_dir)
    assert (run_dir / "resources.json").exists()
    assert (run_dir / "custodian-run.log").exists()


def test_terraform_service_lifecycle():
    """Verify Terraform service deploy, inventory, and teardown."""
    service = TerraformService()
    deploy_result = service.deploy_vulnerable_infrastructure()
    assert deploy_result.status == "SUCCESS"
    assert len(deploy_result.resources_deployed) >= 4

    # Verify resource items
    sg_res = next((r for r in deploy_result.resources_deployed if r.resource_type == "aws_security_group"), None)
    assert sg_res is not None

    # Destroy
    teardown_success = service.destroy_infrastructure()
    assert teardown_success is True


def test_e2e_rest_api_full_pipeline():
    """Verify the entire pipeline triggered via REST endpoints."""
    client = TestClient(app)

    # 1. Prowler Scan endpoint
    scan_resp = client.post("/scan", json={"services": ["ec2", "s3"], "run_graph_analysis": True})
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["status"] == "success"
    assert len(scan_data["findings"]) > 0

    # 2. Custodian Policies List endpoint
    cust_list_resp = client.get("/custodian/policies")
    assert cust_list_resp.status_code == 200
    cust_data = cust_list_resp.json()
    assert cust_data["status"] == "SUCCESS"
    assert cust_data["total_policies"] >= 4

    # 3. Direct Custodian Run endpoint
    cust_run_resp = client.post("/custodian/run", json={
        "policy_name": "ec2-remediate-revoke-unrestricted-ssh",
        "target_resource": "sg-3423",
    })
    assert cust_run_resp.status_code == 200
    run_data = cust_run_resp.json()
    assert run_data["status"] == "SUCCESS"
    assert run_data["report"]["actions_applied"][0]["action"] == "remove-permissions"

    # 4. Status endpoint
    status_resp = client.get("/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "online"
