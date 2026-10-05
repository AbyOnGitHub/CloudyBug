import pytest
import asyncio
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver
from starlette.testclient import TestClient

from backend.graph.assistant import (
    build_security_assistant,
    observation_node,
    reasoning_node,
    risk_assessment_node,
    human_approval_node,
    execute_remediation_node,
    verify_fix_node,
    finish_node,
    route_after_reasoning,
    route_after_approval,
)
from backend.graph.assistant_state import SecurityAssistantState, SecurityStateModel
from backend.api.main import app

client = TestClient(app)


@pytest.mark.asyncio
async def test_observation_and_reasoning_nodes():
    # 1. Test Observation Node
    initial_state: SecurityAssistantState = {
        "session_id": "test-obs-1",
        "target_services": ["s3"],
        "endpoint_url": "http://localhost:4566",
    }
    obs_state = await observation_node(initial_state)

    assert "total_observed" in obs_state
    assert "observed_findings" in obs_state
    assert obs_state["total_observed"] > 0

    # 2. Test Reasoning Node (Failing issues detected)
    reason_state = await reasoning_node({**initial_state, **obs_state})
    assert "need_fix" in reason_state
    assert reason_state["need_fix"] is True
    assert len(reason_state["identified_issues"]) > 0
    assert route_after_reasoning({**obs_state, **reason_state}) == "RiskAssessment"

    # 3. Test Reasoning Node (Clean state)
    clean_obs = {
        "observed_findings": [{"compliance_status": "PASSED", "title": "Encrypted S3"}],
        "failed_observed": 0,
    }
    clean_reason = await reasoning_node(clean_obs)
    assert clean_reason["need_fix"] is False
    assert route_after_reasoning(clean_reason) == "Finish"


@pytest.mark.asyncio
async def test_risk_assessment_node():
    state: SecurityAssistantState = {
        "observed_findings": [
            {
                "title": "S3 Public Bucket",
                "severity": {"level": "CRITICAL"},
                "compliance_status": "FAILED",
                "resource": {"name": "test-bucket", "service": "s3", "resource_type": "AwsS3Bucket", "arn": "arn:aws:s3:::test-bucket"},
                "remediation": {"recommendation_summary": "Block public access", "suggested_cli_command": "aws s3api ..."},
            },
            {
                "title": "Unrestricted SSH",
                "severity": {"level": "HIGH"},
                "compliance_status": "FAILED",
                "resource": {"name": "sg-12345", "service": "ec2", "resource_type": "AwsEc2SecurityGroup", "arn": "arn:aws:ec2:us-east-1:1:security-group/sg-12345"},
                "remediation": {"recommendation_summary": "Revoke 0.0.0.0/0", "suggested_cli_command": "aws ec2 ..."},
            },
        ],
    }

    risk_state = await risk_assessment_node(state)
    assert risk_state["risk_score"] > 0
    assert risk_state["risk_category"] in ["CRITICAL", "ELEVATED"]
    assert len(risk_state["remediation_plan"]) == 2
    assert risk_state["remediation_plan"][0]["action_type"] == "ENABLE_S3_PUBLIC_ACCESS_BLOCK"


@pytest.mark.asyncio
async def test_assistant_stategraph_with_interrupt_and_approval():
    """
    Test the full 7-node autonomous assistant graph:
    1. Runs: Observation -> Reasoning -> RiskAssessment -> HumanApproval
    2. Pauses at HumanApproval with interrupt()
    3. Resumes with approval response -> ExecuteRemediation -> VerifyFix -> Finish
    """
    checkpointer = MemorySaver()
    graph = build_security_assistant(checkpointer=checkpointer)

    thread_id = "assistant-test-thread-01"
    config = {"configurable": {"thread_id": thread_id}}

    initial_input: SecurityAssistantState = {
        "session_id": "sess-test-full-01",
        "thread_id": thread_id,
        "target_services": ["s3", "iam"],
    }

    # Step 1: Execute graph until interrupt() is called at HumanApproval
    result1 = await graph.ainvoke(initial_input, config)

    # Validate that graph was paused by interrupt()
    assert "__interrupt__" in result1
    interrupt_items = result1["__interrupt__"]
    assert len(interrupt_items) == 1
    interrupt_data = interrupt_items[0].value

    assert interrupt_data["event"] == "HUMAN_APPROVAL_REQUIRED"
    assert "remediation_plan" in interrupt_data
    assert len(interrupt_data["remediation_plan"]) > 0

    # Step 2: Resume with Human Approval (Command)
    approval_decision = {
        "approved": True,
        "approver": "Principal Security Architect",
        "comments": "Remediation verified and authorized for deployment.",
    }
    result2 = await graph.ainvoke(Command(resume=approval_decision), config)

    # Validate resumed path: executed and verified
    assert result2["is_approved"] is True
    assert result2["approver"] == "Principal Security Architect"
    assert "executed_actions" in result2
    assert "verification_results" in result2
    assert result2["final_status"] == "FIXED"
    assert "Autonomous Cloud Security Assistant Report" in result2["final_report"]


@pytest.mark.asyncio
async def test_assistant_stategraph_rejection_path():
    """Test when human approval is rejected, routing directly to Finish with REJECTED."""
    checkpointer = MemorySaver()
    graph = build_security_assistant(checkpointer=checkpointer)

    thread_id = "assistant-test-thread-reject"
    config = {"configurable": {"thread_id": thread_id}}

    initial_input: SecurityAssistantState = {
        "session_id": "sess-reject-01",
        "thread_id": thread_id,
        "target_services": ["s3"],
    }

    # Step 1: Run until interrupt
    await graph.ainvoke(initial_input, config)

    # Step 2: Resume with Rejection
    rejection = {
        "approved": False,
        "approver": "SecOps Manager",
        "comments": "Freeze window in effect. Abort changes.",
    }
    result = await graph.ainvoke(Command(resume=rejection), config)

    assert result["is_approved"] is False
    assert result["final_status"] == "REJECTED"
    assert "executed_actions" not in result or len(result.get("executed_actions", [])) == 0


def test_async_postgres_saver_class():
    """Verify that AsyncPostgresSaver is imported and available for PostgreSQL."""
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    assert AsyncPostgresSaver is not None
    assert hasattr(AsyncPostgresSaver, "from_conn_string")
    assert hasattr(AsyncPostgresSaver, "setup")


def test_assistant_api_endpoints():
    """Test FastAPI /assistant/start and /assistant/approve endpoints."""
    # 1. Start assistant session (should interrupt and wait for approval)
    res_start = client.post("/assistant/start", json={"target_services": ["s3"]})
    assert res_start.status_code == 200
    start_data = res_start.json()

    assert start_data["status"] == "PAUSED_FOR_APPROVAL"
    assert "thread_id" in start_data
    thread_id = start_data["thread_id"]
    assert start_data["stage"] == "HumanApproval"
    assert "approval_request" in start_data

    # 2. Check state endpoint
    res_state = client.get(f"/assistant/state/{thread_id}")
    assert res_state.status_code == 200

    # 3. Approve and resume
    res_approve = client.post(
        "/assistant/approve",
        json={
            "thread_id": thread_id,
            "approved": True,
            "approver": "Cloud Security Lead",
            "comments": "Approved via automated API test.",
        },
    )
    assert res_approve.status_code == 200
    approve_data = res_approve.json()
    assert approve_data["status"] == "COMPLETED"
    assert approve_data["final_status"] == "FIXED"
    assert approve_data["is_approved"] is True
    assert len(approve_data["executed_actions"]) > 0


@pytest.mark.asyncio
async def test_custom_state_model_fields_and_trace():
    """
    Verify custom State model attributes:
    vulnerabilities, recommendations, cloud_resources, approval_status,
    execution_history, reasoning_trace, and timestamps.
    """
    checkpointer = MemorySaver()
    graph = build_security_assistant(checkpointer=checkpointer)

    thread_id = "custom-state-test-thread-01"
    config = {"configurable": {"thread_id": thread_id}}

    initial_state = {
        "session_id": "test-custom-state",
        "thread_id": thread_id,
        "target_services": ["s3"],
        "reasoning_trace": [],
        "execution_history": [],
        "timestamps": {},
    }

    # Step 1: Run through Observation -> Reasoning -> RiskAssessment -> HumanApproval (interrupt)
    interrupted_result = await graph.ainvoke(initial_state, config)
    assert "__interrupt__" in interrupted_result

    # Inspect checkpointed state at interruption
    curr_snapshot = graph.get_state(config)
    state_values = curr_snapshot.values

    # Validate Core Custom State Fields
    assert "vulnerabilities" in state_values
    assert isinstance(state_values["vulnerabilities"], list)
    assert len(state_values["vulnerabilities"]) > 0

    assert "cloud_resources" in state_values
    assert isinstance(state_values["cloud_resources"], list)
    assert len(state_values["cloud_resources"]) > 0

    assert "recommendations" in state_values
    assert isinstance(state_values["recommendations"], list)
    assert len(state_values["recommendations"]) > 0

    # Validate reasoning trace accumulation (Observation + Reasoning + RiskAssessment)
    assert "reasoning_trace" in state_values
    trace = state_values["reasoning_trace"]
    assert len(trace) >= 3
    trace_nodes = [t["node"] for t in trace]
    assert "Observation" in trace_nodes
    assert "Reasoning" in trace_nodes
    assert "RiskAssessment" in trace_nodes

    # Validate execution history accumulation
    assert "execution_history" in state_values
    history = state_values["execution_history"]
    assert len(history) >= 3
    events = [h["event"] for h in history]
    assert "OBSERVATION_COMPLETED" in events
    assert "REASONING_COMPLETED" in events

    # Validate timestamps merging across transitions
    assert "timestamps" in state_values
    ts = state_values["timestamps"]
    assert "started_at" in ts
    assert "observed_at" in ts
    assert "reasoned_at" in ts
    assert "assessed_at" in ts

    # Step 2: Resume with Human Approval
    resumed_result = await graph.ainvoke(
        Command(resume={"approved": True, "approver": "Chief SecOps Officer", "feedback": "Approved for execution"}),
        config,
    )

    # Validate approval status
    assert "approval_status" in resumed_result
    app_status = resumed_result["approval_status"]
    assert app_status["is_approved"] is True
    assert app_status["status"] == "APPROVED"
    assert app_status["approver"] == "Chief SecOps Officer"

    # Validate post-execution reasoning trace accumulation
    full_trace = resumed_result["reasoning_trace"]
    full_trace_nodes = [t["node"] for t in full_trace]
    assert "HumanApproval" in full_trace_nodes
    assert "ExecuteRemediation" in full_trace_nodes
    assert "VerifyFix" in full_trace_nodes
    assert "Finish" in full_trace_nodes

    # Validate final timestamps
    full_ts = resumed_result["timestamps"]
    assert "approved_at" in full_ts
    assert "executed_at" in full_ts
    assert "verified_at" in full_ts
    assert "completed_at" in full_ts


def test_security_state_pydantic_model_validation():
    """Verify that SecurityStateModel parses and validates the LangGraph State."""
    sample_state = {
        "session_id": "sess-model-val",
        "thread_id": "thread-model-val",
        "vulnerabilities": [
            {
                "id": "vuln-1",
                "title": "Unencrypted S3 Bucket",
                "severity": "HIGH",
                "service": "s3",
            }
        ],
        "recommendations": [
            {
                "id": "rec-1",
                "action_type": "ENABLE_S3_DEFAULT_ENCRYPTION",
                "cli_command": "aws s3api put-bucket-encryption ...",
            }
        ],
        "cloud_resources": [
            {
                "arn": "arn:aws:s3:::my-bucket",
                "name": "my-bucket",
                "service": "s3",
            }
        ],
        "approval_status": {
            "status": "APPROVED",
            "is_approved": True,
            "approver": "SecOps Lead",
        },
        "execution_history": [
            {"event": "REMEDIATION_EXECUTION_COMPLETED", "node": "ExecuteRemediation", "success": True}
        ],
        "reasoning_trace": [
            {"node": "Observation", "thought": "Discovered 1 vulnerability"}
        ],
        "timestamps": {
            "started_at": "2026-10-05T12:00:00Z",
            "completed_at": "2026-10-05T12:05:00Z",
        },
        "final_status": "FIXED",
        "final_report": "# Security Report",
    }

    model = SecurityStateModel.from_graph_state(sample_state)
    assert model.session_id == "sess-model-val"
    assert len(model.vulnerabilities) == 1
    assert model.vulnerabilities[0]["title"] == "Unencrypted S3 Bucket"
    assert len(model.recommendations) == 1
    assert len(model.cloud_resources) == 1
    assert model.approval_status["status"] == "APPROVED"
    assert len(model.execution_history) == 1
    assert len(model.reasoning_trace) == 1
    assert "started_at" in model.timestamps
    assert model.final_status == "FIXED"


