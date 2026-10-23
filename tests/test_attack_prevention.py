import pytest
from starlette.testclient import TestClient
from backend.api.main import app
from backend.simulation.attack_simulator import (
    attack_simulator,
    AttackType,
    AttackStatus,
)
from backend.graph.assistant import default_assistant_graph
from langgraph.types import Command

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_simulator():
    """Ensure clean attack simulator state for each test."""
    attack_simulator.clear_attacks()
    yield
    attack_simulator.clear_attacks()


def test_attack_simulation_and_probe_lifecycle():
    """Test simulating an attack and probing before vs after remediation."""
    # 1. Simulate SSH Brute Force
    event = attack_simulator.simulate_attack(AttackType.SSH_BRUTE_FORCE, attacker_ip="198.51.100.50")
    assert event.attack_type == AttackType.SSH_BRUTE_FORCE
    assert event.attacker_ip == "198.51.100.50"
    assert event.status in [AttackStatus.VULNERABILITY_EXPLOITED, AttackStatus.ACTIVE_ATTACK]

    # 2. Probe before remediation: Should be EXPLOITED (prevented = False)
    probe_before = attack_simulator.probe_attack_vector(AttackType.SSH_BRUTE_FORCE)
    assert probe_before.prevented is False
    assert probe_before.status == "EXPLOITED"

    # 3. Simulate remediation applied to security group
    attack_simulator.record_remediation("sg-3423", "REVOKE_SECURITY_GROUP_INGRESS")

    # 4. Probe after remediation: Should be PREVENTED (prevented = True)
    probe_after = attack_simulator.probe_attack_vector(AttackType.SSH_BRUTE_FORCE)
    assert probe_after.prevented is True
    assert probe_after.status == "PREVENTED"
    assert "BLOCKED" in probe_after.message or "revoked" in probe_after.message


def test_s3_and_iam_attack_probes():
    """Test S3 exfiltration and IAM escalation probes."""
    # S3 Probe
    s3_event = attack_simulator.simulate_attack(AttackType.S3_DATA_EXFILTRATION)
    assert s3_event.attack_type == AttackType.S3_DATA_EXFILTRATION
    probe_s3_before = attack_simulator.probe_attack_vector(AttackType.S3_DATA_EXFILTRATION)
    assert probe_s3_before.prevented is False

    attack_simulator.record_remediation("vulnerable-customer-data-bucket", "ENABLE_S3_PUBLIC_ACCESS_BLOCK")
    probe_s3_after = attack_simulator.probe_attack_vector(AttackType.S3_DATA_EXFILTRATION)
    assert probe_s3_after.prevented is True

    # IAM Probe
    iam_event = attack_simulator.simulate_attack(AttackType.IAM_PRIVILEGE_ESCALATION)
    assert iam_event.attack_type == AttackType.IAM_PRIVILEGE_ESCALATION
    probe_iam_before = attack_simulator.probe_attack_vector(AttackType.IAM_PRIVILEGE_ESCALATION)
    assert probe_iam_before.prevented is False

    attack_simulator.record_remediation("insecure-app-admin-role", "DETACH_IAM_ADMIN_POLICY")
    probe_iam_after = attack_simulator.probe_attack_vector(AttackType.IAM_PRIVILEGE_ESCALATION)
    assert probe_iam_after.prevented is True


@pytest.mark.asyncio
async def test_crawler_detects_and_prevents_attack_e2e():
    """
    Test full LangGraph Crawler lifecycle:
    1. Injects active attack into environment
    2. Observation Node detects the attack
    3. Reasoning Node correlates attack with vulnerable finding
    4. RiskAssessment elevates risk and prioritizes countermeasure
    5. HumanApproval interrupts and awaits authorization
    6. ExecuteRemediation applies defensive fix
    7. VerifyFix probes attack and confirms ATTACK PREVENTED
    """
    # 1. Inject SSH Brute-Force attack
    attack_simulator.simulate_attack(AttackType.SSH_BRUTE_FORCE, attacker_ip="198.51.100.99")
    assert len(attack_simulator.get_active_attacks()) == 1

    thread_id = "test-atk-thread-1"
    config = {"configurable": {"thread_id": thread_id}}
    initial_state = {
        "session_id": "test-sess-1",
        "thread_id": thread_id,
        "target_services": ["s3", "iam", "ec2"],
    }

    # Step through graph until interrupt
    result_stage1 = await default_assistant_graph.ainvoke(initial_state, config)

    # Verify Observation Node ingested the attack
    detected_attacks = result_stage1.get("detected_attacks", [])
    assert len(detected_attacks) >= 1
    assert any(a["attack_type"] == AttackType.SSH_BRUTE_FORCE.value for a in detected_attacks)

    # Verify Reasoning Node correlated the attack with vulnerable SG finding
    correlated_exploits = result_stage1.get("correlated_exploits", [])
    assert len(correlated_exploits) >= 1
    exp = correlated_exploits[0]
    assert exp["attack_type"] == AttackType.SSH_BRUTE_FORCE.value
    assert exp["status"] == "ACTIVELY_EXPLOITED"
    assert "attack_chain" in exp

    # Verify RiskAssessment set risk to 100 for active exploit
    assert result_stage1.get("risk_score") == 100.0
    assert "ACTIVE" in result_stage1.get("risk_category", "")

    # Verify graph paused at HumanApproval
    interrupts = result_stage1.get("__interrupt__", [])
    assert len(interrupts) > 0
    approval_val = interrupts[0].value if hasattr(interrupts[0], "value") else interrupts[0]
    assert "correlated_exploits" in approval_val
    assert len(approval_val["correlated_exploits"]) >= 1

    # Resume graph with Human Approval
    resume_payload = {
        "approved": True,
        "approver": "Lead SecOps Engineer",
        "comments": "Authorize emergency mitigation: close port 22 ingress.",
    }
    result_stage2 = await default_assistant_graph.ainvoke(Command(resume=resume_payload), config)

    # Verify Execution & Fix Verification
    assert result_stage2.get("is_approved") is True
    assert result_stage2.get("final_status") == "FIXED"

    # Verify Attack Prevention Probe
    prevention_results = result_stage2.get("prevention_results", [])
    assert len(prevention_results) >= 1
    assert any(p["prevented"] is True for p in prevention_results)
    assert result_stage2.get("threat_level") == "DEFENDED"

    # Verify final report details
    final_report = result_stage2.get("final_report", "")
    assert "Adversary Exploit Paths Neutralized" in final_report
    assert "Prevention Proof" in final_report



def test_api_attack_endpoints():
    """Test HTTP API routes for simulating, probing, and clearing attacks."""
    # 1. Simulate Attack via API
    sim_res = client.post("/attack/simulate", json={"attack_type": "SSH_BRUTE_FORCE", "attacker_ip": "198.51.100.77"})
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["status"] == "success"
    assert sim_data["attack_event"]["attacker_ip"] == "198.51.100.77"

    # 2. Get Active Attacks
    list_res = client.get("/attack/active")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total_active"] >= 1

    # 3. Probe Attack Vector (Vulnerable before fix)
    probe_res = client.post("/attack/probe", json={"attack_type": "SSH_BRUTE_FORCE"})
    assert probe_res.status_code == 200
    probe_data = probe_res.json()
    assert probe_data["probe"]["prevented"] is False

    # 4. Clear Attacks
    clear_res = client.post("/attack/clear")
    assert clear_res.status_code == 200
    assert client.get("/attack/active").json()["total_active"] == 0


def test_api_attack_triage_e2e_endpoint():
    """Test the complete closed-loop attack-triage endpoint."""
    res = client.post("/assistant/attack-triage", json={"attack_type": "SSH_BRUTE_FORCE"})
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "COMPLETED"
    assert "attack_simulated" in data
    assert len(data["correlated_exploits"]) >= 1
    assert data["attack_prevented"] is True
    assert "prevention_results" in data
    assert any(p["prevented"] for p in data["prevention_results"])
