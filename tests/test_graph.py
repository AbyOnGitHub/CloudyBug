import pytest
from backend.scanner.parser import ASFFParser
from backend.scanner.utils import get_sample_asff_findings
from backend.graph.workflow import run_security_triage


def test_langgraph_security_triage():
    sample_raw = get_sample_asff_findings()
    findings = ASFFParser.parse_findings(sample_raw)

    result = run_security_triage(findings)

    assert "risk_score" in result
    assert "risk_rating" in result
    assert result["risk_rating"] in ["CRITICAL", "ELEVATED", "MODERATE", "LOW"]

    # Check attack vectors
    assert "attack_vectors" in result
    assert len(result["attack_vectors"]) > 0

    # Check prioritization queue
    assert "prioritized_queue" in result
    assert len(result["prioritized_queue"]) > 0
    top_issue = result["prioritized_queue"][0]
    assert "rank" in top_issue
    assert "severity" in top_issue
    assert "blast_radius" in top_issue

    # Check automated remediation plans
    assert "remediation_plans" in result
    assert len(result["remediation_plans"]) > 0
    plan = result["remediation_plans"][0]
    assert "cli_command" in plan
    assert "terraform_fix" in plan
    assert "manual_steps" in plan

    # Check executive summary markdown
    assert "executive_summary" in result
    assert "Cloud Security Posture & Compliance Report" in result["executive_summary"]
