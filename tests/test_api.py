from starlette.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def test_api_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "localstack_endpoint" in data
    assert "engine_mode" in data


def test_api_services_endpoint():
    response = client.get("/services")
    assert response.status_code == 200
    data = response.json()
    assert "supported_services" in data
    assert len(data["supported_services"]) >= 3
    assert "compliance_frameworks" in data


def test_api_scan_endpoint():
    payload = {
        "services": ["s3", "iam", "ec2"],
        "run_graph_analysis": True,
    }
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert "scan_id" in data
    assert "summary" in data
    assert "findings" in data
    assert len(data["findings"]) > 0

    # Verify first finding has required fields
    f0 = data["findings"][0]
    assert "severity" in f0
    assert "resource_id" in f0
    assert "resource_type" in f0
    assert "recommendation" in f0
    assert "compliance_status" in f0

    # Verify LangGraph analysis was attached
    assert "graph_analysis" in data
    assert data["graph_analysis"] is not None
    assert "risk_score" in data["graph_analysis"]
    assert "prioritized_queue" in data["graph_analysis"]


def test_api_graph_analyze_endpoint():
    response = client.post("/graph/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "remediation_plans" in data
