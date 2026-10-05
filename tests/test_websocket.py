import json
import pytest
from fastapi.testclient import TestClient
from backend.api.main import app


def test_websocket_connect_and_ndjson():
    """Verify WebSocket connects and emits initial NDJSON event."""
    client = TestClient(app)
    with client.websocket_connect("/ws/stream") as websocket:
        raw_msg = websocket.receive_text()
        # Ensure message is NDJSON (newline-terminated)
        assert raw_msg.endswith("\n")
        data = json.loads(raw_msg.strip())
        assert data["event"] == "CONNECTED"
        assert data["status"] == "Connected"
        assert "[✓] Connected" in data["message"]


def test_websocket_start_scan_progression():
    """Verify trigger_audit or start_scan streams scan milestones and waiting approval."""
    client = TestClient(app)
    with client.websocket_connect("/ws/stream") as websocket:
        # Initial CONNECTED
        init_raw = websocket.receive_text()
        assert json.loads(init_raw.strip())["event"] == "CONNECTED"

        # Trigger scan
        websocket.send_text(json.dumps({"action": "start_scan", "target_services": ["ec2", "iam", "s3"]}) + "\n")

        # 1. Scanning EC2...
        ec2_msg = json.loads(websocket.receive_text().strip())
        assert ec2_msg["event"] == "SCAN_PROGRESS"
        assert ec2_msg["step"] == "Scanning EC2..."

        # 2. Checking IAM...
        iam_msg = json.loads(websocket.receive_text().strip())
        assert iam_msg["event"] == "SCAN_PROGRESS"
        assert iam_msg["step"] == "Checking IAM..."

        # 3. Checking S3...
        s3_msg = json.loads(websocket.receive_text().strip())
        assert s3_msg["event"] == "SCAN_PROGRESS"
        assert s3_msg["step"] == "Checking S3..."

        # 4. Found issues
        findings_msg = json.loads(websocket.receive_text().strip())
        assert findings_msg["event"] == "FINDINGS_DISCOVERED"
        assert "Found" in findings_msg["message"]
        assert len(findings_msg["findings"]) > 0

        # 5. AI analysing...
        ai_msg = json.loads(websocket.receive_text().strip())
        assert ai_msg["event"] == "AI_ANALYSING"
        assert "AI analysing" in ai_msg["message"]

        # 6. Waiting for Approval...
        approval_msg = json.loads(websocket.receive_text().strip())
        assert approval_msg["event"] == "WAITING_APPROVAL"
        assert approval_msg["approval_item"]["resource_id"] == "Security Group sg-3423"
        assert approval_msg["approval_item"]["issue"] == "Port 22 Open"
        assert approval_msg["approval_item"]["recommendation"] == "Restrict SSH"


def test_websocket_approval_actions():
    """Verify Approve, Reject, and Modify actions over WebSocket."""
    client = TestClient(app)
    with client.websocket_connect("/ws/stream") as websocket:
        # Connected
        websocket.receive_text()

        # Test Modify
        websocket.send_text(json.dumps({
            "action": "modify",
            "item_id": "act-sg-3423",
            "cli_command": "aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "recommendation": "Restrict SSH to 10.0.0.0/16 only",
        }) + "\n")
        mod_msg = json.loads(websocket.receive_text().strip())
        assert mod_msg["event"] == "REMEDIATION_MODIFIED"

        # Test Approve
        websocket.send_text(json.dumps({
            "action": "approve",
            "item_id": "act-sg-3423",
            "comments": "Approved for immediate mitigation",
        }) + "\n")
        decision_msg = json.loads(websocket.receive_text().strip())
        assert decision_msg["event"] == "APPROVAL_DECISION"
        assert decision_msg["status"] == "APPROVED"

        exec_msg = json.loads(websocket.receive_text().strip())
        assert exec_msg["event"] == "EXECUTING_REMEDIATION"

        verify_msg = json.loads(websocket.receive_text().strip())
        assert verify_msg["event"] == "VERIFYING_FIX"

        done_msg = json.loads(websocket.receive_text().strip())
        assert done_msg["event"] == "EXECUTION_COMPLETE"
        assert done_msg["status"] == "RESOLVED"


def test_connection_manager_class():
    """Verify ConnectionManager methods (connect, disconnect, broadcast, send_ndjson)."""
    from backend.api.websocket_manager import ConnectionManager
    mgr = ConnectionManager()
    assert mgr.get_active_count() == 0


def test_rest_approve_endpoint():
    """Verify REST POST /approve broadcasts NDJSON and returns approval confirmation."""
    client = TestClient(app)
    
    # Connect a WebSocket listener to observe NDJSON broadcasts from REST /approve
    with client.websocket_connect("/ws/stream") as ws:
        # Initial connected message
        ws.receive_text()

        # Trigger REST /approve
        resp = client.post("/approve", json={
            "item_id": "act-sg-3423",
            "approver": "SecOps Lead",
            "comments": "Immediate remediation approved via REST",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "APPROVED"
        assert data["item_id"] == "act-sg-3423"

        # Check WebSocket received the broadcasted NDJSON events
        decision_raw = ws.receive_text()
        assert decision_raw.endswith("\n")
        decision_event = json.loads(decision_raw.strip())
        assert decision_event["event"] == "APPROVAL_DECISION"
        assert decision_event["status"] == "APPROVED"


def test_rest_reject_endpoint():
    """Verify REST POST /reject broadcasts NDJSON and returns rejection confirmation."""
    client = TestClient(app)
    
    with client.websocket_connect("/ws/stream") as ws:
        ws.receive_text()

        resp = client.post("/reject", json={
            "item_id": "act-sg-3423",
            "reason": "False positive - internal test security group",
            "approver": "Security Director",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "REJECTED"
        assert data["item_id"] == "act-sg-3423"

        # Check WebSocket received the broadcasted NDJSON rejection event
        rejection_raw = ws.receive_text()
        assert rejection_raw.endswith("\n")
        rej_event = json.loads(rejection_raw.strip())
        assert rej_event["event"] == "APPROVAL_DECISION"
        assert rej_event["status"] == "REJECTED"


def test_rest_status_endpoint():
    """Verify REST GET /status returns agent, WebSocket, and scanner status."""
    client = TestClient(app)
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "online"
    assert "websocket" in data
    assert data["websocket"]["format"] == "NDJSON"
    assert "localstack" in data
    assert "scanner" in data
    assert "pending_approvals" in data
    assert len(data["pending_approvals"]) > 0
    assert data["pending_approvals"][0]["resource_id"] == "Security Group sg-3423"


def test_rest_scan_broadcasts_ndjson():
    """Verify REST POST /scan triggers scan and broadcasts NDJSON events."""
    client = TestClient(app)
    
    with client.websocket_connect("/ws/stream") as ws:
        ws.receive_text()

        resp = client.post("/scan", json={"services": ["ec2", "s3"], "mock_mode": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"

        # Check WebSocket received scan progress broadcast
        msg1 = json.loads(ws.receive_text().strip())
        assert msg1["event"] == "SCAN_PROGRESS"

        msg2 = json.loads(ws.receive_text().strip())
        assert msg2["event"] == "FINDINGS_DISCOVERED"


def test_langgraph_execution_broadcasts_ndjson():
    """Verify LangGraph assistant session start broadcasts node execution events as NDJSON."""
    client = TestClient(app)
    
    with client.websocket_connect("/ws/stream") as ws:
        ws.receive_text()

        # Start assistant session which runs LangGraph nodes
        resp = client.post("/assistant/start", json={
            "target_services": ["ec2", "iam", "s3"]
        })
        assert resp.status_code == 200

        # Receive streamed LangGraph node execution events
        node_event = json.loads(ws.receive_text().strip())
        assert node_event["event"] == "LANGGRAPH_NODE_EXECUTION"
        assert "node" in node_event

