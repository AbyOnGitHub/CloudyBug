import pytest
from backend.scanner.prowler_service import ProwlerService
from backend.scanner.models import ScanRequest, SeverityLevel, ComplianceStatus


def test_prowler_service_scan():
    service = ProwlerService()
    req = ScanRequest(services=["s3", "iam", "ec2"], run_graph_analysis=False)

    response = service.execute_scan(req)

    assert response.status == "success"
    assert response.scan_id.startswith("scan-")
    assert len(response.findings) > 0
    assert response.summary.total_findings == len(response.findings)

    # Ensure required normalized attributes exist on each finding
    for f in response.findings:
        assert hasattr(f, "severity")
        assert hasattr(f, "resource_id")
        assert hasattr(f, "resource_type")
        assert hasattr(f, "recommendation")
        assert hasattr(f, "compliance_status")
        assert f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFORMATIONAL]
        assert f.compliance_status in [ComplianceStatus.PASSED, ComplianceStatus.FAILED, ComplianceStatus.WARNING, ComplianceStatus.NOT_AVAILABLE]


def test_prowler_service_with_severity_filter():
    service = ProwlerService()
    req = ScanRequest(
        services=["s3", "iam"],
        severity_filter=[SeverityLevel.CRITICAL],
        run_graph_analysis=False
    )

    response = service.execute_scan(req)

    assert response.status == "success"
    for f in response.findings:
        assert f.severity == SeverityLevel.CRITICAL
