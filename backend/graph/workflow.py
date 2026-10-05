from typing import Dict, Any, List
from langgraph.graph import StateGraph, START, END

from backend.graph.state import (
    SecurityTriageState,
    AttackVector,
    PrioritizedIssue,
    RemediationItem,
)
from backend.scanner.models import NormalizedFinding


def ingest_findings_node(state: SecurityTriageState) -> Dict[str, Any]:
    """Ingest, validate, and compute baseline distributions from normalized findings."""
    raw_findings = state.get("findings", [])
    total = len(raw_findings)

    passed_count = sum(1 for f in raw_findings if f.get("compliance_status") == "PASSED")
    failed_count = sum(1 for f in raw_findings if f.get("compliance_status") == "FAILED")

    critical_count = sum(
        1 for f in raw_findings if f.get("severity") == "CRITICAL" and f.get("compliance_status") == "FAILED"
    )
    high_count = sum(
        1 for f in raw_findings if f.get("severity") == "HIGH" and f.get("compliance_status") == "FAILED"
    )
    medium_count = sum(
        1 for f in raw_findings if f.get("severity") == "MEDIUM" and f.get("compliance_status") == "FAILED"
    )
    low_count = sum(
        1 for f in raw_findings if f.get("severity") == "LOW" and f.get("compliance_status") == "FAILED"
    )

    return {
        "total_findings": total,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "status": "ingested",
    }


def risk_assessment_node(state: SecurityTriageState) -> Dict[str, Any]:
    """Analyze attack vectors and calculate cloud security risk posture score."""
    findings = state.get("findings", [])
    failed_findings = [f for f in findings if f.get("compliance_status") == "FAILED"]

    crit = state.get("critical_count", 0)
    high = state.get("high_count", 0)
    med = state.get("medium_count", 0)
    low = state.get("low_count", 0)

    # Composite risk calculation
    raw_score = (crit * 30.0) + (high * 15.0) + (med * 8.0) + (low * 2.0)
    risk_score = round(min(100.0, raw_score), 1)

    if risk_score >= 70:
        rating = "CRITICAL"
    elif risk_score >= 40:
        rating = "ELEVATED"
    elif risk_score >= 20:
        rating = "MODERATE"
    else:
        rating = "LOW"

    # Identify Attack Vectors
    attack_vectors: List[AttackVector] = []

    # 1. S3 Public Access / Data Exposure
    s3_public = [
        f for f in failed_findings
        if "s3" in f.get("resource_type", "").lower() or "public" in f.get("title", "").lower()
    ]
    if s3_public:
        attack_vectors.append({
            "category": "Data Exposure / S3 Leakage",
            "severity": "CRITICAL" if any(f.get("severity") == "CRITICAL" for f in s3_public) else "HIGH",
            "affected_resources_count": len(s3_public),
            "description": "Unrestricted S3 permissions or missing Block Public Access allows potential data exfiltration.",
            "sample_resources": [f.get("resource_id", "") for f in s3_public[:3]],
        })

    # 2. Overprivileged IAM
    iam_issues = [
        f for f in failed_findings
        if "iam" in f.get("resource_type", "").lower() or "role" in f.get("title", "").lower()
    ]
    if iam_issues:
        attack_vectors.append({
            "category": "Privilege Escalation / Wildcard IAM",
            "severity": "CRITICAL",
            "affected_resources_count": len(iam_issues),
            "description": "Wildcard administrator privileges (*:*) grant attackers lateral movement and account takeover.",
            "sample_resources": [f.get("resource_id", "") for f in iam_issues[:3]],
        })

    # 3. Open Network Ingress
    net_issues = [
        f for f in failed_findings
        if "securitygroup" in f.get("resource_type", "").lower() or "ssh" in f.get("title", "").lower()
    ]
    if net_issues:
        attack_vectors.append({
            "category": "Network Perimeter Breach (0.0.0.0/0)",
            "severity": "HIGH",
            "affected_resources_count": len(net_issues),
            "description": "Security Groups permitting ingress from 0.0.0.0/0 directly expose management ports to brute force.",
            "sample_resources": [f.get("resource_id", "") for f in net_issues[:3]],
        })

    # 4. Storage at rest
    enc_issues = [
        f for f in failed_findings
        if "encryption" in f.get("title", "").lower() and f not in s3_public
    ]
    if enc_issues:
        attack_vectors.append({
            "category": "Unencrypted Storage at Rest",
            "severity": "MEDIUM",
            "affected_resources_count": len(enc_issues),
            "description": "Default encryption not enforced on storage volumes or buckets, violating compliance controls.",
            "sample_resources": [f.get("resource_id", "") for f in enc_issues[:3]],
        })

    return {
        "risk_score": risk_score,
        "risk_rating": rating,
        "attack_vectors": attack_vectors,
        "status": "risk_assessed",
    }


def prioritization_node(state: SecurityTriageState) -> Dict[str, Any]:
    """Prioritize issues based on blast radius, severity, and compliance impact."""
    findings = state.get("findings", [])
    failed_findings = [f for f in findings if f.get("compliance_status") == "FAILED"]

    # Sort order: CRITICAL (4) -> HIGH (3) -> MEDIUM (2) -> LOW (1)
    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

    sorted_findings = sorted(
        failed_findings,
        key=lambda x: (
            severity_weights.get(x.get("severity", "LOW"), 0),
            x.get("severity_score", 0),
        ),
        reverse=True,
    )

    prioritized_queue: List[PrioritizedIssue] = []
    for rank, f in enumerate(sorted_findings, start=1):
        sev = f.get("severity", "LOW")
        res_type = f.get("resource_type", "Other")

        if sev == "CRITICAL":
            urgency = "Immediate (< 24 Hours)"
            blast_radius = "Account-wide or Critical Data Store"
        elif sev == "HIGH":
            urgency = "Urgent (< 72 Hours)"
            blast_radius = "Service Perimeter or Network Ingress"
        elif sev == "MEDIUM":
            urgency = "Planned (< 14 Days)"
            blast_radius = "Component level"
        else:
            urgency = "Low (< 30 Days)"
            blast_radius = "Informational"

        frameworks = f.get("compliance_frameworks", [])
        primary_framework = frameworks[0] if frameworks else "AWS FSBP"

        prioritized_queue.append({
            "rank": rank,
            "title": f.get("title", "Security Finding"),
            "severity": sev,
            "resource_id": f.get("resource_id", ""),
            "resource_type": res_type,
            "blast_radius": blast_radius,
            "compliance_framework": primary_framework,
            "urgency": urgency,
        })

    return {
        "prioritized_queue": prioritized_queue,
        "status": "prioritized",
    }


def remediation_generator_node(state: SecurityTriageState) -> Dict[str, Any]:
    """Generate exact CLI commands, Terraform snippets, and guidance for prioritized findings."""
    prioritized = state.get("prioritized_queue", [])
    findings_map = {f.get("resource_id"): f for f in state.get("findings", [])}

    remediation_plans: List[RemediationItem] = []

    for item in prioritized[:6]:  # Generate detailed plans for top actionable items
        res_id = item["resource_id"]
        res_type = item["resource_type"]
        title = item["title"]

        # 1. S3 Public Access Block
        if "public_access_block" in title.lower() or "public" in title.lower():
            bucket_name = res_id.split(":::")[-1] if ":::" in res_id else res_id
            cli = f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
            tf = f"""resource "aws_s3_bucket_public_access_block" "remediation" {{
  bucket = "{bucket_name}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"""
            manual = f"Open AWS Console > S3 > Select '{bucket_name}' > Permissions > Edit 'Block public access (bucket settings)' > Check 'Block all public access' > Save."
            est_time = 5

        # 2. S3 Default Encryption
        elif "encryption" in title.lower() and "s3" in res_type.lower():
            bucket_name = res_id.split(":::")[-1] if ":::" in res_id else res_id
            cli = f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
            tf = f"""resource "aws_s3_bucket_server_side_encryption_configuration" "remediation" {{
  bucket = "{bucket_name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"""
            manual = f"Open AWS S3 Console > '{bucket_name}' > Properties > Default encryption > Edit > Enable Server-side encryption with Amazon S3-managed keys (SSE-S3)."
            est_time = 10

        # 3. IAM Overprivileged Admin
        elif "iam" in res_type.lower() or "administratoraccess" in title.lower():
            role_name = res_id.split("/")[-1] if "/" in res_id else res_id
            cli = f"aws iam detach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
            tf = f"""# Detach wildcard AdministratorAccess and attach scoped policy
resource "aws_iam_role_policy_attachment" "scoped_policy" {{
  role       = "{role_name}"
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess" # Or tailored custom policy
}}"""
            manual = f"Navigate to IAM > Roles > '{role_name}' > Permissions tab > Find 'AdministratorAccess' > Click Remove > Attach specific policy matching workload."
            est_time = 15

        # 4. Security Group Open SSH
        elif "securitygroup" in res_type.lower() or "ssh" in title.lower():
            sg_id = res_id.split("/")[-1] if "/" in res_id else res_id
            cli = f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0"
            tf = f"""# Update ingress rule to limit CIDR or migrate to AWS Systems Manager
ingress {{
  description = "SSH from Authorized VPN/Bastion"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"] # Restricted corporate CIDR
}}"""
            manual = f"Go to EC2 > Security Groups > '{sg_id}' > Inbound rules > Edit > Remove 0.0.0.0/0 on port 22 > Add trusted IP or switch to SSM Session Manager."
            est_time = 10

        # Default fallback
        else:
            cli = f"# Review resource configuration: aws {res_type.lower().replace('aws', '')} get/describe for {res_id}"
            tf = "# Update resource configuration in Terraform according to benchmark standards."
            manual = "Follow the official AWS documentation link in the finding recommendation."
            est_time = 15

        remediation_plans.append({
            "issue_title": title,
            "resource_id": res_id,
            "cli_command": cli,
            "terraform_fix": tf,
            "manual_steps": manual,
            "estimated_time_minutes": est_time,
        })

    return {
        "remediation_plans": remediation_plans,
        "status": "remediations_generated",
    }


def executive_reporting_node(state: SecurityTriageState) -> Dict[str, Any]:
    """Assemble final markdown executive summary report."""
    total = state.get("total_findings", 0)
    failed = state.get("failed_count", 0)
    passed = state.get("passed_count", 0)
    crit = state.get("critical_count", 0)
    high = state.get("high_count", 0)
    risk_score = state.get("risk_score", 0.0)
    risk_rating = state.get("risk_rating", "MODERATE")
    vectors = state.get("attack_vectors", [])

    report_lines = [
        "# AWS Cloud Security Posture & Compliance Report",
        f"**Risk Rating:** `{risk_rating}` | **Composite Risk Score:** `{risk_score}/100`",
        "",
        "## Executive Summary",
        f"- **Total Security Controls Evaluated:** {total}",
        f"- **Controls Compliant (PASSED):** {passed} ({round((passed/total*100) if total else 100, 1)}%)",
        f"- **Non-Compliant Findings (FAILED):** {failed}",
        f"  - **Critical Vulnerabilities:** {crit}",
        f"  - **High Severity Vulnerabilities:** {high}",
        "",
        "## Key Attack Vectors Identified",
    ]

    for v in vectors:
        report_lines.append(f"- **[{v['severity']}] {v['category']}**: {v['description']} (*{v['affected_resources_count']} affected*)")

    report_lines.extend([
        "",
        "## Recommended Immediate Actions",
        "1. Block all public access for sensitive S3 buckets to prevent data leakages.",
        "2. Detach `AdministratorAccess` policies from workload roles and implement Least Privilege IAM.",
        "3. Revoke `0.0.0.0/0` ingress on port 22 in all security groups.",
        "",
        "*Report generated automatically by LangGraph Security Triage Engine.*",
    ])

    return {
        "executive_summary": "\n".join(report_lines),
        "status": "completed",
    }


def build_triage_graph():
    """Build and compile the LangGraph Security Triage workflow."""
    workflow = StateGraph(SecurityTriageState)

    # Add Nodes
    workflow.add_node("ingest", ingest_findings_node)
    workflow.add_node("risk_assessment", risk_assessment_node)
    workflow.add_node("prioritization", prioritization_node)
    workflow.add_node("remediation_generator", remediation_generator_node)
    workflow.add_node("executive_reporting", executive_reporting_node)

    # Add Edges
    workflow.add_edge(START, "ingest")
    workflow.add_edge("ingest", "risk_assessment")
    workflow.add_edge("risk_assessment", "prioritization")
    workflow.add_edge("prioritization", "remediation_generator")
    workflow.add_edge("remediation_generator", "executive_reporting")
    workflow.add_edge("executive_reporting", END)

    return workflow.compile()


# Singleton compiled graph
triage_graph = build_triage_graph()


def run_security_triage(findings: List[NormalizedFinding]) -> Dict[str, Any]:
    """Execute the LangGraph workflow on a list of normalized findings."""
    raw_findings_dict = [f.model_dump() for f in findings]
    initial_state: SecurityTriageState = {"findings": raw_findings_dict}
    result = triage_graph.invoke(initial_state)
    return result
