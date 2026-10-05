# Prowler LocalStack Security Service

A production-grade Python microservice built with **FastAPI** that integrates **Prowler** with **LocalStack** instead of live AWS. The service executes security compliance audits, captures findings in **AWS Security Finding Format (ASFF)**, normalizes them into structured JSON objects, and feeds them into an automated **LangGraph** security triage workflow.

---

## 🏛️ Architecture & Data Flow

The microservice follows Clean Architecture principles:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  LocalStack  │ ──► │ Prowler SDK  │ ──► │ Raw Findings │
│ (Port 4566)  │     │ (CLI/Engine) │     │    (ASFF)    │
└──────────────┘     └──────────────┘     └──────────────┘
                                                 │
                                                 ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  LangGraph   │ ◄── │Standard JSON │ ◄── │ ASFF Parser  │
│(Agent Triage)│     │ (/scan API)  │     │(Normalizer)  │
└──────────────┘     └──────────────┘     └──────────────┘
```

1. **LocalStack**: Emulates AWS cloud APIs (`S3`, `IAM`, `EC2`, `STS`, `SecurityHub`) locally without cloud costs or risks.
2. **Prowler SDK**: Executes security compliance checks against LocalStack endpoints using configured AWS sessions (`AWS_ENDPOINT_URL=http://localhost:4566`).
3. **Raw Findings**: Captures findings adhering to the official **AWS Security Finding Format (ASFF)** standard.
4. **ASFF Parser**: Normalizes raw ASFF into strongly typed models with required core fields:
   - `severity`: (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
   - `resource_id`: Target resource ARN or identifier
   - `resource_type`: AWS resource type (e.g., `AwsS3Bucket`, `AwsIamRole`, `AwsEc2SecurityGroup`)
   - `recommendation`: Actionable remediation guidance
   - `compliance_status`: Check result (`PASSED`, `FAILED`, `WARNING`)
5. **Standard JSON**: Clean, decoupled API response returned by `POST /scan`.
6. **LangGraph Agentic Triage**: Executes an automated multi-step state graph evaluating blast radius, attack vectors, prioritized remediation queues, and generating executive reports with Terraform and AWS CLI fixes.

---

## 📁 Project Directory Structure

```
d:/Projects/SB-Project/
├── backend/
│   ├── core/
│   │   ├── config.py             # Pydantic v2 BaseSettings (Endpoints, credentials, postgres URL)
│   ├── scanner/
│   │   ├── models.py             # ASFF schema, NormalizedFinding, ScanRequest, ScanResponse
│   │   ├── parser.py             # ASFFParser: converts ASFF to Normalized JSON
│   │   ├── llm_parser.py         # LLMASFFParser: converts ASFF to simplified LLM reasoning objects
│   │   ├── prowler_service.py    # Prowler CLI runner & LocalStack Boto3 audit engine
│   │   └── utils.py              # LocalStack session factory & health check
│   ├── graph/
│   │   ├── state.py              # SecurityTriageState TypedDict schema
│   │   ├── workflow.py           # LangGraph StateGraph (Ingest -> Assess -> Prioritize -> Remediate -> Report)
│   │   ├── assistant_state.py    # SecurityAssistantState TypedDict schema
│   │   └── assistant.py          # Autonomous Cloud Security Assistant (7-node StateGraph with interrupt() & AsyncPostgresSaver)
│   └── api/
│       ├── main.py               # FastAPI application setup, CORS, static UI mounting
│       ├── routes.py             # /scan, /scan/llm, /assistant/start, /assistant/approve, /health
│       └── deps.py               # Dependency injection container
├── frontend/
│   ├── index.html                # Modern Cyber Security UI dashboard
│   ├── css/styles.css            # Dark glassmorphism stylesheet
│   └── js/app.js                 # Real-time scan trigger, interactive filters, modal viewers
├── terraform/
│   ├── provider.tf               # Terraform AWS provider mapped to LocalStack endpoints
│   ├── main.tf                   # S3, IAM, and EC2 resources (vulnerable & compliant)
│   ├── variables.tf              # Configurable variables
│   └── outputs.tf                # Resource identifiers
├── docker/
│   ├── Dockerfile.backend        # Multi-stage Python 3.11 container with Prowler
│   ├── docker-compose.yml        # Orchestration for LocalStack and FastAPI backend
│   ├── localstack-init.sh        # Awslocal startup script for provisioning mock resources
│   └── .env.example              # Container environment templates
├── tests/
│   ├── test_parser.py            # Unit tests for ASFF parsing and normalization
│   ├── test_prowler_service.py   # Unit tests for Prowler scan execution
│   ├── test_graph.py             # Unit tests for LangGraph state graph
│   └── test_api.py               # Integration tests for FastAPI endpoints
├── requirements.txt              # Python package dependencies
├── run.py                        # Root execution script
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ installed
- Node.js (optional, for frontend tools)
- Docker & Docker Compose (optional, for running LocalStack in container)

### 2. Local Installation

```bash
# Clone and enter workspace
git clone <repo-url>
cd SB-Project

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Running the FastAPI Service

```bash
python run.py
```

The application will start on **`http://localhost:8000`**:
- **Interactive Cyber Security Dashboard**: `http://localhost:8000/`
- **Swagger / OpenAPI Documentation**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`

---

## 🐳 Running with Docker & LocalStack

To run the complete system (LocalStack + FastAPI backend) in isolated Docker containers:

```bash
cd docker
docker-compose up --build
```

This starts:
1. **LocalStack** on port `4566` with S3, IAM, and EC2 services initialized via `localstack-init.sh`.
2. **FastAPI Backend** on port `8000` connected directly to LocalStack.

---

## 🏗️ Provisioning Test Infrastructure with Terraform

The `terraform/` directory provisions realistic infrastructure inside LocalStack to test both failing and passing compliance checks:

```bash
cd terraform

# Initialize Terraform
terraform init

# Plan and apply against LocalStack
terraform apply -auto-approve
```

Resources created in LocalStack:
- **`vulnerable-customer-data-bucket`**: S3 bucket without default encryption and without public access block (*Triggers CIS Benchmark FAILED*).
- **`secure-encrypted-backup-bucket`**: S3 bucket with AES256 default encryption and public access block enabled (*Triggers CIS Benchmark PASSED*).
- **`insecure-app-admin-role`**: IAM role with `AdministratorAccess` wildcard policy (*Triggers Least-Privilege FAILED*).
- **`insecure-ssh-sg`**: Security group allowing `0.0.0.0/0` on port 22 (*Triggers Ingress FAILED*).

---

## 📡 API Reference

### `POST /scan`
Triggers a Prowler security scan targeting LocalStack, captures ASFF findings, and returns the normalized list.

**Request Body (optional):**
```json
{
  "services": ["s3", "iam", "ec2"],
  "severity_filter": ["CRITICAL", "HIGH"],
  "compliance_status_filter": ["FAILED"],
  "run_graph_analysis": true
}
```

**Normalized Response Body (`200 OK`):**
```json
{
  "status": "success",
  "scan_id": "scan-a1b2c3d4",
  "timestamp": "2026-10-04T12:00:00Z",
  "target_endpoint": "http://localhost:4566",
  "summary": {
    "total_findings": 6,
    "passed": 2,
    "failed": 4,
    "critical": 2,
    "high": 2,
    "medium": 0,
    "low": 0,
    "pass_percentage": 33.33,
    "risk_score": 80.0
  },
  "findings": [
    {
      "id": "norm-9f8e7d6c",
      "finding_id": "arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_public_access_block",
      "title": "S3 Bucket does not have Public Access Block enabled",
      "description": "Amazon S3 Public Access Block settings prevent public policies.",
      "severity": "CRITICAL",
      "severity_score": 90,
      "resource_id": "arn:aws:s3:::vulnerable-customer-data-bucket",
      "resource_type": "AwsS3Bucket",
      "region": "us-east-1",
      "account_id": "000000000000",
      "compliance_status": "FAILED",
      "compliance_frameworks": ["CIS AWS Benchmark 1.4 - 2.1.5"],
      "recommendation": "Enable S3 Block Public Access at the bucket level.",
      "recommendation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      "generator_id": "prowler-s3_bucket_public_access_block",
      "created_at": "2026-10-04T12:00:00Z"
    }
  ],
  "graph_analysis": {
    "risk_score": 80.0,
    "risk_rating": "CRITICAL",
    "attack_vectors": [...],
    "prioritized_queue": [...],
    "remediation_plans": [...]
  }
}
```

### `GET /health`
Returns microservice status and LocalStack connectivity.

```json
{
  "status": "healthy",
  "localstack_endpoint": "http://localhost:4566",
  "localstack_connected": true,
  "prowler_cli_available": false,
  "engine_mode": "Boto3 Direct LocalStack Engine",
  "timestamp": "2026-10-04T12:00:00Z"
}
```

### `POST /assistant/start`
Starts the autonomous security assistant session:
`Observation` ➔ `Reasoning` ➔ `Need Fix?` ➔ `RiskAssessment` ➔ `HumanApproval` (`interrupt()`).
Pauses execution and returns the pending authorization request with thread ID.

### `POST /assistant/approve`
Resumes the paused assistant session using `Command(resume=...)`:
`HumanApproval` ➔ `Approved?` ➔ `ExecuteRemediation` ➔ `VerifyFix` ➔ `Finish`.

---

## 🤖 Autonomous Cloud Security Assistant

An autonomous 7-node LangGraph `StateGraph` with human-in-the-loop governance:

```
Observation Node
       ↓
 Reasoning Node
       ↓
  (Need Fix?) ─── No ──► Finish (CLEAN)
       ↓ Yes
Risk Assessment Node
       ↓
Human Approval Node (interrupt() pauses execution)
       ↓
  (Approved?) ─── No ──► Finish (REJECTED)
       ↓ Yes
Execute Remediation Node (Applies fixes to LocalStack)
       ↓
  Verify Fix Node (Audits post-remediation compliance)
       ↓
   Finish Node (Final Executive Report)
```

### PostgreSQL Persistence with `AsyncPostgresSaver`
State checkpoints are persisted using `AsyncPostgresSaver` backed by PostgreSQL (configured via `POSTGRES_URL` or in `docker-compose.yml`), enabling long-running workflows to pause across hours or days while awaiting human approval.

---

## 🧪 Running Automated Tests

Run the full pytest suite:

```bash
pytest -v
```

All 23 tests validate:
- **ASFF & LLM Parsers**: Schema transformations, severity mapping, resource metadata extraction, token-efficient prompt synthesis.
- **Autonomous Assistant**: 7-node execution, `interrupt()` pause, resume with approval, rejection routing, and verification.
- **AsyncPostgresSaver**: PostgreSQL checkpoint integration and setup.
- **FastAPI HTTP Routes**: `/scan`, `/scan/llm`, `/parse/llm`, `/assistant/start`, `/assistant/approve`, `/health`.

---

## 📜 License
MIT License. Created for LocalStack and Prowler Cloud Security Engineering.
