// State Management
let allFindings = [];
let scanSummary = null;
let currentTriage = null;

// DOM Elements
const findingsContainer = document.getElementById("findings-list");
const totalFindingsEl = document.getElementById("metric-total");
const passRateEl = document.getElementById("metric-pass-rate");
const riskScoreEl = document.getElementById("metric-risk");
const critCountEl = document.getElementById("metric-crit");
const searchInput = document.getElementById("search-input");
const severityFilter = document.getElementById("severity-filter");
const statusFilter = document.getElementById("status-filter");
const serviceFilter = document.getElementById("service-filter");
const scanBtn = document.getElementById("btn-run-scan");
const triageBtn = document.getElementById("btn-open-triage");
const triageModal = document.getElementById("triage-modal");
const triageModalContent = document.getElementById("triage-modal-body");
const pipelineModal = document.getElementById("pipeline-modal");
const pipelineModalBody = document.getElementById("pipeline-modal-body");

// Initialize on Load
document.addEventListener("DOMContentLoaded", () => {
  fetchHealth();
  triggerScan(); // initial scan to populate findings immediately
  setupEventListeners();
});

function setupEventListeners() {
  scanBtn.addEventListener("click", () => triggerScan());
  triageBtn.addEventListener("click", () => openTriageModal());

  searchInput.addEventListener("input", filterAndRender);
  severityFilter.addEventListener("change", filterAndRender);
  statusFilter.addEventListener("change", filterAndRender);
  serviceFilter.addEventListener("change", filterAndRender);

  document.querySelectorAll(".modal-close").forEach(btn => {
    btn.addEventListener("click", () => {
      triageModal.classList.remove("open");
      pipelineModal.classList.remove("open");
    });
  });

  // Pipeline stepper click events
  document.querySelectorAll(".step-node").forEach(node => {
    node.addEventListener("click", () => {
      const step = node.getAttribute("data-step");
      openPipelineModal(step);
    });
  });
}

// Check Health & LocalStack
async function fetchHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById("localstack-status");
      if (data.localstack_connected) {
        badge.innerHTML = `<span class="pulse-dot"></span> LocalStack Live (${data.engine_mode})`;
      } else {
        badge.innerHTML = `<span class="pulse-dot" style="background:#f59e0b;box-shadow:0 0 10px #f59e0b;"></span> Emulated LocalStack (${data.engine_mode})`;
      }
    }
  } catch (err) {
    console.error("Health check error:", err);
  }
}

// Trigger Scan
async function triggerScan() {
  setScanning(true);
  try {
    const res = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        services: ["s3", "iam", "ec2"],
        run_graph_analysis: true
      })
    });

    if (!res.ok) throw new Error("Scan request failed with status: " + res.status);

    const data = await res.json();
    allFindings = data.findings || [];
    scanSummary = data.summary || {};
    currentTriage = data.graph_analysis || null;

    updateMetrics(scanSummary);
    filterAndRender();
  } catch (err) {
    console.error("Scan error:", err);
    findingsContainer.innerHTML = `
      <div class="glass-panel" style="padding: 2rem; text-align: center; color: #ef4444;">
        <h3>⚠️ Scan Execution Error</h3>
        <p style="margin-top:0.5rem; color:#94a3b8;">${err.message}</p>
      </div>
    `;
  } finally {
    setScanning(false);
  }
}

function setScanning(isScanning) {
  if (isScanning) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span class="scanning-indicator"></span> Scanning LocalStack...`;
  } else {
    scanBtn.disabled = false;
    scanBtn.innerHTML = `
      <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
      </svg>
      Run Prowler Scan
    `;
  }
}

// Update Top KPI Cards
function updateMetrics(summary) {
  if (!summary) return;
  totalFindingsEl.textContent = summary.total_findings || 0;
  passRateEl.textContent = (summary.pass_percentage || 0) + "%";
  riskScoreEl.textContent = (summary.risk_score || 0) + "/100";
  critCountEl.textContent = (summary.critical || 0) + (summary.high || 0);

  // Dynamic Risk Score color
  if (summary.risk_score >= 70) {
    riskScoreEl.style.color = "var(--sev-critical)";
  } else if (summary.risk_score >= 40) {
    riskScoreEl.style.color = "var(--sev-high)";
  } else {
    riskScoreEl.style.color = "var(--sev-pass)";
  }
}

// Filter and Render Findings
function filterAndRender() {
  const query = searchInput.value.toLowerCase().trim();
  const selectedSev = severityFilter.value;
  const selectedStatus = statusFilter.value;
  const selectedService = serviceFilter.value;

  const filtered = allFindings.filter(f => {
    // Query Search
    const matchesQuery = !query || 
      f.title.toLowerCase().includes(query) ||
      f.resource_id.toLowerCase().includes(query) ||
      f.resource_type.toLowerCase().includes(query) ||
      f.description.toLowerCase().includes(query);

    // Severity Filter
    const matchesSev = (selectedSev === "ALL") || (f.severity === selectedSev);

    // Status Filter
    const matchesStatus = (selectedStatus === "ALL") || (f.compliance_status === selectedStatus);

    // Service Filter
    let matchesService = true;
    if (selectedService !== "ALL") {
      const typeLower = f.resource_type.toLowerCase();
      if (selectedService === "s3") matchesService = typeLower.includes("s3");
      else if (selectedService === "iam") matchesService = typeLower.includes("iam");
      else if (selectedService === "ec2") matchesService = typeLower.includes("ec2") || typeLower.includes("securitygroup");
    }

    return matchesQuery && matchesSev && matchesStatus && matchesService;
  });

  renderFindings(filtered);
}

function renderFindings(findings) {
  if (!findings || findings.length === 0) {
    findingsContainer.innerHTML = `
      <div class="glass-panel" style="padding: 3rem; text-align: center; color: var(--text-muted);">
        <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">🔍 No matching security findings</p>
        <span style="font-size: 0.85rem;">Adjust search filters or run a new scan against LocalStack.</span>
      </div>
    `;
    return;
  }

  findingsContainer.innerHTML = findings.map(f => {
    const isPassed = f.compliance_status === "PASSED";
    const cardClass = isPassed ? "passed" : f.severity.toLowerCase();
    const badgeClass = isPassed ? "pass" : f.severity.toLowerCase();

    return `
      <div class="glass-panel finding-card ${cardClass}" id="card-${f.id}">
        <div class="finding-header">
          <div class="badge-row">
            <span class="badge ${badgeClass}">${f.severity}</span>
            <span class="badge ${isPassed ? 'pass' : 'critical'}">${f.compliance_status}</span>
            <span class="badge resource-type">${f.resource_type}</span>
            <span class="badge" style="background:rgba(255,255,255,0.03);color:#64748b;">${f.region}</span>
          </div>
          <button class="details-toggle" onclick="toggleDetails('${f.id}')">
            View Technical Details ▾
          </button>
        </div>

        <h3 class="finding-title">${escapeHtml(f.title)}</h3>
        <p class="finding-desc">${escapeHtml(f.description)}</p>

        <div class="resource-bar">
          <span style="color:#64748b;font-weight:600;">RESOURCE:</span>
          <span>${escapeHtml(f.resource_id)}</span>
          <button class="copy-btn" title="Copy Resource ARN" onclick="copyText('${escapeHtml(f.resource_id)}')">📋</button>
        </div>

        ${f.recommendation ? `
          <div class="recommendation-box">
            <strong>Actionable Recommendation:</strong> ${escapeHtml(f.recommendation)}
            ${f.recommendation_url ? `<a href="${f.recommendation_url}" target="_blank" style="color:var(--accent-cyan);margin-left:0.5rem;text-decoration:none;">Doc Link ↗</a>` : ''}
          </div>
        ` : ''}

        <div class="accordion-body" id="details-${f.id}">
          <div style="margin-bottom:0.75rem;font-size:0.8rem;color:#94a3b8;">
            <strong>Generator ID:</strong> <code>${escapeHtml(f.generator_id || 'prowler')}</code> | 
            <strong>Compliance Frameworks:</strong> ${f.compliance_frameworks ? f.compliance_frameworks.join(', ') : 'CIS AWS Benchmark'}
          </div>

          <div style="font-size:0.8rem;font-weight:600;color:var(--accent-cyan);margin-top:0.75rem;">
            AWS Security Finding Format (ASFF) Raw JSON:
          </div>
          <pre class="code-block">${escapeHtml(JSON.stringify(f.raw_asff || f, null, 2))}</pre>
        </div>

        <div class="finding-footer">
          <span>Finding ID: ${escapeHtml(f.finding_id || f.id)}</span>
          <span>Recorded: ${f.created_at || 'Just now'}</span>
        </div>
      </div>
    `;
  }).join("");
}

// Toggle Finding Details
window.toggleDetails = function(id) {
  const el = document.getElementById(`details-${id}`);
  if (el) {
    el.classList.toggle("open");
  }
};

// Clipboard Helper
window.copyText = function(text) {
  navigator.clipboard.writeText(text);
  alert("Copied to clipboard: " + text);
};

// Escape HTML helper
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Open LangGraph Triage Modal
function openTriageModal() {
  if (!currentTriage) {
    triageModalContent.innerHTML = "<p>No LangGraph triage data available. Run a scan first.</p>";
    triageModal.classList.add("open");
    return;
  }

  const triage = currentTriage;
  const vectors = triage.attack_vectors || [];
  const queue = triage.prioritized_queue || [];
  const remediations = triage.remediation_plans || [];

  triageModalContent.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding:1rem;background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.3);border-radius:10px;">
      <div>
        <h4 style="font-size:1.1rem;color:#c084fc;">LangGraph Security Triage Engine</h4>
        <span style="font-size:0.8rem;color:#cbd5e1;">Agentic multi-stage pipeline: Ingest ➔ Assess ➔ Prioritize ➔ Remediate ➔ Executive Report</span>
      </div>
      <div style="text-align:right;">
        <span class="badge ${triage.risk_rating === 'CRITICAL' ? 'critical' : 'high'}" style="font-size:0.9rem;padding:0.4rem 1rem;">
          POSTURE: ${triage.risk_rating} (${triage.risk_score}/100)
        </span>
      </div>
    </div>

    <h3 style="font-size:1rem;margin-bottom:0.75rem;color:var(--accent-cyan);">1. Active Cloud Attack Vectors</h3>
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1rem;margin-bottom:1.5rem;">
      ${vectors.map(v => `
        <div class="glass-panel" style="padding:1rem;border-left:3px solid ${v.severity === 'CRITICAL' ? 'var(--sev-critical)' : 'var(--sev-high)'};">
          <div style="display:flex;justify-content:space-between;margin-bottom:0.4rem;">
            <strong style="font-size:0.9rem;">${escapeHtml(v.category)}</strong>
            <span class="badge ${v.severity.toLowerCase()}">${v.severity}</span>
          </div>
          <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:0.5rem;">${escapeHtml(v.description)}</p>
          <span style="font-size:0.72rem;color:var(--accent-cyan);font-family:var(--font-mono);">${v.affected_resources_count} affected resource(s)</span>
        </div>
      `).join("")}
    </div>

    <h3 style="font-size:1rem;margin-bottom:0.75rem;color:var(--accent-cyan);">2. Prioritized Remediation Queue</h3>
    <div style="display:flex;flex-direction:column;gap:0.75rem;margin-bottom:1.5rem;">
      ${queue.map(q => `
        <div class="glass-panel" style="padding:0.85rem 1.25rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;">
          <div style="display:flex;align-items:center;gap:1rem;">
            <div style="width:28px;height:28px;border-radius:50%;background:rgba(0,240,255,0.15);color:var(--accent-cyan);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.85rem;">
              #${q.rank}
            </div>
            <div>
              <div style="font-size:0.9rem;font-weight:600;color:white;">${escapeHtml(q.title)}</div>
              <div style="font-size:0.75rem;color:#94a3b8;font-family:var(--font-mono);">${escapeHtml(q.resource_id)}</div>
            </div>
          </div>
          <div style="text-align:right;">
            <span class="badge ${q.severity.toLowerCase()}">${q.severity}</span>
            <div style="font-size:0.72rem;color:#f59e0b;margin-top:0.25rem;">${q.urgency}</div>
          </div>
        </div>
      `).join("")}
    </div>

    <h3 style="font-size:1rem;margin-bottom:0.75rem;color:var(--accent-cyan);">3. Automated Fixes (CLI & Terraform)</h3>
    <div style="display:flex;flex-direction:column;gap:1rem;margin-bottom:1.5rem;">
      ${remediations.map(r => `
        <div class="glass-panel" style="padding:1rem;">
          <h4 style="font-size:0.9rem;margin-bottom:0.4rem;color:white;">Fix for: ${escapeHtml(r.issue_title)}</h4>
          <span style="font-size:0.75rem;color:#94a3b8;">Est. Remediation Time: <strong>~${r.estimated_time_minutes} mins</strong></span>

          <div style="margin-top:0.5rem;">
            <span style="font-size:0.72rem;font-weight:700;color:var(--accent-cyan);">AWS CLI COMMAND:</span>
            <pre class="code-block">${escapeHtml(r.cli_command)}</pre>
          </div>

          <div style="margin-top:0.5rem;">
            <span style="font-size:0.72rem;font-weight:700;color:#c084fc;">TERRAFORM CODE REMEDIATION:</span>
            <pre class="code-block" style="color:#c084fc;">${escapeHtml(r.terraform_fix)}</pre>
          </div>
        </div>
      `).join("")}
    </div>

    <h3 style="font-size:1rem;margin-bottom:0.75rem;color:var(--accent-cyan);">4. Executive Posture Report</h3>
    <div class="glass-panel" style="padding:1.25rem;background:#06080e;">
      <pre style="white-space:pre-wrap;font-family:var(--font-sans);font-size:0.85rem;color:#cbd5e1;line-height:1.6;">${escapeHtml(triage.executive_summary || '')}</pre>
    </div>
  `;

  triageModal.classList.add("open");
}

// Pipeline Inspection Modal
function openPipelineModal(step) {
  let title = "";
  let content = "";

  if (step === "localstack") {
    title = "Step 1: LocalStack AWS Simulation";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;">LocalStack runs AWS cloud APIs entirely locally on <code>http://localhost:4566</code>. S3, IAM, and EC2 services simulate cloud infrastructure without incurring AWS bills.</p>
      <div class="code-block">
# Connecting boto3 to LocalStack
import boto3

session = boto3.Session(
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name="us-east-1"
)
s3 = session.client("s3", endpoint_url="http://localhost:4566")
buckets = s3.list_buckets()
      </div>
    `;
  } else if (step === "prowler") {
    title = "Step 2: Prowler SDK Execution";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;">Prowler runs security controls against LocalStack endpoints, directing AWS API queries to LocalStack using credentials <code>test/test</code> and <code>AWS_ENDPOINT_URL</code>.</p>
      <div class="code-block">
# Running Prowler targeting LocalStack with ASFF mode
prowler aws \\
  --endpoint-url http://localhost:4566 \\
  -M json-asff \\
  -F scan_output/scan_01 \\
  --services s3,iam,ec2
      </div>
    `;
  } else if (step === "asff") {
    title = "Step 3: Raw AWS Security Finding Format (ASFF)";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;">Prowler produces findings following the AWS Security Hub ASFF standard specification (SchemaVersion: 2018-10-08).</p>
      <div class="code-block">
{
  "SchemaVersion": "2018-10-08",
  "Id": "arn:aws:securityhub:us-east-1:.../finding/...",
  "Severity": { "Label": "HIGH", "Normalized": 70 },
  "Title": "S3 Bucket does not have default encryption enabled",
  "Resources": [{ "Type": "AwsS3Bucket", "Id": "arn:aws:s3:::vulnerable-bucket" }],
  "Compliance": { "Status": "FAILED" },
  "Remediation": { "Recommendation": { "Text": "Enable SSE-S3 or KMS" } }
}
      </div>
    `;
  } else if (step === "parser") {
    title = "Step 4: ASFF Parser & Normalizer";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;"><code>ASFFParser</code> extracts and normalizes the required schema attributes into strongly typed Pydantic models:</p>
      <ul style="margin-left:1.5rem;color:#cbd5e1;font-size:0.85rem;line-height:1.8;">
        <li><code>severity</code> (CRITICAL, HIGH, MEDIUM, LOW)</li>
        <li><code>resource_id</code> (ARN or name)</li>
        <li><code>resource_type</code> (e.g. AwsS3Bucket, AwsIamRole)</li>
        <li><code>recommendation</code> (Actionable remediation guidance)</li>
        <li><code>compliance_status</code> (FAILED, PASSED)</li>
      </ul>
    `;
  } else if (step === "json") {
    title = "Step 5: Standard Normalized JSON";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;">Clean, decoupled JSON payload returned by <code>/scan</code> and consumed by downstream AI agents.</p>
      <div class="code-block">
{
  "severity": "CRITICAL",
  "resource_id": "arn:aws:s3:::vulnerable-customer-data-bucket",
  "resource_type": "AwsS3Bucket",
  "recommendation": "Enable S3 Block Public Access...",
  "compliance_status": "FAILED",
  "severity_score": 90,
  "region": "us-east-1"
}
      </div>
    `;
  } else if (step === "langgraph") {
    title = "Step 6: LangGraph Agentic Triage";
    content = `
      <p style="margin-bottom:1rem;color:#94a3b8;">LangGraph takes the standard JSON findings and executes a multi-node StateGraph for risk scoring, prioritization, and automated code generation.</p>
      <div class="code-block">
StateGraph(SecurityTriageState)
  START ➔ ingest ➔ risk_assessment ➔ prioritization ➔ remediation_generator ➔ executive_reporting ➔ END
      </div>
    `;
  }

  pipelineModalBody.innerHTML = `
    <h3 style="font-size:1.15rem;color:var(--accent-cyan);margin-bottom:1rem;">${title}</h3>
    ${content}
  `;
  pipelineModal.classList.add("open");
}
