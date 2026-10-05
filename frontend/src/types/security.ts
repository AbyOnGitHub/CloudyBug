export type NavigationTab = 
  | 'dashboard' 
  | 'activity' 
  | 'findings' 
  | 'approval' 
  | 'resources' 
  | 'logs';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type ComplianceStatus = 'PASSED' | 'FAILED' | 'WARNING' | 'MUTED';
export type ApprovalStatus = 'WAITING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'EXECUTING' | 'RESOLVED' | 'PENDING';

export interface Finding {
  finding_id: string;
  title: string;
  description: string;
  severity: {
    level: SeverityLevel;
    score: number;
  } | SeverityLevel;
  resource_id: string;
  resource_name?: string;
  resource_type: string;
  service: string;
  compliance_status: ComplianceStatus;
  recommendation?: {
    text?: string;
    url?: string;
    summary?: string;
    cli_command?: string;
    terraform_snippet?: string;
  } | string;
  frameworks?: string[];
  first_observed_at?: string;
}

export interface ApprovalItem {
  id: string;
  resource_id: string;
  resource_name: string;
  resource_arn?: string;
  resource_type: string;
  service: string;
  issue: string;
  recommendation: string;
  description?: string;
  severity: SeverityLevel;
  status: ApprovalStatus;
  cli_command?: string;
  terraform_snippet?: string;
  thread_id?: string;
  created_at?: string;
  operator_comment?: string;
}

export interface StreamEvent {
  event: string;
  step?: string;
  service?: string;
  message?: string;
  status?: string;
  progress?: number;
  count?: number;
  findings?: Finding[];
  approval_item?: ApprovalItem;
  item_id?: string;
  command?: string;
  thought?: string;
  node?: string;
  reasoning_trace?: Array<{ node: string; thought: string }>;
  timestamp: string;
}

export interface ActivityLogEntry {
  id: string;
  timestamp: string;
  step: string;
  message: string;
  service?: string;
  type: 'connected' | 'scan' | 'findings' | 'ai' | 'approval' | 'execution' | 'verification' | 'info';
  status?: string;
  raw?: any;
}

export interface ReasoningNodeTrace {
  id: string;
  node: 'Observation' | 'Reasoning' | 'RiskAssessment' | 'HumanApproval' | 'ExecuteRemediation' | 'VerifyFix' | 'Finish';
  thought: string;
  decision?: string;
  timestamp: string;
  status: 'completed' | 'in_progress' | 'paused' | 'pending';
}

export interface CloudResourceCard {
  id: string;
  name: string;
  arn: string;
  type: string;
  service: 'EC2' | 'IAM' | 'S3';
  status: 'COMPLIANT' | 'VULNERABLE' | 'NEEDS_ATTENTION';
  issue?: string;
  severity?: SeverityLevel;
  recommendation?: string;
  lastChecked: string;
}
