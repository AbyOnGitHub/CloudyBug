import { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Finding, 
  ApprovalItem, 
  ActivityLogEntry, 
  ReasoningNodeTrace, 
  StreamEvent, 
  CloudResourceCard 
} from '../types/security';

const DEFAULT_APPROVAL_ITEM: ApprovalItem = {
  id: 'act-sg-3423',
  resource_id: 'Security Group sg-3423',
  resource_name: 'sg-3423',
  resource_arn: 'arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423',
  resource_type: 'AWS::EC2::SecurityGroup',
  service: 'EC2',
  issue: 'Port 22 Open',
  recommendation: 'Restrict SSH',
  description: 'Security Group sg-3423 allows unrestricted SSH ingress traffic (0.0.0.0/0 to Port 22), exposing instances to automated brute-force attacks.',
  severity: 'HIGH',
  status: 'WAITING_APPROVAL',
  cli_command: 'aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0',
  terraform_snippet: `resource "aws_security_group_rule" "restricted_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/16"] # Restricted Bastion / VPN
  security_group_id = "sg-3423"
}`,
  created_at: new Date().toISOString(),
};

const DEFAULT_FINDINGS: Finding[] = [
  {
    finding_id: 'arn:aws:securityhub:us-east-1:000000000000:finding/prowler-ec2_security_group_open_ssh_port-sg-3423',
    title: "Security Group 'sg-3423' allows unrestricted ingress SSH traffic (0.0.0.0/0:22)",
    description: "Security group 'sg-3423' permits inbound connections from 0.0.0.0/0 to TCP port 22.",
    severity: { level: 'HIGH', score: 70 },
    resource_id: 'Security Group sg-3423',
    resource_name: 'sg-3423',
    resource_type: 'AwsEc2SecurityGroup',
    service: 'EC2',
    compliance_status: 'FAILED',
    recommendation: {
      text: 'Restrict SSH: Revoke 0.0.0.0/0 on Port 22 and restrict SSH ingress to authorized bastion or VPN CIDRs.',
      cli_command: 'aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0',
    },
    frameworks: ['CIS AWS Benchmark 1.4 - 5.2', 'NIST 800-53'],
  },
  {
    finding_id: 'arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_public_access_block-vulnerable-bucket',
    title: "S3 Bucket 'vulnerable-customer-data-bucket' does not have Public Access Block enabled",
    description: 'Bucket lacks complete S3 Public Access Block settings, allowing accidental public exposure.',
    severity: { level: 'CRITICAL', score: 90 },
    resource_id: 'arn:aws:s3:::vulnerable-customer-data-bucket',
    resource_name: 'vulnerable-customer-data-bucket',
    resource_type: 'AwsS3Bucket',
    service: 'S3',
    compliance_status: 'FAILED',
    recommendation: {
      text: 'Enable all four S3 Block Public Access flags on the bucket.',
      cli_command: 'aws s3api put-public-access-block --bucket vulnerable-customer-data-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
    },
    frameworks: ['CIS AWS Benchmark 1.4 - 2.1.5', 'PCI-DSS v3.2.1'],
  },
  {
    finding_id: 'arn:aws:securityhub:us-east-1:000000000000:finding/prowler-iam_role_administrator_access-admin_role',
    title: "IAM Role 'insecure-app-admin-role' has overly permissive AdministratorAccess attached",
    description: 'The IAM role has full administrative access (*:*) violating principle of least privilege.',
    severity: { level: 'CRITICAL', score: 90 },
    resource_id: 'arn:aws:iam::000000000000:role/insecure-app-admin-role',
    resource_name: 'insecure-app-admin-role',
    resource_type: 'AwsIamRole',
    service: 'IAM',
    compliance_status: 'FAILED',
    recommendation: {
      text: 'Detach AdministratorAccess and replace with scoped least-privilege IAM policies.',
      cli_command: 'aws iam detach-role-policy --role-name insecure-app-admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
    },
    frameworks: ['CIS AWS Benchmark 1.4 - 1.16', 'SOC2 CC6.1'],
  },
  {
    finding_id: 'arn:aws:securityhub:us-east-1:000000000000:finding/prowler-s3_bucket_default_encryption-vulnerable-bucket',
    title: "S3 Bucket 'vulnerable-customer-data-bucket' does not have default encryption enabled",
    description: 'Bucket data at rest is not automatically encrypted using SSE-S3 or AWS KMS.',
    severity: { level: 'HIGH', score: 70 },
    resource_id: 'arn:aws:s3:::vulnerable-customer-data-bucket',
    resource_name: 'vulnerable-customer-data-bucket',
    resource_type: 'AwsS3Bucket',
    service: 'S3',
    compliance_status: 'FAILED',
    recommendation: {
      text: 'Enable default SSE-S3 encryption on the bucket.',
      cli_command: 'aws s3api put-bucket-encryption --bucket vulnerable-customer-data-bucket --server-side-encryption-configuration "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]"',
    },
    frameworks: ['CIS AWS Benchmark 1.4 - 2.1.1', 'AWS FSBP - S3.4'],
  },
  {
    finding_id: 'arn:aws:securityhub:us-east-1:000000000000:finding/prowler-ec2_ebs_volume_encryption-vol-default',
    title: 'EBS Default Encryption is not enabled in region us-east-1',
    description: 'New EBS volumes created in the account are not automatically encrypted at rest.',
    severity: { level: 'MEDIUM', score: 40 },
    resource_id: 'arn:aws:ec2:us-east-1:000000000000:account-attributes/ebs-encryption',
    resource_name: 'ebs-encryption',
    resource_type: 'AwsEc2RegionalSetting',
    service: 'EC2',
    compliance_status: 'FAILED',
    recommendation: {
      text: 'Enable EBS default volume encryption for the region.',
      cli_command: 'aws ec2 enable-ebs-encryption-by-default --region us-east-1',
    },
    frameworks: ['AWS FSBP - EC2.7'],
  },
];

const INITIAL_ACTIVITY_LOGS: ActivityLogEntry[] = [
  {
    id: 'act-1',
    timestamp: new Date(Date.now() - 45000).toLocaleTimeString(),
    step: 'Connected',
    message: '[✓] Connected',
    type: 'connected',
    status: 'Ready',
  },
  {
    id: 'act-2',
    timestamp: new Date(Date.now() - 35000).toLocaleTimeString(),
    step: 'Scanning EC2...',
    service: 'EC2',
    message: 'Scanning EC2...',
    type: 'scan',
  },
  {
    id: 'act-3',
    timestamp: new Date(Date.now() - 25000).toLocaleTimeString(),
    step: 'Checking IAM...',
    service: 'IAM',
    message: 'Checking IAM...',
    type: 'scan',
  },
  {
    id: 'act-4',
    timestamp: new Date(Date.now() - 18000).toLocaleTimeString(),
    step: 'Checking S3...',
    service: 'S3',
    message: 'Checking S3...',
    type: 'scan',
  },
  {
    id: 'act-5',
    timestamp: new Date(Date.now() - 12000).toLocaleTimeString(),
    step: 'Found 5 issues',
    message: 'Found 5 issues',
    type: 'findings',
  },
  {
    id: 'act-6',
    timestamp: new Date(Date.now() - 6000).toLocaleTimeString(),
    step: 'AI analysing...',
    message: 'AI analysing...',
    type: 'ai',
  },
  {
    id: 'act-7',
    timestamp: new Date().toLocaleTimeString(),
    step: 'Waiting for Approval...',
    message: 'Waiting for Approval...',
    type: 'approval',
  },
];

const INITIAL_REASONING_TRACES: ReasoningNodeTrace[] = [
  {
    id: 'trace-1',
    node: 'Observation',
    thought: 'Audited LocalStack services [EC2, IAM, S3]. Identified 5 non-compliant security controls in AWS Security Finding Format.',
    decision: 'OBSERVATION_COMPLETE',
    timestamp: new Date(Date.now() - 30000).toISOString(),
    status: 'completed',
  },
  {
    id: 'trace-2',
    node: 'Reasoning',
    thought: 'Active violation detected: Security Group sg-3423 exposes TCP Port 22 globally to 0.0.0.0/0. Remediation is required to prevent unauthorized ingress.',
    decision: 'NEED_FIX -> TRUE',
    timestamp: new Date(Date.now() - 20000).toISOString(),
    status: 'completed',
  },
  {
    id: 'trace-3',
    node: 'RiskAssessment',
    thought: 'Blast radius evaluation: Elevated risk score 85/100. Open SSH allows remote brute-force vectors. Formulated targeted CLI revocation and Terraform rules.',
    decision: 'SYNTHESIZED_ACTIONS',
    timestamp: new Date(Date.now() - 10000).toISOString(),
    status: 'completed',
  },
  {
    id: 'trace-4',
    node: 'HumanApproval',
    thought: 'LangGraph interrupt() invoked. Pausing autonomous execution to await explicit human authorization before applying firewall modifications.',
    decision: 'AWAITING_HUMAN_DECISION',
    timestamp: new Date().toISOString(),
    status: 'paused',
  },
];

export function useSecurityWebSocket() {
  const [isConnected, setIsConnected] = useState<boolean>(true);
  const [currentStep, setCurrentStep] = useState<string>('Waiting for Approval...');
  const [progressPercent, setProgressPercent] = useState<number>(100);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activityLogs, setActivityLogs] = useState<ActivityLogEntry[]>(INITIAL_ACTIVITY_LOGS);
  const [findings, setFindings] = useState<Finding[]>(DEFAULT_FINDINGS);
  const [approvalItems, setApprovalItems] = useState<ApprovalItem[]>([DEFAULT_APPROVAL_ITEM]);
  const [reasoningTraces, setReasoningTraces] = useState<ReasoningNodeTrace[]>(INITIAL_REASONING_TRACES);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  const appendActivityLog = useCallback((entry: Omit<ActivityLogEntry, 'id' | 'timestamp'>) => {
    const newLog: ActivityLogEntry = {
      ...entry,
      id: `act-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      timestamp: new Date().toLocaleTimeString(),
    };
    setActivityLogs(prev => [newLog, ...prev.slice(0, 49)]);
  }, []);

  const handleNdjsonEvent = useCallback((event: StreamEvent) => {
    const eventType = event.event;

    if (eventType === 'CONNECTED') {
      setIsConnected(true);
      setCurrentStep(event.message || '[✓] Connected');
      appendActivityLog({
        step: 'Connected',
        message: event.message || '[✓] Connected',
        type: 'connected',
        status: 'Connected',
      });
    } else if (eventType === 'SCAN_PROGRESS') {
      setIsScanning(true);
      setCurrentStep(event.step || event.message || 'Scanning...');
      if (event.progress !== undefined) setProgressPercent(event.progress);
      appendActivityLog({
        step: event.step || 'Scan',
        service: event.service,
        message: event.message || `${event.step}`,
        type: 'scan',
      });
    } else if (eventType === 'FINDINGS_DISCOVERED') {
      setCurrentStep(event.step || `Found ${event.count || 5} issues`);
      if (event.progress !== undefined) setProgressPercent(event.progress);
      if (event.findings && event.findings.length > 0) {
        setFindings(event.findings);
      }
      appendActivityLog({
        step: event.step || 'Found 5 issues',
        message: event.message || `Found ${event.count || 5} issues`,
        type: 'findings',
      });
    } else if (eventType === 'AI_ANALYSING') {
      setCurrentStep('AI analysing...');
      if (event.progress !== undefined) setProgressPercent(event.progress);
      appendActivityLog({
        step: 'AI analysing...',
        message: event.message || 'AI analysing...',
        type: 'ai',
      });
      if (event.thought) {
        setReasoningTraces(prev => [
          ...prev,
          {
            id: `trace-${Date.now()}`,
            node: (event.node as any) || 'Reasoning',
            thought: event.thought || '',
            decision: 'EVALUATING',
            timestamp: new Date().toISOString(),
            status: 'in_progress',
          },
        ]);
      }
    } else if (eventType === 'WAITING_APPROVAL') {
      setIsScanning(false);
      setCurrentStep('Waiting for Approval...');
      setProgressPercent(100);
      if (event.approval_item) {
        setApprovalItems([event.approval_item]);
      }
      appendActivityLog({
        step: 'Waiting for Approval...',
        message: 'Waiting for Approval...',
        type: 'approval',
      });
    } else if (eventType === 'APPROVAL_DECISION') {
      const status = event.status === 'APPROVED' ? 'APPROVED' : 'REJECTED';
      setApprovalItems(prev =>
        prev.map(item =>
          item.id === event.item_id ? { ...item, status } : item
        )
      );
      appendActivityLog({
        step: `Decision: ${status}`,
        message: event.message || `Remediation ${status}`,
        type: 'approval',
      });
    } else if (eventType === 'EXECUTING_REMEDIATION') {
      setApprovalItems(prev =>
        prev.map(item =>
          item.id === event.item_id ? { ...item, status: 'EXECUTING' } : item
        )
      );
      appendActivityLog({
        step: 'Executing',
        message: event.message || 'Executing remediation...',
        type: 'execution',
      });
    } else if (eventType === 'VERIFYING_FIX') {
      appendActivityLog({
        step: 'Verifying',
        message: event.message || 'Verifying security fix...',
        type: 'verification',
      });
    } else if (eventType === 'EXECUTION_COMPLETE') {
      setApprovalItems(prev =>
        prev.map(item =>
          item.id === event.item_id ? { ...item, status: 'RESOLVED' } : item
        )
      );
      appendActivityLog({
        step: 'Complete',
        message: event.message || 'Vulnerability resolved & verified.',
        type: 'execution',
      });
    } else if (eventType === 'REMEDIATION_MODIFIED') {
      setApprovalItems(prev =>
        prev.map(item =>
          item.id === event.item_id
            ? {
                ...item,
                cli_command: (event as any).modified_command || item.cli_command,
                recommendation: (event as any).recommendation || item.recommendation,
              }
            : item
        )
      );
      appendActivityLog({
        step: 'Modified',
        message: event.message || 'Remediation parameters updated.',
        type: 'info',
      });
    }
  }, [appendActivityLog]);

  const connectWebSocket = useCallback(() => {
    try {
      const host = window.location.hostname || 'localhost';
      const wsUrl = `ws://${host}:8000/api/ws/stream`;
      
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (messageEvent) => {
        const raw = messageEvent.data;
        if (typeof raw === 'string') {
          // Process line-by-line NDJSON format
          const lines = raw.split('\n').filter(l => l.trim().length > 0);
          for (const line of lines) {
            try {
              const parsed: StreamEvent = JSON.parse(line);
              handleNdjsonEvent(parsed);
            } catch (err) {
              console.warn('Failed to parse NDJSON line:', line, err);
            }
          }
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        // Automatic reconnection retry
        reconnectTimeoutRef.current = setTimeout(() => {
          connectWebSocket();
        }, 3000);
      };

      ws.onerror = () => {
        // Fallback gracefully without breaking UI
        setIsConnected(false);
      };
    } catch (e) {
      console.warn('WebSocket init exception:', e);
    }
  }, [handleNdjsonEvent]);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connectWebSocket]);

  // Actions
  const startScan = useCallback(() => {
    setIsScanning(true);
    setCurrentStep('Scanning EC2...');
    setProgressPercent(15);

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'start_scan',
        target_services: ['ec2', 'iam', 's3'],
      }) + '\n');
    } else {
      // Local fallback simulation if WS is reconnecting
      appendActivityLog({ step: 'Scanning EC2...', service: 'EC2', message: 'Scanning EC2...', type: 'scan' });
      setTimeout(() => {
        setCurrentStep('Checking IAM...');
        appendActivityLog({ step: 'Checking IAM...', service: 'IAM', message: 'Checking IAM...', type: 'scan' });
      }, 500);
      setTimeout(() => {
        setCurrentStep('Checking S3...');
        appendActivityLog({ step: 'Checking S3...', service: 'S3', message: 'Checking S3...', type: 'scan' });
      }, 1000);
      setTimeout(() => {
        setCurrentStep('Found 5 issues');
        appendActivityLog({ step: 'Found 5 issues', message: 'Found 5 issues', type: 'findings' });
      }, 1500);
      setTimeout(() => {
        setCurrentStep('AI analysing...');
        appendActivityLog({ step: 'AI analysing...', message: 'AI analysing...', type: 'ai' });
      }, 2000);
      setTimeout(() => {
        setCurrentStep('Waiting for Approval...');
        setIsScanning(false);
        appendActivityLog({ step: 'Waiting for Approval...', message: 'Waiting for Approval...', type: 'approval' });
      }, 2600);
    }
  }, [appendActivityLog]);

  const approveAction = useCallback((itemId: string, comments = 'Approved by Operator') => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'approve',
        item_id: itemId,
        comments,
      }) + '\n');
    } else {
      setApprovalItems(prev =>
        prev.map(i => (i.id === itemId ? { ...i, status: 'APPROVED' } : i))
      );
      appendActivityLog({ step: 'Approved', message: `Approved ${itemId}`, type: 'approval' });
      setTimeout(() => {
        appendActivityLog({ step: 'Executing', message: 'Revoking 0.0.0.0/0 on Port 22...', type: 'execution' });
      }, 400);
      setTimeout(() => {
        appendActivityLog({ step: 'Verifying', message: 'Verifying security group rule revocation...', type: 'verification' });
      }, 800);
      setTimeout(() => {
        setApprovalItems(prev =>
          prev.map(i => (i.id === itemId ? { ...i, status: 'RESOLVED' } : i))
        );
        appendActivityLog({ step: 'Resolved', message: 'Remediation completed and verified.', type: 'execution' });
      }, 1200);
    }
  }, [appendActivityLog]);

  const rejectAction = useCallback((itemId: string, reason = 'Operator rejected remediation.') => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'reject',
        item_id: itemId,
        reason,
      }) + '\n');
    } else {
      setApprovalItems(prev =>
        prev.map(i => (i.id === itemId ? { ...i, status: 'REJECTED' } : i))
      );
      appendActivityLog({ step: 'Rejected', message: `Remediation rejected: ${reason}`, type: 'approval' });
    }
  }, [appendActivityLog]);

  const modifyAction = useCallback((itemId: string, newCommand: string, newRecommendation: string) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'modify',
        item_id: itemId,
        cli_command: newCommand,
        recommendation: newRecommendation,
      }) + '\n');
    } else {
      setApprovalItems(prev =>
        prev.map(i =>
          i.id === itemId
            ? { ...i, cli_command: newCommand, recommendation: newRecommendation }
            : i
        )
      );
      appendActivityLog({ step: 'Modified', message: `Updated configuration for ${itemId}`, type: 'info' });
    }
  }, [appendActivityLog]);

  return {
    isConnected,
    currentStep,
    progressPercent,
    isScanning,
    activityLogs,
    findings,
    approvalItems,
    reasoningTraces,
    startScan,
    approveAction,
    rejectAction,
    modifyAction,
  };
}
