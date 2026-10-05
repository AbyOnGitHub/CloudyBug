import React, { useState } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { HumanApprovalPanel } from './components/HumanApprovalPanel';
import { ActivityStream } from './components/ActivityStream';
import { VulnerabilityTable } from './components/VulnerabilityTable';
import { ResourceMap } from './components/ResourceMap';
import { ReasoningLogs } from './components/ReasoningLogs';
import { useSecurityWebSocket } from './hooks/useSecurityWebSocket';
import { NavigationTab } from './types/security';
import { 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  Cpu, 
  AlertTriangle,
  Flame,
  Activity,
  Layers
} from 'lucide-react';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('dashboard');

  const {
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
  } = useSecurityWebSocket();

  const pendingApprovals = approvalItems.filter(i => i.status === 'WAITING_APPROVAL');
  const failedFindingsCount = findings.filter(f => f.compliance_status === 'FAILED').length;

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100 cyber-grid">
      {/* 1. Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        pendingApprovalCount={pendingApprovals.length}
        isConnected={isConnected}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* 2. Top Header with [✓] Connected and Status */}
        <Header
          isConnected={isConnected}
          currentStep={currentStep}
          isScanning={isScanning}
          onTriggerScan={startScan}
          pendingApprovalsCount={pendingApprovals.length}
        />

        {/* Dynamic Route Content */}
        <main className="flex-1 p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-6">
          {/* TAB 1: DASHBOARD (Unified High-Density View) */}
          {currentTab === 'dashboard' && (
            <div className="space-y-6">
              {/* KPI Metrics Strip */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs font-mono font-semibold uppercase">Scan Targets</span>
                    <Cpu className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-black text-slate-100 mt-2">
                    {findings.length || 6} Controls
                  </div>
                  <div className="text-[11px] font-mono text-cyan-400 mt-1">
                    EC2, IAM, S3 LocalStack
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs font-mono font-semibold uppercase">Active Issues</span>
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  </div>
                  <div className="text-2xl font-black text-rose-400 mt-2">
                    {failedFindingsCount || 5} Issues
                  </div>
                  <div className="text-[11px] font-mono text-rose-300 mt-1 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    Found 5 issues across cloud
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs font-mono font-semibold uppercase">Pending Approval</span>
                    <Clock className="w-4 h-4 text-amber-400" />
                  </div>
                  <div className="text-2xl font-black text-amber-400 mt-2">
                    {pendingApprovals.length} Required
                  </div>
                  <div className="text-[11px] font-mono text-amber-300 mt-1">
                    Security Group sg-3423
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl">
                  <div className="flex items-center justify-between text-slate-400">
                    <span className="text-xs font-mono font-semibold uppercase">Composite Risk</span>
                    <Flame className="w-4 h-4 text-orange-400" />
                  </div>
                  <div className="text-2xl font-black text-orange-400 mt-2">
                    85 / 100
                  </div>
                  <div className="text-[11px] font-mono text-orange-300 mt-1">
                    Elevated Blast Radius
                  </div>
                </div>
              </div>

              {/* 3. Human Approval Panel (Highlighted First Class Citizen) */}
              <HumanApprovalPanel
                items={approvalItems}
                onApprove={approveAction}
                onReject={rejectAction}
                onModify={modifyAction}
              />

              {/* Grid: Activity Stream Snippet & Findings Table */}
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                <div className="xl:col-span-2 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyan-400" />
                      <span>Current Security Findings</span>
                    </h3>
                    <button
                      onClick={() => setCurrentTab('findings')}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      View All Findings →
                    </button>
                  </div>
                  <VulnerabilityTable findings={findings} />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-amber-400" />
                      <span>Live Activity Stream</span>
                    </h3>
                    <button
                      onClick={() => setCurrentTab('activity')}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      Full Stream →
                    </button>
                  </div>
                  <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 font-mono text-xs space-y-3 max-h-[500px] overflow-y-auto">
                    {activityLogs.slice(0, 10).map((log) => (
                      <div key={log.id} className="pb-2 border-b border-slate-800/60 last:border-0">
                        <div className="flex items-center justify-between text-[10px] text-slate-500">
                          <span>{log.timestamp}</span>
                          <span className="text-cyan-400 font-bold">{log.step}</span>
                        </div>
                        <p className="text-slate-300 text-xs mt-0.5">{log.message}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ACTIVITY STREAM */}
          {currentTab === 'activity' && (
            <ActivityStream
              logs={activityLogs}
              currentStep={currentStep}
              isConnected={isConnected}
              isScanning={isScanning}
              onTriggerScan={startScan}
            />
          )}

          {/* TAB 3: CURRENT FINDINGS */}
          {currentTab === 'findings' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-xl font-bold text-slate-100 tracking-tight">
                  Current Vulnerabilities &amp; Compliance Findings
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Normalized AWS Security Finding Format (ASFF) findings parsed for LLM reasoning.
                </p>
              </div>
              <VulnerabilityTable findings={findings} />
            </div>
          )}

          {/* TAB 4: APPROVAL QUEUE */}
          {currentTab === 'approval' && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-slate-100 tracking-tight">
                  Human Approval Queue
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Review, approve, reject, or modify proposed remediation actions before autonomous execution.
                </p>
              </div>
              <HumanApprovalPanel
                items={approvalItems}
                onApprove={approveAction}
                onReject={rejectAction}
                onModify={modifyAction}
              />
            </div>
          )}

          {/* TAB 5: RESOURCE MAP */}
          {currentTab === 'resources' && <ResourceMap />}

          {/* TAB 6: LOGS */}
          {currentTab === 'logs' && <ReasoningLogs traces={reasoningTraces} />}
        </main>
      </div>
    </div>
  );
};

export default App;
