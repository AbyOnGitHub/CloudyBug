import React, { useState } from 'react';
import { 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  Edit3, 
  Terminal, 
  Code2, 
  Clock, 
  AlertTriangle,
  RotateCw,
  Sparkles,
  ArrowRight
} from 'lucide-react';
import { ApprovalItem } from '../types/security';
import { ModifyFindingModal } from './ModifyFindingModal';

interface HumanApprovalPanelProps {
  items: ApprovalItem[];
  onApprove: (itemId: string, comment?: string) => void;
  onReject: (itemId: string, reason?: string) => void;
  onModify: (itemId: string, newCommand: string, newRecommendation: string) => void;
}

export const HumanApprovalPanel: React.FC<HumanApprovalPanelProps> = ({
  items,
  onApprove,
  onReject,
  onModify,
}) => {
  const [selectedItemForEdit, setSelectedItemForEdit] = useState<ApprovalItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Focus primarily on sg-3423 or first pending item
  const displayItem = items.find(i => i.resource_id.includes('sg-3423')) || items[0];

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (!displayItem) {
    return (
      <div className="p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center">
        <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-100">No Pending Approvals</h3>
        <p className="text-xs text-slate-400 mt-1">
          Autonomous Security Assistant has no actions awaiting human authorization.
        </p>
      </div>
    );
  }

  const isPending = displayItem.status === 'WAITING_APPROVAL';
  const isExecuting = displayItem.status === 'EXECUTING';
  const isResolved = displayItem.status === 'RESOLVED';
  const isRejected = displayItem.status === 'REJECTED';

  return (
    <div className="relative rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950/90 border border-amber-500/30 p-6 shadow-xl shadow-amber-500/5 backdrop-blur-xl overflow-hidden">
      {/* Top Ambient Glow Line */}
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-500 via-cyan-500 to-amber-500 opacity-80" />

      {/* Header with Stage Indicator: Waiting for Approval... */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/30 shadow-sm shadow-amber-500/20">
            <ShieldAlert className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-[11px] font-mono uppercase tracking-widest font-bold text-amber-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" />
                Waiting for Approval...
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                {displayItem.severity}
              </span>
            </div>
            <h2 className="text-xl font-extrabold text-slate-100 tracking-tight mt-0.5">
              Human-in-the-Loop Decision Gateway
            </h2>
          </div>
        </div>

        {/* Current State Pill */}
        <div className="flex items-center space-x-2">
          {isPending && (
            <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-amber-500/15 border border-amber-500/40 text-amber-300 text-xs font-mono font-semibold animate-pulse">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span>LangGraph Paused</span>
            </span>
          )}
          {isExecuting && (
            <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold">
              <RotateCw className="w-3 h-3 animate-spin text-cyan-400" />
              <span>Applying Fix...</span>
            </span>
          )}
          {isResolved && (
            <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-semibold">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>Resolved & Verified</span>
            </span>
          )}
          {isRejected && (
            <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 text-rose-300 text-xs font-mono font-semibold">
              <XCircle className="w-3.5 h-3.5 text-rose-400" />
              <span>Remediation Rejected</span>
            </span>
          )}
        </div>
      </div>

      {/* Main Decision Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 my-6">
        {/* Left Column: Targeted Resource & Issue */}
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-1">
              Target Cloud Resource
            </span>
            <div className="text-base font-bold text-slate-100 flex items-center space-x-2">
              <span className="text-cyan-400">Security Group</span>
              <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-mono text-xs border border-cyan-500/30">
                sg-3423
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1 break-all">
              arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-1">
              Issue Detected
            </span>
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              <span className="text-sm font-bold text-amber-300">
                Port 22 Open
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Inbound security rule permits 0.0.0.0/0 directly to port 22, allowing unrestricted public internet SSH access.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-1">
              Recommendation
            </span>
            <div className="flex items-center space-x-2">
              <Sparkles className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-sm font-bold text-cyan-300">
                Restrict SSH
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {displayItem.recommendation}
            </p>
          </div>
        </div>

        {/* Right Column: Code & Remediation Preview */}
        <div className="lg:col-span-2 space-y-4">
          {/* CLI Command Box */}
          <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-xs font-mono font-semibold text-slate-300">
                  Targeted AWS CLI Remediation Command
                </span>
              </div>
              <button
                onClick={() => handleCopy(displayItem.cli_command || '', 'cli')}
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                {copiedId === 'cli' ? 'Copied!' : 'Copy Command'}
              </button>
            </div>
            <div className="p-4 font-mono text-xs text-cyan-300 overflow-x-auto selection:bg-cyan-500 selection:text-slate-950">
              <code>{displayItem.cli_command}</code>
            </div>
          </div>

          {/* Terraform Snippet Box */}
          {displayItem.terraform_snippet && (
            <div className="rounded-xl bg-slate-950 border border-slate-800 overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Code2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-xs font-mono font-semibold text-slate-300">
                    Infrastructure-as-Code (Terraform Patch)
                  </span>
                </div>
                <button
                  onClick={() => handleCopy(displayItem.terraform_snippet || '', 'tf')}
                  className="text-[11px] font-mono text-emerald-400 hover:text-emerald-300 transition-colors"
                >
                  {copiedId === 'tf' ? 'Copied!' : 'Copy HCL'}
                </button>
              </div>
              <pre className="p-4 font-mono text-xs text-slate-300 overflow-x-auto">
                <code>{displayItem.terraform_snippet}</code>
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Human Actions Bar: Approve, Reject, Modify */}
      <div className="pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-2 text-xs text-slate-400 font-mono">
          <span>Action Required:</span>
          <span className="text-slate-200">
            {isPending ? 'Operator authorization needed to proceed.' : `State: ${displayItem.status}`}
          </span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Modify Button */}
          <button
            onClick={() => setSelectedItemForEdit(displayItem)}
            disabled={!isPending}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              isPending
                ? 'bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-500/40 hover:border-amber-500 shadow-sm hover:shadow-amber-500/10'
                : 'bg-slate-800/40 text-slate-500 border border-slate-800 cursor-not-allowed'
            }`}
          >
            <Edit3 className="w-3.5 h-3.5 text-amber-400" />
            <span>Modify</span>
          </button>

          {/* Reject Button */}
          <button
            onClick={() => onReject(displayItem.id, 'Risk accepted by SecOps')}
            disabled={!isPending}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              isPending
                ? 'bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/40 hover:border-rose-500'
                : 'bg-slate-800/40 text-slate-500 border border-slate-800 cursor-not-allowed'
            }`}
          >
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            <span>Reject</span>
          </button>

          {/* Approve Button */}
          <button
            onClick={() => onApprove(displayItem.id, 'Approved for immediate execution')}
            disabled={!isPending}
            className={`flex items-center space-x-2 px-5 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              isPending
                ? 'bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40 active:scale-95'
                : 'bg-slate-800/40 text-slate-500 border border-slate-800 cursor-not-allowed'
            }`}
          >
            <CheckCircle className="w-4 h-4 text-slate-950 font-bold" />
            <span>Approve</span>
          </button>
        </div>
      </div>

      {/* Edit/Modify Modal */}
      {selectedItemForEdit && (
        <ModifyFindingModal
          isOpen={Boolean(selectedItemForEdit)}
          item={selectedItemForEdit}
          onClose={() => setSelectedItemForEdit(null)}
          onSave={onModify}
        />
      )}
    </div>
  );
};
