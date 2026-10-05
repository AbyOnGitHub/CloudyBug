import React from 'react';
import { 
  Terminal, 
  Sparkles, 
  BrainCircuit, 
  CheckCircle2, 
  PauseCircle, 
  Clock, 
  ArrowRight,
  ShieldCheck,
  Copy,
  Check
} from 'lucide-react';
import { ReasoningNodeTrace } from '../types/security';

interface ReasoningLogsProps {
  traces: ReasoningNodeTrace[];
}

export const ReasoningLogs: React.FC<ReasoningLogsProps> = ({ traces }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopyLogs = () => {
    const text = traces.map(t => `[${t.timestamp}] [${t.node}] (${t.status.toUpperCase()}): ${t.thought} -> Decision: ${t.decision}`).join('\n\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusBadge = (status: ReasoningNodeTrace['status']) => {
    switch (status) {
      case 'completed':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            COMPLETED
          </span>
        );
      case 'paused':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 animate-pulse">
            <PauseCircle className="w-3 h-3" />
            INTERRUPT PAUSED
          </span>
        );
      case 'in_progress':
        return (
          <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
            <Clock className="w-3 h-3 animate-spin" />
            EVALUATING
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            PENDING
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono text-purple-400 uppercase tracking-wider font-semibold">
              <BrainCircuit className="w-3.5 h-3.5" />
              <span>Cognitive Architecture • LangGraph State Machine</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight mt-1">
              AI Reasoning &amp; Execution Trace Logs
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Complete step-by-step audit log of agent observation, risk assessment, human approval interrupt, and remediation.
            </p>
          </div>

          <button
            onClick={handleCopyLogs}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Trace'}</span>
          </button>
        </div>

        {/* Visual Graph Pipeline */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 overflow-x-auto pb-2">
          <div className="flex items-center space-x-2 min-w-[700px]">
            {[
              { name: 'Observation', state: 'completed' },
              { name: 'Reasoning', state: 'completed' },
              { name: 'RiskAssessment', state: 'completed' },
              { name: 'HumanApproval', state: 'paused' },
              { name: 'ExecuteRemediation', state: 'pending' },
              { name: 'VerifyFix', state: 'pending' },
              { name: 'Finish', state: 'pending' },
            ].map((node, index, arr) => (
              <React.Fragment key={node.name}>
                <div
                  className={`px-3 py-2 rounded-xl border font-mono text-xs font-semibold flex items-center space-x-2 ${
                    node.state === 'completed'
                      ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
                      : node.state === 'paused'
                      ? 'bg-amber-500/15 border-amber-500/50 text-amber-300 shadow-md shadow-amber-500/10 animate-pulse'
                      : 'bg-slate-950/60 border-slate-800 text-slate-500'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-current" />
                  <span>{node.name}</span>
                </div>
                {index < arr.length - 1 && (
                  <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>

      {/* Trace Log Entries */}
      <div className="space-y-3 font-mono text-xs">
        {traces.map((trace, idx) => (
          <div
            key={trace.id || idx}
            className={`p-5 rounded-2xl bg-slate-900/90 border transition-all ${
              trace.status === 'paused'
                ? 'border-amber-500/40 bg-gradient-to-r from-amber-500/5 to-slate-900/90'
                : 'border-slate-800'
            }`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
              <div className="flex items-center space-x-2.5">
                <div className="p-1 rounded-md bg-slate-950 border border-slate-800">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                </div>
                <span className="font-bold text-slate-200 text-sm">
                  Node: {trace.node}
                </span>
                <span className="text-slate-500 text-[11px]">
                  {new Date(trace.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div>{getStatusBadge(trace.status)}</div>
            </div>

            <p className="text-slate-300 leading-relaxed text-xs pl-7">
              {trace.thought}
            </p>

            {trace.decision && (
              <div className="mt-3 pl-7 flex items-center space-x-2">
                <span className="text-slate-500 text-[11px]">Decision:</span>
                <span className="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 font-bold border border-slate-800 text-[11px]">
                  {trace.decision}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
