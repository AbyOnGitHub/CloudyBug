import React, { useState } from 'react';
import { 
  CheckCircle2, 
  Search, 
  Terminal, 
  Cpu, 
  Sparkles, 
  Clock, 
  Radio, 
  Filter,
  ShieldAlert,
  RotateCw
} from 'lucide-react';
import { ActivityLogEntry } from '../types/security';

interface ActivityStreamProps {
  logs: ActivityLogEntry[];
  currentStep: string;
  isConnected: boolean;
  isScanning: boolean;
  onTriggerScan: () => void;
}

export const ActivityStream: React.FC<ActivityStreamProps> = ({
  logs,
  currentStep,
  isConnected,
  isScanning,
  onTriggerScan,
}) => {
  const [filterType, setFilterType] = useState<string>('all');

  const filteredLogs = logs.filter(log => {
    if (filterType === 'all') return true;
    if (filterType === 'scans') return log.type === 'scan' || log.type === 'connected';
    if (filterType === 'ai') return log.type === 'ai';
    if (filterType === 'approvals') return log.type === 'approval' || log.type === 'execution';
    return true;
  });

  const getStepIcon = (type: ActivityLogEntry['type']) => {
    switch (type) {
      case 'connected':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      case 'scan':
        return <Cpu className="w-4 h-4 text-cyan-400" />;
      case 'findings':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      case 'ai':
        return <Sparkles className="w-4 h-4 text-purple-400" />;
      case 'approval':
        return <Clock className="w-4 h-4 text-amber-400" />;
      case 'execution':
        return <RotateCw className="w-4 h-4 text-blue-400" />;
      default:
        return <Terminal className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Live Stream Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 shadow-xl backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
              <Radio className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
              <span>Real-Time NDJSON WebSocket Event Feed</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight mt-1">
              Autonomous Agent Activity Stream
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Live observability of security audits, LLM policy reasoning, and interrupt cycles.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 flex items-center space-x-2">
              <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span>{isConnected ? '[✓] Connected' : 'Disconnected'}</span>
            </div>
            <button
              onClick={onTriggerScan}
              disabled={isScanning}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-medium transition-colors"
            >
              {isScanning ? 'Streaming...' : 'Replay Stream'}
            </button>
          </div>
        </div>

        {/* Status Pipeline Chips representing prompt progression */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          {[
            { label: '[✓] Connected', active: isConnected, color: 'emerald' },
            { label: 'Scanning EC2...', active: currentStep.includes('EC2'), color: 'cyan' },
            { label: 'Checking IAM...', active: currentStep.includes('IAM'), color: 'cyan' },
            { label: 'Checking S3...', active: currentStep.includes('S3'), color: 'cyan' },
            { label: 'Found 5 issues', active: currentStep.includes('Found'), color: 'rose' },
            { label: 'AI analysing...', active: currentStep.includes('analysing'), color: 'purple' },
            { label: 'Waiting for Approval...', active: currentStep.includes('Approval'), color: 'amber' },
          ].map((chip) => (
            <div
              key={chip.label}
              className={`px-3 py-1 rounded-full text-xs font-mono font-medium border transition-all ${
                chip.active
                  ? chip.color === 'emerald'
                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 shadow-sm shadow-emerald-500/10'
                    : chip.color === 'amber'
                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/40 shadow-sm shadow-amber-500/10'
                    : chip.color === 'rose'
                    ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                    : chip.color === 'purple'
                    ? 'bg-purple-500/15 text-purple-300 border-purple-500/40'
                    : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                  : 'bg-slate-950/60 text-slate-500 border-slate-800/80'
              }`}
            >
              {chip.label}
            </div>
          ))}
        </div>
      </div>

      {/* Stream Controls and Terminal View */}
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/60 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200">NDJSON Stream Terminal</h3>
            <span className="text-xs font-mono text-slate-500">
              ({filteredLogs.length} events logged)
            </span>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center space-x-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-500 ml-1.5 mr-0.5" />
            {(['all', 'scans', 'ai', 'approvals'] as const).map((filter) => (
              <button
                key={filter}
                onClick={() => setFilterType(filter)}
                className={`px-2.5 py-1 rounded text-xs capitalize transition-colors ${
                  filterType === filter
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {filter}
              </button>
            ))}
          </div>
        </div>

        {/* Terminal Log Items */}
        <div className="divide-y divide-slate-800/60 max-h-[520px] overflow-y-auto font-mono text-xs">
          {filteredLogs.map((log) => (
            <div
              key={log.id}
              className="p-4 hover:bg-slate-850/50 transition-colors flex items-start space-x-3.5 group"
            >
              <div className="mt-0.5 p-1 rounded-md bg-slate-950 border border-slate-800 shrink-0">
                {getStepIcon(log.type)}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-500 text-[11px]">{log.timestamp}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${
                    log.type === 'connected'
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      : log.type === 'approval'
                      ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                      : log.type === 'findings'
                      ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                      : log.type === 'ai'
                      ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                      : 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                  }`}>
                    {log.step}
                  </span>
                  {log.service && (
                    <span className="text-[10px] text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                      {log.service}
                    </span>
                  )}
                </div>
                <p className="text-slate-200 text-xs mt-1 group-hover:text-slate-100 transition-colors">
                  {log.message}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
