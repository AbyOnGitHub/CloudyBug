import React from 'react';
import { 
  CheckCircle2, 
  AlertCircle, 
  RotateCw, 
  Radio, 
  Cpu, 
  ShieldAlert 
} from 'lucide-react';

interface HeaderProps {
  isConnected: boolean;
  currentStep: string;
  isScanning: boolean;
  onTriggerScan: () => void;
  pendingApprovalsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  isConnected,
  currentStep,
  isScanning,
  onTriggerScan,
  pendingApprovalsCount,
}) => {
  return (
    <header className="h-16 px-6 border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-xl flex items-center justify-between sticky top-0 z-20">
      {/* Left: Stream Progression & Status */}
      <div className="flex items-center space-x-4">
        {/* Connected Pill: [✓] Connected */}
        <div
          className={`flex items-center space-x-2 px-3 py-1.5 rounded-full text-xs font-mono font-medium transition-all ${
            isConnected
              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shadow-sm shadow-emerald-500/20'
              : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
          }`}
        >
          {isConnected ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-semibold tracking-wide">[✓] Connected</span>
            </>
          ) : (
            <>
              <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
              <span>Offline (Reconnecting...)</span>
            </>
          )}
        </div>

        {/* Dynamic Real-Time Agent Step */}
        <div className="flex items-center space-x-2.5 px-3 py-1.5 rounded-full bg-slate-800/60 border border-slate-700/60 text-xs font-mono text-slate-300">
          <Radio className={`w-3.5 h-3.5 ${isScanning ? 'text-amber-400 animate-spin' : 'text-cyan-400 animate-pulse'}`} />
          <span className="text-slate-400">Agent Stage:</span>
          <span className={`font-semibold ${
            currentStep.includes('Approval') 
              ? 'text-amber-400' 
              : currentStep.includes('Scanning') || currentStep.includes('Checking')
              ? 'text-cyan-400'
              : 'text-slate-200'
          }`}>
            {currentStep}
          </span>
        </div>

        {pendingApprovalsCount > 0 && (
          <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-amber-500/15 border border-amber-500/30 text-amber-300 text-xs font-mono">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>1 Pending Approval</span>
          </div>
        )}
      </div>

      {/* Right: Environment & Audit Trigger Button */}
      <div className="flex items-center space-x-3">
        <div className="hidden lg:flex items-center space-x-2 px-3 py-1 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-400">
          <Cpu className="w-3.5 h-3.5 text-slate-500" />
          <span>LocalStack 4566:us-east-1</span>
        </div>

        <button
          onClick={onTriggerScan}
          disabled={isScanning}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all duration-200 shadow-md ${
            isScanning
              ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold shadow-cyan-500/25 hover:shadow-cyan-500/40 active:scale-95'
          }`}
        >
          <RotateCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? 'Scanning...' : 'Trigger Security Audit'}</span>
        </button>
      </div>
    </header>
  );
};
