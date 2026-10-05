import React from 'react';
import { 
  LayoutDashboard, 
  Activity, 
  ShieldAlert, 
  UserCheck, 
  Network, 
  Terminal,
  ShieldCheck,
  Server
} from 'lucide-react';
import { NavigationTab } from '../types/security';

interface SidebarProps {
  currentTab: NavigationTab;
  onTabChange: (tab: NavigationTab) => void;
  pendingApprovalCount: number;
  isConnected: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  pendingApprovalCount,
  isConnected,
}) => {
  const navItems = [
    { id: 'dashboard' as NavigationTab, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'activity' as NavigationTab, label: 'Activity Stream', icon: Activity },
    { id: 'findings' as NavigationTab, label: 'Current Findings', icon: ShieldAlert },
    { 
      id: 'approval' as NavigationTab, 
      label: 'Approval Queue', 
      icon: UserCheck, 
      badge: pendingApprovalCount > 0 ? pendingApprovalCount : null 
    },
    { id: 'resources' as NavigationTab, label: 'Resource Map', icon: Network },
    { id: 'logs' as NavigationTab, label: 'Logs', icon: Terminal },
  ];

  return (
    <aside className="w-64 bg-slate-900/90 border-r border-slate-800/80 flex flex-col justify-between backdrop-blur-xl h-screen sticky top-0 select-none z-30">
      <div>
        {/* Brand / Logo Header */}
        <div className="h-16 px-5 border-b border-slate-800/80 flex items-center space-x-3 bg-slate-950/40">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
            <ShieldCheck className="w-5 h-5 text-slate-950 font-bold" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-slate-100 uppercase">
              Cloud Security
            </h1>
            <p className="text-[10px] text-cyan-400 font-mono tracking-tight flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              Autonomous Agent
            </p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1.5">
          <div className="px-3 pt-3 pb-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider font-mono">
            Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.badge !== null && item.badge !== undefined && (
                  <span className="px-2 py-0.5 text-xs font-mono font-bold rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer / Agent Runtime Status */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/30 space-y-3">
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-xs font-medium text-slate-300">LocalStack Target</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
              4566
            </span>
          </div>
          <div className="flex items-center space-x-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50 animate-pulse' : 'bg-rose-500'
              }`}
            />
            <span className="text-[11px] font-mono text-slate-300">
              {isConnected ? '[✓] Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between text-[11px] text-slate-400 px-1 font-mono">
          <span>Engine: Prowler+LangGraph</span>
          <span>v1.0.0</span>
        </div>
      </div>
    </aside>
  );
};
