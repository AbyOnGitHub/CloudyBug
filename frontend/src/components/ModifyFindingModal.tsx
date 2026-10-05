import React, { useState } from 'react';
import { X, Sliders, Check, Terminal, Code2 } from 'lucide-react';
import { ApprovalItem } from '../types/security';

interface ModifyFindingModalProps {
  isOpen: boolean;
  item: ApprovalItem;
  onClose: () => void;
  onSave: (itemId: string, newCommand: string, newRecommendation: string) => void;
}

export const ModifyFindingModal: React.FC<ModifyFindingModalProps> = ({
  isOpen,
  item,
  onClose,
  onSave,
}) => {
  const [recommendation, setRecommendation] = useState<string>(
    item.recommendation || 'Restrict SSH to authorized bastion/VPN CIDRs only'
  );
  const [cidr, setCidr] = useState<string>('10.0.0.0/16');
  const [command, setCommand] = useState<string>(
    item.cli_command || `aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0`
  );

  if (!isOpen) return null;

  const handleCidrChange = (val: string) => {
    setCidr(val);
    setCommand(
      `aws ec2 revoke-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr 0.0.0.0/0 && aws ec2 authorize-security-group-ingress --group-id sg-3423 --protocol tcp --port 22 --cidr ${val}`
    );
  };

  const handleSave = () => {
    onSave(item.id, command, recommendation);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in">
      <div className="w-full max-w-2xl bg-slate-900 border border-cyan-500/30 rounded-2xl shadow-2xl shadow-cyan-500/10 overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">
                Modify Remediation Action
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {item.resource_id} • {item.issue}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 font-mono mb-1.5">
              Recommendation Summary
            </label>
            <input
              type="text"
              value={recommendation}
              onChange={(e) => setRecommendation(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase text-slate-400 font-mono mb-1.5">
              Authorized Ingress CIDR Block
            </label>
            <div className="grid grid-cols-3 gap-2">
              {['10.0.0.0/16 (Corporate VPN)', '192.168.1.0/24 (Office Bastion)', '172.16.0.0/12 (VPC Internal)'].map((preset) => {
                const presetCidr = preset.split(' ')[0];
                return (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => handleCidrChange(presetCidr)}
                    className={`px-2.5 py-2 rounded-lg text-xs font-mono text-left border transition-all ${
                      cidr === presetCidr
                        ? 'bg-cyan-500/20 border-cyan-500 text-cyan-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {preset}
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-semibold uppercase text-slate-400 font-mono flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Custom Remediation Command (AWS CLI)
              </label>
            </div>
            <textarea
              rows={4}
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-start space-x-2 text-xs text-slate-400">
            <Code2 className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
            <span>
              Modifications are saved to the LangGraph checkpoint state and will be executed when approved.
            </span>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 flex items-center justify-end space-x-3 bg-slate-950/50">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all shadow-md shadow-cyan-500/20"
          >
            <Check className="w-3.5 h-3.5" />
            <span>Apply Modification</span>
          </button>
        </div>
      </div>
    </div>
  );
};
