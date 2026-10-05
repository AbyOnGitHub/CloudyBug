import React from 'react';
import { 
  Network, 
  Server, 
  HardDrive, 
  Key, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle,
  ExternalLink 
} from 'lucide-react';
import { CloudResourceCard } from '../types/security';

const CLOUD_RESOURCES: CloudResourceCard[] = [
  {
    id: 'res-ec2-sg',
    name: 'Security Group sg-3423',
    arn: 'arn:aws:ec2:us-east-1:000000000000:security-group/sg-3423',
    type: 'AWS::EC2::SecurityGroup',
    service: 'EC2',
    status: 'VULNERABLE',
    issue: 'Port 22 Open (0.0.0.0/0 to SSH)',
    severity: 'HIGH',
    recommendation: 'Restrict SSH ingress to authorized bastion CIDR.',
    lastChecked: 'Just now',
  },
  {
    id: 'res-s3-vuln',
    name: 'vulnerable-customer-data-bucket',
    arn: 'arn:aws:s3:::vulnerable-customer-data-bucket',
    type: 'AWS::S3::Bucket',
    service: 'S3',
    status: 'VULNERABLE',
    issue: 'Public Access Block Disabled & Unencrypted',
    severity: 'CRITICAL',
    recommendation: 'Enforce S3 Block Public Access and SSE-S3 encryption.',
    lastChecked: 'Just now',
  },
  {
    id: 'res-iam-admin',
    name: 'insecure-app-admin-role',
    arn: 'arn:aws:iam::000000000000:role/insecure-app-admin-role',
    type: 'AWS::IAM::Role',
    service: 'IAM',
    status: 'VULNERABLE',
    issue: 'Overly permissive AdministratorAccess (*:*)',
    severity: 'CRITICAL',
    recommendation: 'Scope policy to required microservice APIs only.',
    lastChecked: 'Just now',
  },
  {
    id: 'res-ec2-ebs',
    name: 'EBS Regional Encryption',
    arn: 'arn:aws:ec2:us-east-1:000000000000:account-attributes/ebs-encryption',
    type: 'AWS::EC2::RegionalSetting',
    service: 'EC2',
    status: 'NEEDS_ATTENTION',
    issue: 'Default EBS Encryption Disabled',
    severity: 'MEDIUM',
    recommendation: 'Enable default EBS encryption for us-east-1.',
    lastChecked: 'Just now',
  },
  {
    id: 'res-s3-secure',
    name: 'secure-encrypted-backup-bucket',
    arn: 'arn:aws:s3:::secure-encrypted-backup-bucket',
    type: 'AWS::S3::Bucket',
    service: 'S3',
    status: 'COMPLIANT',
    issue: 'None (Compliant)',
    recommendation: 'Maintain existing security posture.',
    lastChecked: 'Just now',
  },
];

export const ResourceMap: React.FC = () => {
  const getServiceIcon = (service: CloudResourceCard['service']) => {
    switch (service) {
      case 'EC2':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'S3':
        return <HardDrive className="w-4 h-4 text-emerald-400" />;
      case 'IAM':
        return <Key className="w-4 h-4 text-amber-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Topology Overview */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
              <Network className="w-3.5 h-3.5" />
              <span>Target Cloud Infrastructure Topology</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight mt-1">
              Resource Compliance Map
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Visual inventory of scanned cloud resources, blast radius exposure, and compliance status.
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-500/15 text-rose-300 border border-rose-500/30">
              <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse" />
              3 Non-Compliant
            </span>
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              1 Compliant
            </span>
          </div>
        </div>

        {/* Cloud Service Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-200">Amazon EC2</span>
              </div>
              <span className="text-xs font-mono text-rose-400">1 Critical Ingress</span>
            </div>
            <div className="text-xl font-extrabold text-slate-100 mt-2">2 Resources</div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono">sg-3423, ebs-encryption</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <HardDrive className="w-4 h-4 text-emerald-400" />
                <span className="text-xs font-bold text-slate-200">Amazon S3</span>
              </div>
              <span className="text-xs font-mono text-rose-400">1 Public Bucket</span>
            </div>
            <div className="text-xl font-extrabold text-slate-100 mt-2">2 Buckets</div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono">customer-data, backup-bucket</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Key className="w-4 h-4 text-amber-400" />
                <span className="text-xs font-bold text-slate-200">AWS IAM</span>
              </div>
              <span className="text-xs font-mono text-rose-400">1 Wildcard Policy</span>
            </div>
            <div className="text-xl font-extrabold text-slate-100 mt-2">1 Role</div>
            <div className="text-[11px] text-slate-400 mt-1 font-mono">insecure-app-admin-role</div>
          </div>
        </div>
      </div>

      {/* Grid of Resource Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {CLOUD_RESOURCES.map((res) => {
          const isVulnerable = res.status === 'VULNERABLE';
          const isCompliant = res.status === 'COMPLIANT';
          const isSpecial = res.name.includes('sg-3423');

          return (
            <div
              key={res.id}
              className={`p-5 rounded-2xl bg-slate-900/90 border transition-all duration-200 flex flex-col justify-between ${
                isSpecial
                  ? 'border-amber-500/40 ring-1 ring-amber-500/20 bg-gradient-to-b from-amber-500/5 to-slate-900/90 shadow-lg shadow-amber-500/5'
                  : isVulnerable
                  ? 'border-rose-500/30 hover:border-rose-500/50'
                  : isCompliant
                  ? 'border-emerald-500/30 hover:border-emerald-500/50'
                  : 'border-slate-800'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <div className="p-1.5 rounded-lg bg-slate-950 border border-slate-800">
                      {getServiceIcon(res.service)}
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">{res.type}</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                      isCompliant
                        ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                    }`}
                  >
                    {res.status}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
                  {isSpecial && <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />}
                  <span>{res.name}</span>
                </h3>

                <p className="text-[11px] font-mono text-slate-400 truncate mt-1">
                  {res.arn}
                </p>

                <div className="mt-4 p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-amber-300">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>{res.issue}</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {res.recommendation}
                  </p>
                </div>
              </div>

              <div className="pt-4 mt-4 border-t border-slate-800/70 flex items-center justify-between text-[11px] font-mono text-slate-500">
                <span>Audited: {res.lastChecked}</span>
                <span className="text-cyan-400 hover:text-cyan-300 cursor-pointer flex items-center gap-1">
                  Inspect <ExternalLink className="w-3 h-3" />
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
