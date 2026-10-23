import React, { useState, useEffect } from 'react';
import { 
  Flame, 
  ShieldAlert, 
  ShieldCheck, 
  Play, 
  RefreshCw, 
  Trash2, 
  Terminal, 
  Crosshair, 
  CheckCircle2, 
  AlertTriangle,
  Zap,
  ArrowRight,
  Lock,
  Server,
  Database,
  Key
} from 'lucide-react';

interface ActiveAttack {
  attack_id: string;
  attack_type: string;
  attacker_ip: string;
  target_resource_id: string;
  target_resource_name: string;
  target_check_id: string;
  mitre_attack_id: string;
  mitre_technique: string;
  raw_payload: string;
  simulated_logs: string[];
  status: string;
  title: string;
  timestamp: string;
  prevention_proof?: string;
  prevented_at?: string;
}

interface ProbeResult {
  attack_type: string;
  target_resource: string;
  prevented: boolean;
  status: string;
  message: string;
  raw_details: Record<string, any>;
  timestamp: string;
}

export const AttackSimulationPanel: React.FC = () => {
  const [activeAttacks, setActiveAttacks] = useState<ActiveAttack[]>([]);
  const [selectedAttackType, setSelectedAttackType] = useState<string>('SSH_BRUTE_FORCE');
  const [attackerIp, setAttackerIp] = useState<string>('198.51.100.42');
  const [loading, setLoading] = useState<boolean>(false);
  const [triageLoading, setTriageLoading] = useState<boolean>(false);
  const [probeResult, setProbeResult] = useState<ProbeResult | null>(null);
  const [triageReport, setTriageReport] = useState<any | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const attackVectors = [
    {
      id: 'SSH_BRUTE_FORCE',
      name: 'SSH Brute-Force Password Spraying',
      icon: Terminal,
      service: 'EC2',
      mitre: 'T1110.001',
      target: 'sg-3423 (insecure-ssh-sg)',
      desc: 'High-frequency dictionary password attempts targeting unrestricted 0.0.0.0/0 port 22 ingress rule.',
      exploitVuln: 'prowler-ec2_security_group_open_ssh_port',
      remediation: 'Revoke 0.0.0.0/0 ingress on port 22',
      color: 'from-amber-500/20 to-rose-500/20 border-rose-500/40 text-rose-300'
    },
    {
      id: 'S3_DATA_EXFILTRATION',
      name: 'Unauthenticated S3 Data Exfiltration',
      icon: Database,
      service: 'S3',
      mitre: 'T1530',
      target: 'vulnerable-customer-data-bucket',
      desc: 'Anonymous attacker exfiltrating customer records CSV from public unencrypted S3 bucket.',
      exploitVuln: 'prowler-s3_bucket_public_access_block',
      remediation: 'Enable S3 Block Public Access & AES-256 SSE',
      color: 'from-cyan-500/20 to-blue-500/20 border-cyan-500/40 text-cyan-300'
    },
    {
      id: 'IAM_PRIVILEGE_ESCALATION',
      name: 'IAM AdministratorAccess Abuse',
      icon: Key,
      service: 'IAM',
      mitre: 'T1078.004',
      target: 'insecure-app-admin-role',
      desc: 'Attacker assumes compromised role with AdministratorAccess wildcard policy to gain full cloud takeover.',
      exploitVuln: 'prowler-iam_role_administrator_access',
      remediation: 'Detach AdministratorAccess and enforce least-privilege',
      color: 'from-purple-500/20 to-pink-500/20 border-purple-500/40 text-purple-300'
    },
    {
      id: 'IMDS_CREDENTIAL_THEFT',
      name: 'IMDSv1 SSRF Credential Theft',
      icon: Server,
      service: 'EC2',
      mitre: 'T1552.005',
      target: 'insecure-web-instance',
      desc: 'SSRF probe to 169.254.169.254 to harvest temporary STS credentials from instance metadata.',
      exploitVuln: 'ec2_security_group_open_ssh_port',
      remediation: 'Enforce IMDSv2 token requirement & lock down SG',
      color: 'from-orange-500/20 to-red-500/20 border-orange-500/40 text-orange-300'
    }
  ];

  const fetchActiveAttacks = async () => {
    try {
      const res = await fetch('/api/attack/active');
      if (res.ok) {
        const data = await res.json();
        setActiveAttacks(data.active_attacks || []);
      }
    } catch (err) {
      console.warn('Failed to fetch active attacks:', err);
    }
  };

  useEffect(() => {
    fetchActiveAttacks();
    const interval = setInterval(fetchActiveAttacks, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateAttack = async () => {
    setLoading(true);
    setStatusMessage('Simulating adversary attack injection...');
    try {
      const res = await fetch('/api/attack/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_type: selectedAttackType,
          attacker_ip: attackerIp,
        })
      });
      if (res.ok) {
        const data = await res.json();
        setStatusMessage(`🚨 Attack Simulated: ${data.attack.title}`);
        await fetchActiveAttacks();
        setProbeResult(null);
      } else {
        setStatusMessage('Error launching simulated attack.');
      }
    } catch (e: any) {
      setStatusMessage(`Simulation error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleProbeVector = async (attackType?: string) => {
    const targetType = attackType || selectedAttackType;
    setLoading(true);
    setStatusMessage(`Probing attack vector: ${targetType}...`);
    try {
      const res = await fetch('/api/attack/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: targetType })
      });
      if (res.ok) {
        const data = await res.json();
        setProbeResult(data.probe);
        setStatusMessage(
          data.probe.prevented 
            ? `🛡️ Attack Vector BLOCKED & PREVENTED!` 
            : `⚠️ Attack Vector EXPLOITABLE! Vulnerability is active.`
        );
      }
    } catch (e: any) {
      setStatusMessage(`Probe error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClearAttacks = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/attack/clear', { method: 'POST' });
      if (res.ok) {
        setActiveAttacks([]);
        setProbeResult(null);
        setTriageReport(null);
        setStatusMessage('All active simulated attacks cleared.');
      }
    } catch (e: any) {
      setStatusMessage(`Clear error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClosedLoopTriage = async () => {
    setTriageLoading(true);
    setStatusMessage('Executing Closed-Loop Autonomous Triage (Detect -> Correlate -> Fix -> Prevent)...');
    try {
      const res = await fetch('/api/assistant/attack-triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_type: selectedAttackType,
          attacker_ip: attackerIp,
        })
      });
      if (res.ok) {
        const data = await res.json();
        setTriageReport(data);
        setStatusMessage(`🛡️ Closed-Loop Defense Complete: Attack ${data.attack_prevented ? 'PREVENTED & BLOCKED' : 'PROCESSED'}`);
        await fetchActiveAttacks();
        if (data.prevention_results && data.prevention_results.length > 0) {
          const p = data.prevention_results[0];
          setProbeResult({
            attack_type: p.attack_type,
            target_resource: p.target_resource,
            prevented: p.prevented,
            status: p.status,
            message: p.proof,
            raw_details: {},
            timestamp: p.verified_at,
          });
        }
      } else {
        setStatusMessage('Closed-loop triage returned an error.');
      }
    } catch (e: any) {
      setStatusMessage(`Triage error: ${e.message}`);
    } finally {
      setTriageLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-rose-950/40 via-slate-900 to-cyan-950/30 border border-rose-500/30 backdrop-blur-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1.5 animate-pulse">
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                SIMULATED ATTACK & DEFENSE ENVIRONMENT
              </span>
              <span className="text-xs font-mono text-slate-400">LocalStack AWS Sandbox</span>
            </div>
            <h2 className="text-2xl font-black text-slate-100 tracking-tight">
              Adversary Attack Simulation & Live Prevention Engine
            </h2>
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              Inject realistic adversary attacks against simulated cloud infrastructure, monitor the security crawler's real-time detection and vulnerability exploit correlation, execute automated defensive remediation, and verify attack vector neutralization.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={fetchActiveAttacks}
              disabled={loading}
              className="p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-all"
              title="Refresh Attack Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={handleClearAttacks}
              disabled={loading}
              className="px-3.5 py-2.5 rounded-xl bg-slate-800/80 hover:bg-rose-950/60 text-rose-300 border border-slate-700 hover:border-rose-500/40 text-xs font-mono font-semibold transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Clear Attacks
            </button>
          </div>
        </div>

        {statusMessage && (
          <div className="mt-4 p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-cyan-300 flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span>{statusMessage}</span>
          </div>
        )}
      </div>

      {/* 2. Attack Vectors Selector Grid */}
      <div className="space-y-3">
        <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
          Step 1: Select Adversary Attack Vector
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {attackVectors.map((atk) => {
            const Icon = atk.icon;
            const isSelected = selectedAttackType === atk.id;
            return (
              <div
                key={atk.id}
                onClick={() => setSelectedAttackType(atk.id)}
                className={`p-4 rounded-xl cursor-pointer border transition-all duration-200 relative overflow-hidden ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-400 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-400/40'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/90'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className={`p-2 rounded-lg bg-slate-800 border border-slate-700`}>
                    <Icon className="w-4 h-4 text-cyan-400" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {atk.mitre}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">{atk.name}</h4>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">{atk.desc}</p>
                <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                  <span className="text-slate-400">Target:</span>
                  <span className="text-cyan-300 font-semibold truncate max-w-[140px]">{atk.target}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Attack Controls & Execution Bar */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl space-y-4">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
          <div className="flex-1 flex flex-col sm:flex-row items-start sm:items-center gap-3">
            <label className="text-xs font-mono text-slate-400 whitespace-nowrap">
              Simulated Attacker IP:
            </label>
            <input
              type="text"
              value={attackerIp}
              onChange={(e) => setAttackerIp(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm font-mono text-slate-100 focus:outline-none focus:border-cyan-400 w-full sm:w-48"
              placeholder="e.g. 198.51.100.42"
            />
            <span className="text-xs text-slate-400 font-mono">
              Target Check: <span className="text-rose-400">{attackVectors.find(a => a.id === selectedAttackType)?.exploitVuln}</span>
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleSimulateAttack}
              disabled={loading || triageLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white font-mono text-xs font-bold shadow-lg shadow-rose-600/20 flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <Flame className="w-4 h-4" />
              1. Simulate Attack
            </button>

            <button
              onClick={() => handleProbeVector()}
              disabled={loading || triageLoading}
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono text-xs font-semibold flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <Crosshair className="w-4 h-4 text-cyan-400" />
              2. Probe Vector
            </button>

            <button
              onClick={handleClosedLoopTriage}
              disabled={triageLoading}
              className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-600/20 flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <Zap className={`w-4 h-4 ${triageLoading ? 'animate-spin' : ''}`} />
              3. Run Full Autonomous Defense Loop
            </button>
          </div>
        </div>
      </div>

      {/* 4. Active Vector Probe & Prevention Proof Result */}
      {probeResult && (
        <div className={`p-5 rounded-2xl border backdrop-blur-xl transition-all ${
          probeResult.prevented 
            ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200' 
            : 'bg-rose-950/20 border-rose-500/40 text-rose-200'
        }`}>
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className={`p-2 rounded-xl mt-0.5 ${
                probeResult.prevented ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'
              }`}>
                {probeResult.prevented ? <ShieldCheck className="w-6 h-6" /> : <ShieldAlert className="w-6 h-6" />}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                    probeResult.prevented ? 'bg-emerald-500/30 text-emerald-300' : 'bg-rose-500/30 text-rose-300'
                  }`}>
                    {probeResult.status}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{probeResult.attack_type}</span>
                </div>
                <h4 className="text-base font-bold text-slate-100 mt-1">
                  {probeResult.prevented ? 'Attack Vector BLOCKED and Neutralized' : 'Attack Vector EXPLOITABLE'}
                </h4>
                <p className="text-sm font-mono mt-1 text-slate-300 leading-relaxed">
                  {probeResult.message}
                </p>
                <div className="text-[11px] font-mono text-slate-400 mt-2">
                  Target Resource: <span className="text-cyan-300">{probeResult.target_resource}</span>
                </div>
              </div>
            </div>

            <button
              onClick={() => handleProbeVector(probeResult.attack_type)}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 shrink-0 flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Re-test Probe
            </button>
          </div>
        </div>
      )}

      {/* 5. Active Attacks & Correlated Exploit Paths */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Active Injected Attacks Feed */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-mono font-bold text-slate-200 uppercase flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              Live Injected Attack Telemetry ({activeAttacks.length})
            </h3>
            <span className="text-xs font-mono text-slate-400">Mock CloudTrail / GuardDuty</span>
          </div>

          {activeAttacks.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-950/60 border border-slate-800/80 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
              <p className="text-sm text-slate-300 font-medium">No active attacks in simulated environment</p>
              <p className="text-xs text-slate-400">
                Click "1. Simulate Attack" above to inject an adversary payload.
              </p>
            </div>
          ) : (
            <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
              {activeAttacks.map((atk) => (
                <div
                  key={atk.attack_id}
                  className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3 hover:border-slate-700 transition-all"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          atk.status === 'PREVENTED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                        }`}>
                          {atk.status}
                        </span>
                        <span className="text-xs font-mono text-cyan-300 font-semibold">{atk.attack_type}</span>
                        <span className="text-[10px] font-mono text-slate-400">{atk.mitre_attack_id}</span>
                      </div>
                      <h5 className="text-sm font-bold text-slate-100 mt-1">{atk.title}</h5>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400 whitespace-nowrap">
                      {new Date(atk.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="text-xs font-mono text-slate-400 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800/80 space-y-1">
                    <div className="text-slate-300">
                      <span className="text-slate-400">Attacker:</span> {atk.attacker_ip} ➔ <span className="text-slate-400">Target:</span> {atk.target_resource_name}
                    </div>
                    <div className="text-slate-400 truncate">
                      <span className="text-slate-400">Payload:</span> {atk.raw_payload}
                    </div>
                  </div>

                  {atk.simulated_logs && atk.simulated_logs.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase text-slate-400">Security Telemetry Logs:</div>
                      <div className="p-2.5 rounded-lg bg-black/60 font-mono text-[11px] text-amber-300/90 border border-slate-800/80 space-y-0.5 max-h-24 overflow-y-auto">
                        {atk.simulated_logs.map((log, i) => (
                          <div key={i} className="leading-tight">{log}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {atk.prevention_proof && (
                    <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-xs font-mono text-emerald-300 flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-400" />
                      <span>{atk.prevention_proof}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Closed-Loop Triage Report / Correlation View */}
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-mono font-bold text-slate-200 uppercase flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Autonomous Triage & Exploit Correlation
            </h3>
            <span className="text-xs font-mono text-cyan-400">LangGraph Cyclical State</span>
          </div>

          {triageReport ? (
            <div className="space-y-4 max-h-[480px] overflow-y-auto pr-1">
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-300">Triage Session:</span>
                  <span className="text-xs font-mono text-cyan-400">{triageReport.session_id}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-300">Composite Risk Score:</span>
                  <span className="text-xs font-mono font-bold text-rose-400">
                    {triageReport.risk_score} / 100 ({triageReport.threat_level})
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-slate-300">Defense Verdict:</span>
                  <span className={`text-xs font-mono font-bold ${
                    triageReport.attack_prevented ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {triageReport.attack_prevented ? '🛡️ ATTACK BLOCKED & PREVENTED' : 'IN_PROGRESS'}
                  </span>
                </div>
              </div>

              {/* Correlated Exploit Chains */}
              {triageReport.correlated_exploits && triageReport.correlated_exploits.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-mono font-semibold text-rose-300 uppercase">
                    🚨 Correlated Adversary Exploit Chains:
                  </div>
                  {triageReport.correlated_exploits.map((exp: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 text-xs font-mono space-y-1">
                      <div className="text-slate-200 font-bold flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                        {exp.attack_type} ➔ {exp.vulnerability_title}
                      </div>
                      <div className="text-slate-400">{exp.attack_chain}</div>
                      <div className="text-emerald-400 pt-1 border-t border-rose-900/30">
                        {exp.defense_goal}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Remediation Summary */}
              {triageReport.executed_actions && triageReport.executed_actions.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-mono font-semibold text-cyan-300 uppercase">
                    Defensive Remediations Executed:
                  </div>
                  {triageReport.executed_actions.map((act: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono flex items-center justify-between">
                      <span className="text-slate-300 font-semibold">{act.resource_id}</span>
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Remediated
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Prevention Proof */}
              {triageReport.prevention_results && triageReport.prevention_results.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-mono font-semibold text-emerald-300 uppercase">
                    Prevention Probes Verification:
                  </div>
                  {triageReport.prevention_results.map((pr: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-xs font-mono space-y-1">
                      <div className="text-emerald-300 font-bold flex items-center gap-1.5">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        {pr.attack_type}: {pr.status}
                      </div>
                      <div className="text-slate-300">{pr.proof}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-slate-950/60 border border-slate-800/80 text-center space-y-3">
              <Zap className="w-8 h-8 text-cyan-400 mx-auto" />
              <p className="text-sm text-slate-300 font-medium">Ready for Autonomous Attack Triage</p>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Select an attack vector and click <strong>"3. Run Full Autonomous Defense Loop"</strong> to see the crawler detect the attack, correlate the exploited vulnerability, remediate the cloud resource, and probe the vector to prove it is prevented.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
