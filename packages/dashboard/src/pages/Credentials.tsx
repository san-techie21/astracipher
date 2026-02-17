import { ShieldCheck, Clock, AlertCircle, CheckCircle2 } from 'lucide-react';

const credentials = [
  { id: 'vc-001', agent: 'data-processor-v2', type: 'AgentIdentityCredential', capabilities: ['read', 'write'], expires: '2026-08-15', status: 'valid' },
  { id: 'vc-002', agent: 'api-gateway', type: 'AgentIdentityCredential', capabilities: ['read', 'write', 'execute'], expires: '2026-07-01', status: 'valid' },
  { id: 'vc-003', agent: 'ml-pipeline', type: 'AgentIdentityCredential', capabilities: ['read', 'execute'], expires: '2026-03-01', status: 'expiring' },
  { id: 'vc-004', agent: 'old-service', type: 'AgentIdentityCredential', capabilities: ['read'], expires: '2026-01-15', status: 'expired' },
  { id: 'vc-005', agent: 'orchestrator', type: 'AgentIdentityCredential', capabilities: ['admin'], expires: '2026-12-31', status: 'revoked' },
];

export default function Credentials() {
  const statusIcon = (status: string) => {
    switch (status) {
      case 'valid': return <CheckCircle2 className="w-4 h-4 text-green-400" />;
      case 'expiring': return <Clock className="w-4 h-4 text-amber-400" />;
      case 'expired': return <AlertCircle className="w-4 h-4 text-red-400" />;
      case 'revoked': return <AlertCircle className="w-4 h-4 text-red-500" />;
      default: return null;
    }
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Verifiable Credentials</h2>
        <p className="text-gray-500 mt-1">W3C Verifiable Credentials issued to your agents</p>
      </div>

      <div className="grid gap-4">
        {credentials.map((cred) => (
          <div key={cred.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div className="p-2.5 bg-brand-400/10 rounded-lg mt-0.5">
                  <ShieldCheck className="w-5 h-5 text-brand-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white">{cred.agent}</h3>
                    <code className="text-xs text-gray-600">{cred.id}</code>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">{cred.type}</p>
                  <div className="flex gap-2 mt-3">
                    {cred.capabilities.map((cap) => (
                      <span key={cap} className="text-xs px-2 py-0.5 bg-gray-800 text-gray-400 rounded">{cap}</span>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {statusIcon(cred.status)}
                <span className={`text-xs capitalize ${
                  cred.status === 'valid' ? 'text-green-400' :
                  cred.status === 'expiring' ? 'text-amber-400' : 'text-red-400'
                }`}>
                  {cred.status}
                </span>
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-gray-800 flex justify-between text-xs text-gray-600">
              <span>Expires: {cred.expires}</span>
              <span>Proof: AgentPassHybridSignature2026</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
