import { Bot, Plus, MoreVertical, Shield } from 'lucide-react';

const agents = [
  { id: 'did:agentpass:testnet:abc123', name: 'data-processor-v2', status: 'active', trustLevel: 8, credentials: 3, created: '2026-01-15' },
  { id: 'did:agentpass:testnet:def456', name: 'api-gateway', status: 'active', trustLevel: 9, credentials: 5, created: '2026-01-10' },
  { id: 'did:agentpass:testnet:ghi789', name: 'ml-pipeline', status: 'active', trustLevel: 7, credentials: 2, created: '2026-02-01' },
  { id: 'did:agentpass:testnet:jkl012', name: 'orchestrator', status: 'suspended', trustLevel: 10, credentials: 8, created: '2025-12-20' },
  { id: 'did:agentpass:testnet:mno345', name: 'customer-bot', status: 'active', trustLevel: 6, credentials: 4, created: '2026-02-10' },
];

export default function Agents() {
  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white">Agent Identities</h2>
          <p className="text-gray-500 mt-1">Manage your agent DIDs and their identities</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-700 transition-colors">
          <Plus className="w-4 h-4" />
          Create Agent
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Agent</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">DID</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Trust</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Credentials</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase"></th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                <td className="p-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-brand-400/10 rounded-lg">
                      <Bot className="w-4 h-4 text-brand-400" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-200">{agent.name}</p>
                      <p className="text-xs text-gray-600">{agent.created}</p>
                    </div>
                  </div>
                </td>
                <td className="p-4">
                  <code className="text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded">{agent.id.slice(0, 30)}...</code>
                </td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    <Shield className="w-3 h-3 text-brand-400" />
                    <span className="text-sm text-gray-300">{agent.trustLevel}/10</span>
                  </div>
                </td>
                <td className="p-4">
                  <span className="text-sm text-gray-300">{agent.credentials}</span>
                </td>
                <td className="p-4">
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    agent.status === 'active' ? 'bg-green-400/10 text-green-400' : 'bg-red-400/10 text-red-400'
                  }`}>
                    {agent.status}
                  </span>
                </td>
                <td className="p-4">
                  <button className="text-gray-600 hover:text-gray-400">
                    <MoreVertical className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
