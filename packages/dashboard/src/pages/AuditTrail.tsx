import { ScrollText, Filter, Download } from 'lucide-react';

const auditEvents = [
  { id: 1, timestamp: '2026-02-17T10:32:15Z', agent: 'data-processor-v2', action: 'data.read', resource: '/api/customers', result: 'allowed', latency: '12ms' },
  { id: 2, timestamp: '2026-02-17T10:31:42Z', agent: 'unknown-agent', action: 'data.write', resource: '/api/orders', result: 'denied', latency: '3ms' },
  { id: 3, timestamp: '2026-02-17T10:30:58Z', agent: 'api-gateway', action: 'credential.verify', resource: 'vc-002', result: 'allowed', latency: '45ms' },
  { id: 4, timestamp: '2026-02-17T10:28:12Z', agent: 'ml-pipeline', action: 'model.execute', resource: '/models/predict', result: 'allowed', latency: '230ms' },
  { id: 5, timestamp: '2026-02-17T10:25:01Z', agent: 'orchestrator', action: 'agent.delegate', resource: 'sub-agent-7', result: 'allowed', latency: '8ms' },
  { id: 6, timestamp: '2026-02-17T10:22:33Z', agent: 'customer-bot', action: 'data.read', resource: '/api/products', result: 'allowed', latency: '18ms' },
  { id: 7, timestamp: '2026-02-17T10:20:10Z', agent: 'data-processor-v2', action: 'data.delete', resource: '/api/temp-records', result: 'denied', latency: '5ms' },
];

export default function AuditTrail() {
  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white">Audit Trail</h2>
          <p className="text-gray-500 mt-1">Cryptographically signed log of all agent actions</p>
        </div>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 px-3 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 text-sm">
            <Filter className="w-4 h-4" />
            Filter
          </button>
          <button className="flex items-center gap-2 px-3 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 text-sm">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-800">
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Timestamp</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Agent</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Action</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Resource</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Result</th>
              <th className="text-left p-4 text-xs font-medium text-gray-500 uppercase">Latency</th>
            </tr>
          </thead>
          <tbody>
            {auditEvents.map((event) => (
              <tr key={event.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                <td className="p-4 text-xs text-gray-400 font-mono">{new Date(event.timestamp).toLocaleTimeString()}</td>
                <td className="p-4 text-sm text-gray-300">{event.agent}</td>
                <td className="p-4">
                  <code className="text-xs text-brand-400 bg-brand-400/10 px-2 py-0.5 rounded">{event.action}</code>
                </td>
                <td className="p-4 text-xs text-gray-500 font-mono">{event.resource}</td>
                <td className="p-4">
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    event.result === 'allowed' ? 'bg-green-400/10 text-green-400' : 'bg-red-400/10 text-red-400'
                  }`}>
                    {event.result}
                  </span>
                </td>
                <td className="p-4 text-xs text-gray-500">{event.latency}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
