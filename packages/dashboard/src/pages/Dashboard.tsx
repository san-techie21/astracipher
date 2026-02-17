import { Bot, ShieldCheck, ScrollText, AlertTriangle } from 'lucide-react';
import StatCard from '../components/StatCard';

const recentActivity = [
  { id: 1, action: 'Agent Created', agent: 'data-processor-v2', time: '2 min ago', status: 'success' },
  { id: 2, action: 'Credential Issued', agent: 'api-gateway', time: '15 min ago', status: 'success' },
  { id: 3, action: 'Permission Denied', agent: 'unknown-agent', time: '32 min ago', status: 'error' },
  { id: 4, action: 'Credential Verified', agent: 'ml-pipeline', time: '1 hr ago', status: 'success' },
  { id: 5, action: 'Trust Chain Updated', agent: 'orchestrator', time: '2 hr ago', status: 'success' },
];

export default function Dashboard() {
  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <p className="text-gray-500 mt-1">Overview of your agent identity infrastructure</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard title="Active Agents" value={24} change="+3" icon={Bot} color="brand" />
        <StatCard title="Valid Credentials" value={47} change="+8" icon={ShieldCheck} color="green" />
        <StatCard title="Audit Events (24h)" value={1284} change="+12%" icon={ScrollText} color="amber" />
        <StatCard title="Security Alerts" value={2} icon={AlertTriangle} color="red" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Activity</h3>
          <div className="space-y-3">
            {recentActivity.map((event) => (
              <div key={event.id} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                <div className="flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${event.status === 'success' ? 'bg-green-400' : 'bg-red-400'}`} />
                  <div>
                    <p className="text-sm text-gray-200">{event.action}</p>
                    <p className="text-xs text-gray-500">{event.agent}</p>
                  </div>
                </div>
                <span className="text-xs text-gray-600">{event.time}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Trust Chain Health */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Trust Chain Health</h3>
          <div className="space-y-4">
            {[
              { chain: 'Production Pipeline', depth: 3, status: 'healthy' },
              { chain: 'Data Processing', depth: 4, status: 'healthy' },
              { chain: 'Customer-facing Agents', depth: 2, status: 'warning' },
              { chain: 'Internal Tools', depth: 5, status: 'healthy' },
            ].map((chain) => (
              <div key={chain.chain} className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-200">{chain.chain}</p>
                  <p className="text-xs text-gray-500">Depth: {chain.depth}</p>
                </div>
                <span className={`text-xs px-2 py-1 rounded-full ${
                  chain.status === 'healthy' ? 'bg-green-400/10 text-green-400' : 'bg-amber-400/10 text-amber-400'
                }`}>
                  {chain.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
