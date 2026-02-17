import { Settings as SettingsIcon, Key, Globe, Bell, Shield } from 'lucide-react';

export default function Settings() {
  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Settings</h2>
        <p className="text-gray-500 mt-1">Configure your AgentPass deployment</p>
      </div>

      <div className="space-y-6 max-w-2xl">
        {/* Network */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Globe className="w-5 h-5 text-brand-400" />
            <h3 className="text-lg font-semibold text-white">Network</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Active Network</p>
                <p className="text-xs text-gray-600">Select testnet or mainnet</p>
              </div>
              <select className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300">
                <option>Testnet</option>
                <option>Mainnet</option>
              </select>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Server URL</p>
                <p className="text-xs text-gray-600">AgentPass verification server</p>
              </div>
              <code className="text-xs text-gray-400 bg-gray-800 px-3 py-1.5 rounded">http://localhost:3456</code>
            </div>
          </div>
        </div>

        {/* Cryptography */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Key className="w-5 h-5 text-brand-400" />
            <h3 className="text-lg font-semibold text-white">Cryptography</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Default Mode</p>
                <p className="text-xs text-gray-600">Signing algorithm preference</p>
              </div>
              <select className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300">
                <option>Hybrid (PQC + Classical)</option>
                <option>PQC Only (ML-DSA-65)</option>
                <option>Classical Only (ECDSA P-256)</option>
              </select>
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Key Rotation</p>
                <p className="text-xs text-gray-600">Auto-rotate keys periodically</p>
              </div>
              <select className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300">
                <option>Every 90 days</option>
                <option>Every 30 days</option>
                <option>Manual only</option>
              </select>
            </div>
          </div>
        </div>

        {/* Security */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-5 h-5 text-brand-400" />
            <h3 className="text-lg font-semibold text-white">Security</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Max Trust Chain Depth</p>
                <p className="text-xs text-gray-600">Maximum delegation depth</p>
              </div>
              <input type="number" defaultValue={5} className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300 w-20 text-center" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Credential Validity</p>
                <p className="text-xs text-gray-600">Default expiration for new credentials</p>
              </div>
              <select className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-300">
                <option>365 days</option>
                <option>180 days</option>
                <option>90 days</option>
                <option>30 days</option>
              </select>
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Bell className="w-5 h-5 text-brand-400" />
            <h3 className="text-lg font-semibold text-white">Notifications</h3>
          </div>
          <div className="space-y-3">
            <label className="flex items-center justify-between cursor-pointer">
              <div>
                <p className="text-sm text-gray-300">Credential Expiry Alerts</p>
                <p className="text-xs text-gray-600">Get notified before credentials expire</p>
              </div>
              <div className="w-10 h-6 bg-brand-600 rounded-full relative">
                <div className="w-4 h-4 bg-white rounded-full absolute top-1 right-1" />
              </div>
            </label>
            <label className="flex items-center justify-between cursor-pointer">
              <div>
                <p className="text-sm text-gray-300">Security Alerts</p>
                <p className="text-xs text-gray-600">Unauthorized access attempts</p>
              </div>
              <div className="w-10 h-6 bg-brand-600 rounded-full relative">
                <div className="w-4 h-4 bg-white rounded-full absolute top-1 right-1" />
              </div>
            </label>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-300">Webhook URL</p>
                <p className="text-xs text-gray-600">Send alerts to your webhook</p>
              </div>
              <input type="text" placeholder="https://..." className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-400 w-56" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
