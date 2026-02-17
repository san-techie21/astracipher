import { Outlet, NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Bot,
  ShieldCheck,
  ScrollText,
  Scale,
  Settings,
  Fingerprint,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/agents', icon: Bot, label: 'Agents' },
  { to: '/credentials', icon: ShieldCheck, label: 'Credentials' },
  { to: '/audit', icon: ScrollText, label: 'Audit Trail' },
  { to: '/compliance', icon: Scale, label: 'Compliance' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function Layout() {
  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-6 flex items-center gap-3 border-b border-gray-800">
          <Fingerprint className="w-8 h-8 text-brand-400" />
          <div>
            <h1 className="text-lg font-bold text-white">AgentPass</h1>
            <p className="text-xs text-gray-500">Identity Dashboard</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-brand-600/20 text-brand-400 font-medium'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
                }`
              }
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <div className="bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500">Network</p>
            <p className="text-sm text-green-400 flex items-center gap-2">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
              Testnet
            </p>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
