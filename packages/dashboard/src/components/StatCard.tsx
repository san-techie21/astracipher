import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  icon: LucideIcon;
  color?: string;
}

export default function StatCard({ title, value, change, icon: Icon, color = 'brand' }: StatCardProps) {
  const colorMap: Record<string, string> = {
    brand: 'text-brand-400 bg-brand-400/10',
    green: 'text-green-400 bg-green-400/10',
    amber: 'text-amber-400 bg-amber-400/10',
    red: 'text-red-400 bg-red-400/10',
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-500">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          {change && (
            <p className={`text-xs mt-1 ${change.startsWith('+') ? 'text-green-400' : 'text-red-400'}`}>
              {change} from last period
            </p>
          )}
        </div>
        <div className={`p-2.5 rounded-lg ${colorMap[color] || colorMap.brand}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
