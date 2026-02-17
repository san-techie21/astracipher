import { Scale, CheckCircle2, AlertTriangle, XCircle, FileText } from 'lucide-react';

const frameworks = [
  { id: 'dpdp', name: 'DPDP Act 2023', region: 'India', score: 94, gaps: 1, status: 'compliant' },
  { id: 'sebi', name: 'SEBI CSCRF', region: 'India', score: 88, gaps: 2, status: 'compliant' },
  { id: 'rbi', name: 'RBI Guidelines', region: 'India', score: 91, gaps: 1, status: 'compliant' },
  { id: 'euai', name: 'EU AI Act', region: 'Europe', score: 72, gaps: 5, status: 'attention' },
  { id: 'gdpr', name: 'GDPR', region: 'Europe', score: 85, gaps: 3, status: 'compliant' },
  { id: 'hipaa', name: 'HIPAA AI', region: 'USA', score: 0, gaps: 0, status: 'not-configured' },
];

export default function Compliance() {
  const statusBadge = (status: string) => {
    switch (status) {
      case 'compliant':
        return <span className="flex items-center gap-1 text-xs text-green-400"><CheckCircle2 className="w-3 h-3" /> Compliant</span>;
      case 'attention':
        return <span className="flex items-center gap-1 text-xs text-amber-400"><AlertTriangle className="w-3 h-3" /> Needs Attention</span>;
      case 'non-compliant':
        return <span className="flex items-center gap-1 text-xs text-red-400"><XCircle className="w-3 h-3" /> Non-Compliant</span>;
      default:
        return <span className="text-xs text-gray-600">Not Configured</span>;
    }
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white">Compliance Dashboard</h2>
          <p className="text-gray-500 mt-1">Regulatory compliance status across frameworks</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-700">
          <FileText className="w-4 h-4" />
          Generate Report
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {frameworks.map((fw) => (
          <div key={fw.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-brand-400/10 rounded-lg">
                  <Scale className="w-5 h-5 text-brand-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">{fw.name}</h3>
                  <p className="text-xs text-gray-500">{fw.region}</p>
                </div>
              </div>
              {statusBadge(fw.status)}
            </div>

            {fw.status !== 'not-configured' ? (
              <>
                <div className="mb-2">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-500">Compliance Score</span>
                    <span className="text-gray-300">{fw.score}%</span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${
                        fw.score >= 90 ? 'bg-green-500' : fw.score >= 70 ? 'bg-amber-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${fw.score}%` }}
                    />
                  </div>
                </div>
                <p className="text-xs text-gray-600 mt-2">{fw.gaps} gap{fw.gaps !== 1 ? 's' : ''} identified</p>
              </>
            ) : (
              <div className="text-center py-4">
                <p className="text-sm text-gray-600">Module not activated</p>
                <button className="text-xs text-brand-400 hover:text-brand-300 mt-2">Enable Module →</button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
