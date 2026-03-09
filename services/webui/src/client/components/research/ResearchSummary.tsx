import { ResearchSummary } from '../../types/research';

interface ResearchSummaryProps {
  summary: ResearchSummary | null;
}

const INDICATOR_TYPE_COLORS: Record<string, string> = {
  ip: 'bg-blue-600',
  domain: 'bg-purple-600',
  url: 'bg-indigo-600',
  hash: 'bg-orange-600',
  asn: 'bg-cyan-600',
  email: 'bg-pink-600',
};

const getRiskColor = (score: number): string => {
  if (score <= 30) return 'bg-green-600';
  if (score <= 60) return 'bg-yellow-600';
  return 'bg-red-600';
};

const getRiskLabel = (score: number): string => {
  if (score <= 30) return 'LOW';
  if (score <= 60) return 'MEDIUM';
  return 'HIGH';
};

export default function ResearchSummaryComponent({ summary }: ResearchSummaryProps) {
  if (!summary) {
    return null;
  }

  const riskColor = getRiskColor(summary.risk_score);
  const riskLabel = getRiskLabel(summary.risk_score);
  const badgeColor = INDICATOR_TYPE_COLORS[summary.indicator_type] || 'bg-gray-600';

  return (
    <div className="bg-dark-800 border border-dark-700 rounded-lg p-6 mb-6">
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <span className={`${badgeColor} text-white text-xs font-bold px-3 py-1 rounded uppercase tracking-wider`}>
            {summary.indicator_type}
          </span>
          <h2 className="text-xl font-bold text-gold-400">Research Summary</h2>
        </div>
      </div>

      {/* Risk Score Visualization */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <p className="text-dark-400 text-sm font-medium">Risk Score</p>
          <span className={`${riskColor} text-white text-xs font-bold px-3 py-1 rounded uppercase`}>
            {riskLabel}: {summary.risk_score}
          </span>
        </div>
        <div className="w-full bg-dark-700 rounded-full h-3 overflow-hidden">
          <div
            className={`${riskColor} h-3 transition-all duration-300 ease-out`}
            style={{ width: `${summary.risk_score}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-dark-500 mt-2">
          <span>0 (Low)</span>
          <span>50</span>
          <span>100 (Critical)</span>
        </div>
      </div>

      {/* Key Findings */}
      {summary.key_findings && summary.key_findings.length > 0 && (
        <div>
          <p className="text-dark-400 text-sm font-medium mb-3">Key Findings</p>
          <ul className="space-y-2">
            {summary.key_findings.map((finding, index) => (
              <li key={index} className="flex items-start gap-3 text-gold-400">
                <span className="text-gold-500 mt-1 flex-shrink-0">•</span>
                <span className="text-sm">{finding}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
