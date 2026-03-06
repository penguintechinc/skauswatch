import React from 'react';

interface IssueCardProps {
  issue: {
    id: string;
    type: 'bug' | 'security' | 'style' | 'performance' | 'documentation';
    severity: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    file: string;
    line: number;
    status: 'open' | 'resolved' | 'dismissed';
  };
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-orange-900 text-orange-200',
  medium: 'bg-yellow-900 text-yellow-200',
  low: 'bg-blue-900 text-blue-200',
};

const typeIcons: Record<string, string> = {
  bug: 'Bug',
  security: 'Security',
  style: 'Style',
  performance: 'Performance',
  documentation: 'Docs',
};

const statusColors: Record<string, string> = {
  open: 'text-red-400',
  resolved: 'text-green-400',
  dismissed: 'text-gray-400',
};

export default function IssueCard({ issue }: IssueCardProps) {
  const severityColor = severityColors[issue.severity];
  const statusColor = statusColors[issue.status];

  return (
    <div className="card p-3 hover:border-gold-500 transition-colors cursor-pointer">
      <div className="flex items-start justify-between mb-2">
        <div className="flex-1">
          <h4 className="text-sm font-semibold text-gold-400 mb-1">{issue.title}</h4>
          <p className="text-xs text-elder-text-light">{issue.file}:{issue.line}</p>
        </div>
        <div className="flex items-center gap-2 ml-2">
          <span className={`px-2 py-1 rounded text-xs font-medium ${severityColor}`}>
            {issue.severity}
          </span>
          <span className={`px-2 py-1 rounded text-xs font-medium bg-elder-bg-darker ${statusColor}`}>
            {issue.status}
          </span>
        </div>
      </div>

      <p className="text-xs text-elder-text-base mb-2 line-clamp-2">{issue.description}</p>

      <div className="flex items-center justify-between">
        <span className="inline-block px-2 py-0.5 rounded text-xs bg-elder-bg-darker text-elder-text-light">
          {typeIcons[issue.type]}
        </span>
      </div>
    </div>
  );
}
