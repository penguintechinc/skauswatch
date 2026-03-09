import React from 'react';
import Card from './Card';

interface ReviewCardProps {
  review: {
    id: string;
    prNumber: number;
    repository: string;
    author: string;
    status: 'completed' | 'in_progress' | 'pending' | 'failed';
    createdAt: string;
    summary: string;
    issueCount: number;
  };
}

const statusColors: Record<string, string> = {
  completed: 'bg-green-900 text-green-200',
  in_progress: 'bg-blue-900 text-blue-200',
  pending: 'bg-yellow-900 text-yellow-200',
  failed: 'bg-red-900 text-red-200',
};

const statusLabels: Record<string, string> = {
  completed: 'Completed',
  in_progress: 'In Progress',
  pending: 'Pending',
  failed: 'Failed',
};

export default function ReviewCard({ review }: ReviewCardProps) {
  const statusColor = statusColors[review.status];
  const statusLabel = statusLabels[review.status];
  const formattedDate = new Date(review.createdAt).toLocaleDateString();

  return (
    <Card className="cursor-pointer hover:border-gold-500 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1">
          <h3 className="text-md font-semibold text-gold-400">
            {review.repository} #{review.prNumber}
          </h3>
          <p className="text-sm text-elder-text-light">by {review.author}</p>
        </div>
        <span className={`px-3 py-1 rounded text-xs font-medium ${statusColor}`}>
          {statusLabel}
        </span>
      </div>

      <p className="text-sm text-elder-text-base mb-3 line-clamp-2">{review.summary}</p>

      <div className="flex items-center justify-between text-xs text-elder-text-light">
        <span>{formattedDate}</span>
        <span className="font-medium">
          {review.issueCount} {review.issueCount === 1 ? 'issue' : 'issues'}
        </span>
      </div>
    </Card>
  );
}
