import React, { useState, useEffect } from 'react';
import IssueCard from './IssueCard';

interface Issue {
  id: string;
  type: 'bug' | 'security' | 'style' | 'performance' | 'documentation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  file: string;
  line: number;
  status: 'open' | 'resolved' | 'dismissed';
}

interface IssueListProps {
  reviewId?: string;
  severityFilter?: ('low' | 'medium' | 'high' | 'critical')[];
  statusFilter?: ('open' | 'resolved' | 'dismissed')[];
  onSelectIssue?: (issue: Issue) => void;
}

export default function IssueList({
  reviewId,
  severityFilter = ['low', 'medium', 'high', 'critical'],
  statusFilter = ['open', 'resolved', 'dismissed'],
  onSelectIssue,
}: IssueListProps) {
  const [issues, setIssues] = useState<Issue[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIssues();
  }, [reviewId, severityFilter, statusFilter]);

  const fetchIssues = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (reviewId) params.append('reviewId', reviewId);
      severityFilter.forEach((s) => params.append('severity', s));
      statusFilter.forEach((s) => params.append('status', s));

      const response = await fetch(`/api/v1/issues?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setIssues(data.issues || []);
      }
    } catch (error) {
      console.error('Failed to fetch issues:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-4 text-center text-elder-text-light">Loading issues...</div>;
  }

  if (issues.length === 0) {
    return <div className="p-4 text-center text-elder-text-light">No issues found</div>;
  }

  return (
    <div className="space-y-3">
      {issues.map((issue) => (
        <div key={issue.id} onClick={() => onSelectIssue?.(issue)}>
          <IssueCard issue={issue} />
        </div>
      ))}
    </div>
  );
}
