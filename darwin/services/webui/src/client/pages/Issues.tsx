import { useState, useEffect } from 'react';
import { issuesApi } from '../api/client';
import type { Issue, IssueSeverity, IssueStatus } from '../types';
import Card from '../components/Card';
import Button from '../components/Button';

const severityColors: Record<IssueSeverity, string> = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-orange-900 text-orange-200',
  medium: 'bg-yellow-900 text-yellow-200',
  low: 'bg-blue-900 text-blue-200',
};

const statusColors: Record<IssueStatus, string> = {
  open: 'bg-red-900 text-red-200',
  in_progress: 'bg-yellow-900 text-yellow-200',
  resolved: 'bg-blue-900 text-blue-200',
  closed: 'bg-gray-700 text-gray-300',
};

export default function Issues() {
  const [issues, setIssues] = useState<Issue[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<IssueSeverity | ''>('');
  const [statusFilter, setStatusFilter] = useState<IssueStatus | ''>('');
  const [repoFilter, setRepoFilter] = useState('');

  useEffect(() => {
    const fetchIssues = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await issuesApi.list(page, 20, {
          severity: severityFilter || undefined,
          status: statusFilter || undefined,
          repo: repoFilter || undefined,
        });

        setIssues(result.items);
        setTotalPages(result.pages);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch issues');
      } finally {
        setIsLoading(false);
      }
    };

    fetchIssues();
  }, [page, severityFilter, statusFilter, repoFilter]);

  const handleSeverityFilter = (severity: IssueSeverity | '') => {
    setSeverityFilter(severity);
    setPage(1);
  };

  const handleStatusFilter = (status: IssueStatus | '') => {
    setStatusFilter(status);
    setPage(1);
  };

  const handleRepoFilter = (repo: string) => {
    setRepoFilter(repo);
    setPage(1);
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Issues</h1>
        <p className="text-dark-400 mt-1">Track and manage identified issues</p>
      </div>

      {/* Filters */}
      <Card title="Filters" className="mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Severity Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => handleSeverityFilter(e.target.value as IssueSeverity | '')}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 focus:outline-none focus:border-gold-400"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => handleStatusFilter(e.target.value as IssueStatus | '')}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 focus:outline-none focus:border-gold-400"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          {/* Repository Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Repository</label>
            <input
              type="text"
              value={repoFilter}
              onChange={(e) => handleRepoFilter(e.target.value)}
              placeholder="Filter by repo..."
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
            />
          </div>

          {/* Create Issue Button */}
          <div className="flex items-end">
            <Button
              onClick={() => {
                // Navigate to create issue form
                window.location.href = '/issues/new';
              }}
              className="w-full"
            >
              New Issue
            </Button>
          </div>
        </div>
      </Card>

      {/* Issues Grid */}
      {isLoading ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-dark-800 rounded animate-pulse"></div>
          ))}
        </div>
      ) : error ? (
        <Card className="border border-red-900">
          <p className="text-red-400">{error}</p>
        </Card>
      ) : issues.length === 0 ? (
        <Card>
          <p className="text-dark-400 text-center py-8">No issues found</p>
        </Card>
      ) : (
        <div className="space-y-4">
          {issues.map((issue) => (
            <Card key={issue.id} className="hover:border-gold-500 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold text-gold-400">{issue.title}</h3>
                    <span
                      className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                        severityColors[issue.severity]
                      }`}
                    >
                      {issue.severity}
                    </span>
                    <span
                      className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                        statusColors[issue.status]
                      }`}
                    >
                      {issue.status.replace('_', ' ')}
                    </span>
                  </div>

                  <p className="text-dark-300 mb-3">{issue.description}</p>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-dark-400">Repository</span>
                      <p className="text-dark-200">{issue.repository}</p>
                    </div>
                    <div>
                      <span className="text-dark-400">Assigned To</span>
                      <p className="text-dark-200">{issue.assigned_to || 'Unassigned'}</p>
                    </div>
                    <div>
                      <span className="text-dark-400">Created</span>
                      <p className="text-dark-200">
                        {new Date(issue.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <span className="text-dark-400">Updated</span>
                      <p className="text-dark-200">
                        {new Date(issue.updated_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="ml-4 flex flex-col gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      window.location.href = `/issues/${issue.id}`;
                    }}
                  >
                    View
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      window.location.href = `/issues/${issue.id}/edit`;
                    }}
                  >
                    Edit
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-8">
          <Button
            variant="secondary"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            Previous
          </Button>
          <span className="flex items-center px-4 text-dark-300">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="secondary"
            disabled={page === totalPages}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
