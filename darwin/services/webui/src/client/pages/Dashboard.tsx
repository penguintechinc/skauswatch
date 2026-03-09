import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import { dashboardApi } from '../hooks/useApi';
import Card from '../components/Card';
import type { DashboardStats, Finding, Platform, FindingSeverity, DashboardFilters } from '../types';

export default function Dashboard() {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [isLoadingFindings, setIsLoadingFindings] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filters, setFilters] = useState<DashboardFilters>({});
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const perPage = 20;

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    fetchFindings();
  }, [filters, currentPage]);

  const fetchStats = async () => {
    setIsLoadingStats(true);
    try {
      const data = await dashboardApi.getStats();
      setStats(data);
      setError(null);
    } catch (err) {
      setError('Failed to load dashboard statistics');
      console.error('Error loading stats:', err);
    } finally {
      setIsLoadingStats(false);
    }
  };

  const fetchFindings = async () => {
    setIsLoadingFindings(true);
    try {
      const response = await dashboardApi.getFindings({
        ...filters,
        page: currentPage,
        per_page: perPage,
      });
      setFindings(response.findings || []);
      setTotal(response.pagination.total);
      setTotalPages(response.pagination.pages);
      setError(null);
    } catch (err) {
      setError('Failed to load findings');
      console.error('Error loading findings:', err);
    } finally {
      setIsLoadingFindings(false);
    }
  };

  const updateFilter = (key: keyof DashboardFilters, value: any) => {
    setFilters({ ...filters, [key]: value });
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setFilters({});
    setCurrentPage(1);
  };

  const hasActiveFilters = Object.keys(filters).length > 0;

  const getSeverityColor = (severity: FindingSeverity) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-900/30 border-red-700';
      case 'major':
        return 'text-orange-400 bg-orange-900/30 border-orange-700';
      case 'minor':
        return 'text-yellow-400 bg-yellow-900/30 border-yellow-700';
      case 'suggestion':
        return 'text-blue-400 bg-blue-900/30 border-blue-700';
      default:
        return 'text-dark-300 bg-dark-700 border-dark-600';
    }
  };

  const getSeverityBadge = (severity: FindingSeverity) => {
    return <span className={`badge ${getSeverityColor(severity)}`}>{severity}</span>;
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Dashboard</h1>
        <p className="text-dark-400 mt-1">
          Code review findings across all repositories
        </p>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Overview Cards */}
      {isLoadingStats ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <div className="animate-pulse h-16 bg-dark-700 rounded"></div>
            </Card>
          ))}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          <Card>
            <div className="text-sm text-dark-400 mb-1">Total Repositories</div>
            <div className="text-3xl font-bold text-gold-400">
              {stats.overview.total_repositories}
            </div>
          </Card>
          <Card>
            <div className="text-sm text-dark-400 mb-1">Total Reviews</div>
            <div className="text-3xl font-bold text-gold-400">
              {stats.overview.total_reviews}
            </div>
          </Card>
          <Card>
            <div className="text-sm text-dark-400 mb-1">Pending Reviews</div>
            <div className="text-3xl font-bold text-orange-400">
              {stats.overview.pending_reviews}
            </div>
          </Card>
        </div>
      ) : null}

      {/* Severity Breakdown - Clickable Filters */}
      {stats && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-gold-400 mb-3">
            Findings by Severity (Last 30 Days)
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {(['critical', 'major', 'minor', 'suggestion'] as FindingSeverity[]).map(
              (severity) => (
                <button
                  key={severity}
                  onClick={() => {
                    if (filters.severity === severity) {
                      const { severity: _, ...rest } = filters;
                      setFilters(rest);
                    } else {
                      updateFilter('severity', severity);
                    }
                  }}
                  className={`card cursor-pointer transition-all ${
                    filters.severity === severity
                      ? 'ring-2 ring-gold-500'
                      : 'hover:bg-dark-750'
                  }`}
                >
                  <div className="text-sm text-dark-400 mb-1 capitalize">{severity}</div>
                  <div className={`text-3xl font-bold ${getSeverityColor(severity).split(' ')[0]}`}>
                    {stats.findings[severity]}
                  </div>
                </button>
              )
            )}
          </div>
        </div>
      )}

      {/* Platform Breakdown - Clickable Filters */}
      {stats && Object.keys(stats.platforms).length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-gold-400 mb-3">Repositories by Platform</h2>
          <div className="flex gap-3 flex-wrap">
            {Object.entries(stats.platforms).map(([platform, count]) => (
              <button
                key={platform}
                onClick={() => {
                  if (filters.platform === platform) {
                    const { platform: _, ...rest } = filters;
                    setFilters(rest);
                  } else {
                    updateFilter('platform', platform as Platform);
                  }
                }}
                className={`px-4 py-2 rounded-lg border transition-all ${
                  filters.platform === platform
                    ? 'border-gold-500 bg-gold-900/20 text-gold-400'
                    : 'border-dark-600 bg-dark-800 text-dark-300 hover:border-dark-500'
                }`}
              >
                <span className="font-medium capitalize">{platform}</span>
                <span className="ml-2 text-sm">({count})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Findings Table with Filters */}
      <Card>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gold-400">Recent Findings</h2>
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-sm text-gold-400 hover:text-gold-300"
            >
              Clear All Filters
            </button>
          )}
        </div>

        {/* Active Filters Display */}
        {hasActiveFilters && (
          <div className="mb-4 flex gap-2 flex-wrap">
            {filters.platform && (
              <span className="px-3 py-1 bg-dark-700 text-dark-300 rounded-full text-sm flex items-center gap-2">
                Platform: {filters.platform}
                <button
                  onClick={() => {
                    const { platform, ...rest } = filters;
                    setFilters(rest);
                  }}
                  className="text-red-400 hover:text-red-300"
                >
                  ×
                </button>
              </span>
            )}
            {filters.organization && (
              <span className="px-3 py-1 bg-dark-700 text-dark-300 rounded-full text-sm flex items-center gap-2">
                Org: {filters.organization}
                <button
                  onClick={() => {
                    const { organization, ...rest } = filters;
                    setFilters(rest);
                  }}
                  className="text-red-400 hover:text-red-300"
                >
                  ×
                </button>
              </span>
            )}
            {filters.severity && (
              <span className="px-3 py-1 bg-dark-700 text-dark-300 rounded-full text-sm flex items-center gap-2">
                Severity: {filters.severity}
                <button
                  onClick={() => {
                    const { severity, ...rest } = filters;
                    setFilters(rest);
                  }}
                  className="text-red-400 hover:text-red-300"
                >
                  ×
                </button>
              </span>
            )}
            {filters.repository_id && (
              <span className="px-3 py-1 bg-dark-700 text-dark-300 rounded-full text-sm flex items-center gap-2">
                Repository ID: {filters.repository_id}
                <button
                  onClick={() => {
                    const { repository_id, ...rest } = filters;
                    setFilters(rest);
                  }}
                  className="text-red-400 hover:text-red-300"
                >
                  ×
                </button>
              </span>
            )}
          </div>
        )}

        {isLoadingFindings ? (
          <div className="animate-pulse space-y-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-16 bg-dark-700 rounded"></div>
            ))}
          </div>
        ) : findings.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-dark-400">
              {hasActiveFilters
                ? 'No findings match your filters'
                : 'No findings yet. Add repositories to start reviewing code!'}
            </p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>File</th>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Line</th>
                    <th>Category</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <div>
                          <div className="text-gold-400 font-medium">
                            {finding.repository.display_name || finding.repository.name}
                          </div>
                          <div className="text-xs text-dark-500 capitalize">
                            {finding.repository.platform}
                          </div>
                        </div>
                      </td>
                      <td className="text-dark-300 text-sm font-mono">
                        {finding.file_path.split('/').pop()}
                      </td>
                      <td>{getSeverityBadge(finding.severity)}</td>
                      <td>
                        <div className="max-w-md">
                          <div className="text-dark-200">{finding.title}</div>
                          {finding.body && (
                            <div className="text-xs text-dark-500 mt-1 truncate">
                              {finding.body.substring(0, 80)}...
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="text-dark-400 text-sm">
                        {finding.line_start}
                        {finding.line_end !== finding.line_start && `-${finding.line_end}`}
                      </td>
                      <td>
                        <span className="badge badge-secondary">{finding.category}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="mt-6 flex items-center justify-between">
                <div className="text-sm text-dark-400">
                  Showing {findings.length} of {total} findings
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setCurrentPage(currentPage - 1)}
                    disabled={currentPage === 1}
                    className="px-3 py-1 bg-dark-700 text-dark-300 rounded hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  <div className="flex items-center gap-1">
                    {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                      let pageNum;
                      if (totalPages <= 5) {
                        pageNum = i + 1;
                      } else if (currentPage <= 3) {
                        pageNum = i + 1;
                      } else if (currentPage >= totalPages - 2) {
                        pageNum = totalPages - 4 + i;
                      } else {
                        pageNum = currentPage - 2 + i;
                      }
                      return (
                        <button
                          key={pageNum}
                          onClick={() => setCurrentPage(pageNum)}
                          className={`px-3 py-1 rounded ${
                            currentPage === pageNum
                              ? 'bg-gold-500 text-dark-900'
                              : 'bg-dark-700 text-dark-300 hover:bg-dark-600'
                          }`}
                        >
                          {pageNum}
                        </button>
                      );
                    })}
                  </div>
                  <button
                    onClick={() => setCurrentPage(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className="px-3 py-1 bg-dark-700 text-dark-300 rounded hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
