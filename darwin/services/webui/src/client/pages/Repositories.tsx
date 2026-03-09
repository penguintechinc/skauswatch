import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { repositoriesApi } from '../hooks/useApi';
import Card from '../components/Card';
import Button from '../components/Button';
import CreateRepositoryModal from '../components/CreateRepositoryModal';
import type { Repository } from '../types';

export default function Repositories() {
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // Filters
  const [platformFilter, setPlatformFilter] = useState<string>('');
  const [organizationFilter, setOrganizationFilter] = useState<string>('');
  const [enabledFilter, setEnabledFilter] = useState<string>('all');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const perPage = 20;

  const fetchRepositories = async () => {
    setIsLoading(true);
    try {
      const filters: any = {
        page: currentPage,
        per_page: perPage,
      };

      if (platformFilter) filters.platform = platformFilter;
      if (organizationFilter) filters.organization = organizationFilter;
      if (enabledFilter !== 'all') {
        filters.enabled = enabledFilter === 'enabled';
      }

      const response = await repositoriesApi.list(filters);
      setRepositories(response.repositories || []);
      setTotal(response.pagination.total);
      setTotalPages(response.pagination.pages);
      setError(null);
    } catch (err) {
      setError('Failed to load repositories');
      console.error('Error loading repositories:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRepositories();
  }, [currentPage, platformFilter, organizationFilter, enabledFilter]);

  const handleDeleteRepository = async (id: number) => {
    if (!confirm('Are you sure you want to delete this repository? This will also delete all associated reviews.')) return;
    try {
      await repositoriesApi.delete(id);
      fetchRepositories();
    } catch (err) {
      setError('Failed to delete repository');
    }
  };

  const getPlatformBadgeColor = (platform: string) => {
    switch (platform) {
      case 'github':
        return 'bg-purple-900/30 text-purple-400 border-purple-700';
      case 'gitlab':
        return 'bg-orange-900/30 text-orange-400 border-orange-700';
      case 'git':
        return 'bg-blue-900/30 text-blue-400 border-blue-700';
      default:
        return 'bg-dark-700 text-dark-300 border-dark-600';
    }
  };

  const clearFilters = () => {
    setPlatformFilter('');
    setOrganizationFilter('');
    setEnabledFilter('all');
    setCurrentPage(1);
  };

  const hasActiveFilters = platformFilter || organizationFilter || enabledFilter !== 'all';

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">Repositories</h1>
          <p className="text-dark-400 mt-1">Manage repositories for AI code review</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>+ Add Repository</Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Filters */}
      <Card className="mb-4">
        <div className="flex gap-4 items-end flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm text-dark-400 mb-1">Platform</label>
            <select
              value={platformFilter}
              onChange={(e) => {
                setPlatformFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="input"
            >
              <option value="">All Platforms</option>
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
              <option value="git">Native Git</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm text-dark-400 mb-1">Organization</label>
            <input
              type="text"
              value={organizationFilter}
              onChange={(e) => {
                setOrganizationFilter(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Filter by organization..."
              className="input"
            />
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm text-dark-400 mb-1">Status</label>
            <select
              value={enabledFilter}
              onChange={(e) => {
                setEnabledFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="input"
            >
              <option value="all">All</option>
              <option value="enabled">Enabled Only</option>
              <option value="disabled">Disabled Only</option>
            </select>
          </div>
          {hasActiveFilters && (
            <Button variant="secondary" onClick={clearFilters}>
              Clear Filters
            </Button>
          )}
        </div>
      </Card>

      {/* Repositories Table */}
      <Card>
        {isLoading ? (
          <div className="animate-pulse space-y-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-16 bg-dark-700 rounded"></div>
            ))}
          </div>
        ) : repositories.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-dark-400 mb-4">
              {hasActiveFilters
                ? 'No repositories match your filters'
                : 'No repositories configured yet'}
            </p>
            {!hasActiveFilters && (
              <Button onClick={() => setShowCreateModal(true)}>
                Add Your First Repository
              </Button>
            )}
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Platform</th>
                    <th>Organization</th>
                    <th>Status</th>
                    <th>Polling</th>
                    <th>Auto Review</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {repositories.map((repo) => (
                    <tr key={repo.id}>
                      <td>
                        <div>
                          <div className="text-gold-400 font-medium">
                            {repo.display_name || repo.repository}
                          </div>
                          {repo.display_name && (
                            <div className="text-sm text-dark-400">{repo.repository}</div>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${getPlatformBadgeColor(repo.platform)}`}>
                          {repo.platform}
                        </span>
                      </td>
                      <td className="text-dark-300">
                        {repo.platform_organization || '-'}
                      </td>
                      <td>
                        <span
                          className={
                            repo.enabled
                              ? 'text-green-400'
                              : 'text-red-400'
                          }
                        >
                          {repo.enabled ? '● Active' : '○ Disabled'}
                        </span>
                      </td>
                      <td>
                        {repo.polling_enabled ? (
                          <span className="text-blue-400">
                            Every {repo.polling_interval_minutes}m
                          </span>
                        ) : (
                          <span className="text-dark-500">Off</span>
                        )}
                      </td>
                      <td>
                        <span
                          className={
                            repo.auto_review ? 'text-green-400' : 'text-dark-500'
                          }
                        >
                          {repo.auto_review ? 'On' : 'Off'}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <Link
                            to={`/repositories/${repo.id}`}
                            className="text-gold-400 hover:text-gold-300"
                          >
                            Configure
                          </Link>
                          <button
                            onClick={() => handleDeleteRepository(repo.id)}
                            className="text-red-400 hover:text-red-300"
                          >
                            Delete
                          </button>
                        </div>
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
                  Showing {repositories.length} of {total} repositories
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="secondary"
                    onClick={() => setCurrentPage(currentPage - 1)}
                    disabled={currentPage === 1}
                  >
                    Previous
                  </Button>
                  <div className="flex items-center gap-2">
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
                  <Button
                    variant="secondary"
                    onClick={() => setCurrentPage(currentPage + 1)}
                    disabled={currentPage === totalPages}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      {/* Create Repository Modal */}
      <CreateRepositoryModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onSuccess={() => {
          fetchRepositories();
          setShowCreateModal(false);
        }}
      />
    </div>
  );
}
