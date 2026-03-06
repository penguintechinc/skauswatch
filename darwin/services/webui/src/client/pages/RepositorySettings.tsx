import { useState, useEffect } from 'react';
import { repositoriesApi } from '../api/client';
import type { RepositoryConfig } from '../types';
import Card from '../components/Card';
import Button from '../components/Button';

export default function RepositorySettings() {
  const [repositories, setRepositories] = useState<RepositoryConfig[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    access_token: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);

  useEffect(() => {
    const fetchRepositories = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await repositoriesApi.list(page, 20);
        setRepositories(result.items);
        setTotalPages(result.pages);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch repositories');
      } finally {
        setIsLoading(false);
      }
    };

    fetchRepositories();
  }, [page]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleAddRepository = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name || !formData.url || !formData.access_token) {
      alert('Please fill in all fields');
      return;
    }

    setIsSubmitting(true);
    try {
      const newRepo = await repositoriesApi.create({
        name: formData.name,
        url: formData.url,
        access_token: formData.access_token,
      });

      setRepositories((prev) => [newRepo, ...prev]);
      setFormData({ name: '', url: '', access_token: '' });
      setShowForm(false);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to add repository');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleActive = async (repo: RepositoryConfig) => {
    try {
      const updated = await repositoriesApi.update(repo.id, {
        is_active: !repo.is_active,
      });

      setRepositories((prev) =>
        prev.map((r) => (r.id === repo.id ? updated : r))
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update repository');
    }
  };

  const handleTestConnection = async (repo: RepositoryConfig) => {
    try {
      const result = await repositoriesApi.testConnection(repo.id);
      alert(result.message);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Connection test failed');
    }
  };

  const handleDeleteRepository = async (repo: RepositoryConfig) => {
    if (!window.confirm(`Delete repository "${repo.name}"?`)) return;

    try {
      await repositoriesApi.delete(repo.id);
      setRepositories((prev) => prev.filter((r) => r.id !== repo.id));
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete repository');
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Repository Configuration</h1>
        <p className="text-dark-400 mt-1">Manage your GitHub repository credentials</p>
      </div>

      {/* Add Repository Form */}
      {showForm && (
        <Card title="Add Repository" className="mb-6">
          <form onSubmit={handleAddRepository} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Repository Name
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                placeholder="e.g., my-awesome-repo"
                className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Repository URL
              </label>
              <input
                type="url"
                name="url"
                value={formData.url}
                onChange={handleInputChange}
                placeholder="https://github.com/username/repo"
                className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Access Token
              </label>
              <input
                type="password"
                name="access_token"
                value={formData.access_token}
                onChange={handleInputChange}
                placeholder="GitHub personal access token"
                className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
              />
              <p className="text-xs text-dark-400 mt-2">
                Token must have repo scope permissions
              </p>
            </div>

            <div className="flex gap-2">
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? 'Adding...' : 'Add Repository'}
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Repositories List */}
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
      ) : (
        <>
          <div className="mb-6">
            {repositories.length === 0 ? (
              <Card>
                <p className="text-dark-400 text-center py-8">No repositories configured</p>
              </Card>
            ) : (
              <div className="space-y-4">
                {repositories.map((repo) => (
                  <Card key={repo.id} className="hover:border-gold-500 transition-colors">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-lg font-semibold text-gold-400">
                            {repo.name}
                          </h3>
                          <span
                            className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                              repo.is_active
                                ? 'bg-green-900 text-green-200'
                                : 'bg-gray-700 text-gray-300'
                            }`}
                          >
                            {repo.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </div>

                        <p className="text-dark-300 mb-3">{repo.url}</p>

                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-dark-400">Created</span>
                            <p className="text-dark-200">
                              {new Date(repo.created_at).toLocaleDateString()}
                            </p>
                          </div>
                          <div>
                            <span className="text-dark-400">Updated</span>
                            <p className="text-dark-200">
                              {new Date(repo.updated_at).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="ml-4 flex flex-col gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleTestConnection(repo)}
                        >
                          Test
                        </Button>
                        <Button
                          variant={repo.is_active ? 'secondary' : 'secondary'}
                          size="sm"
                          onClick={() => handleToggleActive(repo)}
                        >
                          {repo.is_active ? 'Disable' : 'Enable'}
                        </Button>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleDeleteRepository(repo)}
                          className="text-red-400 hover:bg-red-900"
                        >
                          Delete
                        </Button>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            )}
          </div>

          {!showForm && (
            <Button onClick={() => setShowForm(true)} className="mb-6">
              Add Repository
            </Button>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2">
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
        </>
      )}
    </div>
  );
}
