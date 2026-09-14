import { useState, useEffect } from 'react';
import { codescanApi } from '../../api/codescan';
import type { CodeScanRepo, CodeScanRepoCreateRequest } from '../../types/codescan';

export default function ReposTab() {
  const [repos, setRepos] = useState<CodeScanRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState<CodeScanRepoCreateRequest>({
    provider: 'github',
    repo_url: '',
    repo_name: '',
    webhook_secret: '',
    auto_review: false,
    is_active: true,
  });

  const load = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await codescanApi.listRepos();
      setRepos(data);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to load repositories';
      if (msg.includes('403') || msg.includes('license')) {
        setError('CodeScan AI Review requires a CodeScan license. Contact your administrator.');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleAdd = async () => {
    if (!form.repo_url || !form.repo_name) return;
    try {
      setSubmitting(true);
      setError(null);
      await codescanApi.createRepo(form);
      setShowAdd(false);
      setForm({ provider: 'github', repo_url: '', repo_name: '', webhook_secret: '', auto_review: false, is_active: true });
      await load();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to add repository';
      if (msg.includes('limit') || msg.includes('cap') || msg.includes('403')) {
        setError('Repository limit reached (3 repos on community plan). Upgrade to a CodeScan license for unlimited repos.');
      } else {
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this repository configuration?')) return;
    try {
      await codescanApi.deleteRepo(id);
      await load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to delete repository');
    }
  };

  const toggleActive = async (repo: CodeScanRepo) => {
    try {
      await codescanApi.updateRepo(repo.id, { is_active: !repo.is_active });
      await load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to update repository');
    }
  };

  if (loading) {
    return <div className="text-dark-400 text-sm">Loading repositories...</div>;
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded px-4 py-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Cap warning at 3 repos */}
      {repos.length >= 3 && (
        <div className="bg-yellow-900/30 border border-yellow-700 rounded px-4 py-3 text-yellow-300 text-sm">
          Community limit: 3 repositories. Purchase a CodeScan license to add more.
        </div>
      )}

      <div className="flex items-center justify-between">
        <span className="text-dark-400 text-sm">{repos.length} repositories configured</span>
        <button
          onClick={() => setShowAdd(!showAdd)}
          disabled={repos.length >= 3}
          className="px-3 py-1.5 text-sm bg-gold-900/40 text-gold-400 border border-gold-700/50 rounded hover:bg-gold-900/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          + Add Repository
        </button>
      </div>

      {showAdd && (
        <div className="bg-dark-800 border border-dark-700 rounded p-4 space-y-3">
          <h3 className="text-gold-400 text-sm font-medium">Add Repository</h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-dark-400 text-xs mb-1">Provider</label>
              <select
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value as 'github' | 'gitlab' })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100"
              >
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
              </select>
            </div>
            <div>
              <label className="block text-dark-400 text-xs mb-1">Repository Name</label>
              <input
                type="text"
                placeholder="org/repo-name"
                value={form.repo_name}
                onChange={(e) => setForm({ ...form, repo_name: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-dark-400 text-xs mb-1">Repository URL</label>
              <input
                type="url"
                placeholder="https://github.com/org/repo"
                value={form.repo_url}
                onChange={(e) => setForm({ ...form, repo_url: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-dark-400 text-xs mb-1">Webhook Secret (optional)</label>
              <input
                type="password"
                placeholder="Leave blank to skip webhook verification"
                value={form.webhook_secret ?? ''}
                onChange={(e) => setForm({ ...form, webhook_secret: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
            <div className="col-span-2 flex items-center gap-2">
              <input
                type="checkbox"
                id="auto_review"
                checked={form.auto_review}
                onChange={(e) => setForm({ ...form, auto_review: e.target.checked })}
                className="accent-gold-400"
              />
              <label htmlFor="auto_review" className="text-dark-300 text-sm">
                Auto-review pull requests on webhook
              </label>
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={handleAdd}
              disabled={submitting || !form.repo_url || !form.repo_name}
              className="px-4 py-1.5 text-sm bg-gold-600 text-dark-950 rounded hover:bg-gold-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {submitting ? 'Adding...' : 'Add'}
            </button>
            <button
              onClick={() => setShowAdd(false)}
              className="px-4 py-1.5 text-sm border border-dark-600 text-dark-400 rounded hover:border-dark-500 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {repos.length === 0 && !showAdd && (
        <div className="text-center py-12 text-dark-500 text-sm">
          No repositories configured. Add one to get started.
        </div>
      )}

      <div className="space-y-2">
        {repos.map((repo) => (
          <div
            key={repo.id}
            className="bg-dark-800 border border-dark-700 rounded p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <span className={`text-xs px-2 py-0.5 rounded border ${
                repo.provider === 'github'
                  ? 'text-green-400 border-green-700 bg-green-900/20'
                  : 'text-orange-400 border-orange-700 bg-orange-900/20'
              }`}>
                {repo.provider}
              </span>
              <div>
                <div className="text-dark-100 text-sm font-medium">{repo.repo_name}</div>
                <div className="text-dark-500 text-xs">{repo.repo_url}</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {repo.auto_review && (
                <span className="text-xs text-blue-400 border border-blue-700 bg-blue-900/20 px-2 py-0.5 rounded">
                  auto-review
                </span>
              )}
              <button
                onClick={() => toggleActive(repo)}
                className={`text-xs px-2 py-0.5 rounded border transition-colors ${
                  repo.is_active
                    ? 'text-gold-400 border-gold-700 bg-gold-900/20 hover:bg-gold-900/40'
                    : 'text-dark-500 border-dark-600 hover:border-dark-500'
                }`}
              >
                {repo.is_active ? 'Active' : 'Inactive'}
              </button>
              <button
                onClick={() => handleDelete(repo.id)}
                className="text-xs text-red-500 hover:text-red-400 transition-colors"
              >
                Remove
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
