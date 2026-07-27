import { useState, useEffect } from 'react';
import { codescanApi } from '../../api/codescan';
import type { CodeScanReview, CodeScanRepo, CodeScanReviewCreateRequest } from '../../types/codescan';

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-yellow-400 border-yellow-700 bg-yellow-900/20',
  processing: 'text-blue-400 border-blue-700 bg-blue-900/20',
  completed: 'text-green-400 border-green-700 bg-green-900/20',
  failed: 'text-red-400 border-red-700 bg-red-900/20',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-dark-400',
};

export default function ReviewsTab() {
  const [reviews, setReviews] = useState<CodeScanReview[]>([]);
  const [repos, setRepos] = useState<CodeScanRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showQueue, setShowQueue] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState<CodeScanReviewCreateRequest>({
    repo_config_id: 0,
    pr_url: '',
    pr_number: undefined,
  });

  const load = async () => {
    try {
      setLoading(true);
      setError(null);
      const [reviewData, repoData] = await Promise.all([
        codescanApi.listReviews(),
        codescanApi.listRepos(),
      ]);
      setReviews(reviewData);
      setRepos(repoData);
      if (repoData.length > 0 && form.repo_config_id === 0) {
        setForm((f) => ({ ...f, repo_config_id: repoData[0].id }));
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load reviews');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleQueue = async () => {
    if (!form.repo_config_id) return;
    try {
      setSubmitting(true);
      setError(null);
      await codescanApi.createReview(form);
      setShowQueue(false);
      setForm((f) => ({ ...f, pr_url: '', pr_number: undefined }));
      await load();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to queue review';
      if (msg.includes('limit') || msg.includes('cap') || msg.includes('403')) {
        setError('Daily review limit reached (10/day on community plan). Upgrade to a CodeScan license for unlimited reviews.');
      } else {
        setError(msg);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const loadExpanded = async (id: number) => {
    if (expanded === id) {
      setExpanded(null);
      return;
    }
    try {
      const full = await codescanApi.getReview(id);
      setReviews((prev) => prev.map((r) => (r.id === id ? full : r)));
      setExpanded(id);
    } catch {
      setExpanded(id);
    }
  };

  if (loading) {
    return <div className="text-dark-400 text-sm">Loading reviews...</div>;
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded px-4 py-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      <div className="flex items-center justify-between">
        <span className="text-dark-400 text-sm">{reviews.length} reviews</span>
        <button
          onClick={() => setShowQueue(!showQueue)}
          className="px-3 py-1.5 text-sm bg-gold-900/40 text-gold-400 border border-gold-700/50 rounded hover:bg-gold-900/60 transition-colors"
        >
          + Queue Review
        </button>
      </div>

      {showQueue && (
        <div className="bg-dark-800 border border-dark-700 rounded p-4 space-y-3">
          <h3 className="text-gold-400 text-sm font-medium">Queue Code Review</h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-dark-400 text-xs mb-1">Repository</label>
              <select
                value={form.repo_config_id}
                onChange={(e) => setForm({ ...form, repo_config_id: Number(e.target.value) })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100"
              >
                {repos.map((r) => (
                  <option key={r.id} value={r.id}>{r.repo_name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-dark-400 text-xs mb-1">PR Number (optional)</label>
              <input
                type="number"
                placeholder="42"
                value={form.pr_number ?? ''}
                onChange={(e) => setForm({ ...form, pr_number: e.target.value ? Number(e.target.value) : undefined })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-dark-400 text-xs mb-1">PR URL (optional)</label>
              <input
                type="url"
                placeholder="https://github.com/org/repo/pull/42"
                value={form.pr_url ?? ''}
                onChange={(e) => setForm({ ...form, pr_url: e.target.value })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={handleQueue}
              disabled={submitting || !form.repo_config_id}
              className="px-4 py-1.5 text-sm bg-gold-600 text-dark-950 rounded hover:bg-gold-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {submitting ? 'Queuing...' : 'Queue Review'}
            </button>
            <button
              onClick={() => setShowQueue(false)}
              className="px-4 py-1.5 text-sm border border-dark-600 text-dark-400 rounded hover:border-dark-500 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {reviews.length === 0 && !showQueue && (
        <div className="text-center py-12 text-dark-500 text-sm">
          No reviews yet. Queue a code review to get started.
        </div>
      )}

      <div className="space-y-2">
        {reviews.map((review) => (
          <div key={review.id} className="bg-dark-800 border border-dark-700 rounded">
            <button
              onClick={() => loadExpanded(review.id)}
              className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-dark-750 transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[review.status] ?? ''}`}>
                  {review.status}
                </span>
                <div>
                  <div className="text-dark-100 text-sm font-medium">
                    {review.repo_name ?? `Repo #${review.repo_config_id}`}
                    {review.pr_number ? ` — PR #${review.pr_number}` : ''}
                  </div>
                  <div className="text-dark-500 text-xs">
                    {new Date(review.created_at).toLocaleString()}
                    {review.ai_provider && ` · ${review.ai_provider}/${review.model}`}
                  </div>
                </div>
              </div>
              <span className="text-dark-500 text-xs">{expanded === review.id ? '▲' : '▼'}</span>
            </button>

            {expanded === review.id && (
              <div className="border-t border-dark-700 px-4 pb-4 pt-3 space-y-3">
                {review.summary && (
                  <div>
                    <div className="text-dark-400 text-xs mb-1 uppercase tracking-wide">Summary</div>
                    <div className="text-dark-200 text-sm leading-relaxed">{review.summary}</div>
                  </div>
                )}
                {review.pr_url && (
                  <div>
                    <a
                      href={review.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 text-xs hover:underline"
                    >
                      View Pull Request →
                    </a>
                  </div>
                )}
                {review.comments && review.comments.length > 0 && (
                  <div>
                    <div className="text-dark-400 text-xs mb-2 uppercase tracking-wide">
                      Comments ({review.comments.length})
                    </div>
                    <div className="space-y-2">
                      {review.comments.map((c) => (
                        <div key={c.id} className="bg-dark-900 rounded p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`text-xs font-medium ${SEVERITY_COLORS[c.severity] ?? ''}`}>
                              {c.severity}
                            </span>
                            <span className="text-dark-500 text-xs">{c.file_path}{c.line_number ? `:${c.line_number}` : ''}</span>
                          </div>
                          <div className="text-dark-200 text-sm">{c.comment}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {review.status === 'completed' && (!review.comments || review.comments.length === 0) && (
                  <div className="text-dark-500 text-sm">No review comments generated.</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
