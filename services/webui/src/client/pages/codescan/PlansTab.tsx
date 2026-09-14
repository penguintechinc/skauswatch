import { useState, useEffect } from 'react';
import { codescanApi } from '../../api/codescan';
import type { CodeScanPlan, CodeScanRepo, CodeScanPlanCreateRequest } from '../../types/codescan';

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-yellow-400 border-yellow-700 bg-yellow-900/20',
  processing: 'text-blue-400 border-blue-700 bg-blue-900/20',
  completed: 'text-green-400 border-green-700 bg-green-900/20',
  failed: 'text-red-400 border-red-700 bg-red-900/20',
};

export default function PlansTab() {
  const [plans, setPlans] = useState<CodeScanPlan[]>([]);
  const [repos, setRepos] = useState<CodeScanRepo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showQueue, setShowQueue] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState<CodeScanPlanCreateRequest>({
    repo_config_id: 0,
    issue_number: undefined,
    issue_url: '',
  });

  const load = async () => {
    try {
      setLoading(true);
      setError(null);
      const [planData, repoData] = await Promise.all([
        codescanApi.listPlans(),
        codescanApi.listRepos(),
      ]);
      setPlans(planData);
      setRepos(repoData);
      if (repoData.length > 0 && form.repo_config_id === 0) {
        setForm((f) => ({ ...f, repo_config_id: repoData[0].id }));
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load plans');
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
      await codescanApi.createPlan(form);
      setShowQueue(false);
      setForm((f) => ({ ...f, issue_url: '', issue_number: undefined }));
      await load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to queue issue plan');
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
      const full = await codescanApi.getPlan(id);
      setPlans((prev) => prev.map((p) => (p.id === id ? full : p)));
    } catch {
      // show what we have
    }
    setExpanded(id);
  };

  if (loading) {
    return <div className="text-dark-400 text-sm">Loading issue plans...</div>;
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded px-4 py-3 text-red-300 text-sm">
          {error}
        </div>
      )}

      <div className="flex items-center justify-between">
        <span className="text-dark-400 text-sm">{plans.length} issue plans</span>
        <button
          onClick={() => setShowQueue(!showQueue)}
          className="px-3 py-1.5 text-sm bg-gold-900/40 text-gold-400 border border-gold-700/50 rounded hover:bg-gold-900/60 transition-colors"
        >
          + Generate Plan
        </button>
      </div>

      {showQueue && (
        <div className="bg-dark-800 border border-dark-700 rounded p-4 space-y-3">
          <h3 className="text-gold-400 text-sm font-medium">Generate Issue Plan</h3>
          <p className="text-dark-400 text-xs">
            CodeScan will analyze the issue and generate an AI-powered implementation plan.
          </p>
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
              <label className="block text-dark-400 text-xs mb-1">Issue Number (optional)</label>
              <input
                type="number"
                placeholder="123"
                value={form.issue_number ?? ''}
                onChange={(e) => setForm({ ...form, issue_number: e.target.value ? Number(e.target.value) : undefined })}
                className="w-full bg-dark-900 border border-dark-600 rounded px-2 py-1.5 text-sm text-dark-100 placeholder-dark-500"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-dark-400 text-xs mb-1">Issue URL (optional)</label>
              <input
                type="url"
                placeholder="https://github.com/org/repo/issues/123"
                value={form.issue_url ?? ''}
                onChange={(e) => setForm({ ...form, issue_url: e.target.value })}
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
              {submitting ? 'Generating...' : 'Generate Plan'}
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

      {plans.length === 0 && !showQueue && (
        <div className="text-center py-12 text-dark-500 text-sm">
          No issue plans yet. Generate a plan from a GitHub or GitLab issue.
        </div>
      )}

      <div className="space-y-2">
        {plans.map((plan) => (
          <div key={plan.id} className="bg-dark-800 border border-dark-700 rounded">
            <button
              onClick={() => loadExpanded(plan.id)}
              className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-dark-750 transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[plan.status] ?? ''}`}>
                  {plan.status}
                </span>
                <div>
                  <div className="text-dark-100 text-sm font-medium">
                    {plan.repo_name ?? `Repo #${plan.repo_config_id}`}
                    {plan.issue_number ? ` — Issue #${plan.issue_number}` : ''}
                  </div>
                  <div className="text-dark-500 text-xs">
                    {new Date(plan.created_at).toLocaleString()}
                    {plan.ai_provider ? ` · ${plan.ai_provider}` : ''}
                  </div>
                </div>
              </div>
              <span className="text-dark-500 text-xs">{expanded === plan.id ? '▲' : '▼'}</span>
            </button>

            {expanded === plan.id && (
              <div className="border-t border-dark-700 px-4 pb-4 pt-3 space-y-3">
                {plan.issue_url && (
                  <div>
                    <a
                      href={plan.issue_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 text-xs hover:underline"
                    >
                      View Issue →
                    </a>
                  </div>
                )}
                {plan.plan_content ? (
                  <div>
                    <div className="text-dark-400 text-xs mb-2 uppercase tracking-wide">Implementation Plan</div>
                    <pre className="bg-dark-900 rounded p-3 text-dark-200 text-sm whitespace-pre-wrap leading-relaxed overflow-auto max-h-96">
                      {plan.plan_content}
                    </pre>
                  </div>
                ) : plan.status === 'pending' || plan.status === 'processing' ? (
                  <div className="text-dark-500 text-sm">Plan is being generated...</div>
                ) : (
                  <div className="text-dark-500 text-sm">No plan content available.</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
