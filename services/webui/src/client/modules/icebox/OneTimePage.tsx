import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Copy, CheckCircle, Clock } from 'lucide-react';
import apiIceBox from '../../lib/apiIceBox';
import type { OneTimeSecret, ApiResponse, PaginatedResponse } from '../../types/icebox';
import { useAuth } from '../../context/IceBoxAuthContext';

export default function OneTimePage() {
  const { hasScope } = useAuth();
  const [value, setValue] = useState('');
  const [ttl, setTtl] = useState(3600);
  const [created, setCreated] = useState<{ url_token: string; view_url: string; expires_at: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['one-time-secrets'],
    queryFn: async () => {
      const res = await apiIceBox.get<ApiResponse<PaginatedResponse<OneTimeSecret>>>(
        '/api/v1/one-time-secrets',
      );
      return res.data.data!;
    },
  });

  const createMutation = useMutation({
    mutationFn: (payload: { value: string; ttl_seconds: number }) =>
      apiIceBox.post<ApiResponse<{ url_token: string; view_url: string; expires_at: string }>>(
        '/api/v1/one-time-secrets',
        payload,
      ),
    onSuccess: (res) => {
      setCreated(res.data.data!);
      setValue('');
      refetch();
      console.log('[OneTimePage] Created one-time secret');
    },
  });

  const handleCopy = () => {
    if (!created) return;
    navigator.clipboard.writeText(window.location.origin + created.view_url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  console.log('[OneTimePage] mounted', { count: data?.total });

  return (
    <div>
      <h1 className="text-2xl font-bold text-amber-400 mb-6">One-Time Secrets</h1>

      {hasScope('secrets:write') && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-5 mb-6">
          <h2 className="text-amber-400 font-semibold mb-4">Create One-Time Secret</h2>
          <div className="space-y-3">
            <textarea
              className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder-slate-500 font-mono text-sm"
              placeholder="Secret value (visible only once after sharing)"
              rows={4}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <div className="flex items-center gap-3">
              <label className="text-slate-400 text-sm">Expires in:</label>
              <select
                className="bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 text-sm"
                value={ttl}
                onChange={(e) => setTtl(Number(e.target.value))}
              >
                <option value={3600}>1 hour</option>
                <option value={86400}>24 hours</option>
                <option value={604800}>7 days</option>
              </select>
            </div>
            <button
              onClick={() => createMutation.mutate({ value, ttl_seconds: ttl })}
              disabled={!value || createMutation.isPending}
              className="bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-900 font-semibold px-4 py-2 rounded-lg transition-colors"
            >
              {createMutation.isPending ? 'Creating...' : 'Create & Get Link'}
            </button>
          </div>

          {created && (
            <div className="mt-4 bg-slate-900 border border-emerald-800 rounded-lg p-4">
              <p className="text-emerald-400 font-semibold mb-2">Share this link (one view only):</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-amber-300 text-sm break-all">
                  {window.location.origin + created.view_url}
                </code>
                <button
                  onClick={handleCopy}
                  className="text-slate-400 hover:text-amber-400 transition-colors p-1"
                  title="Copy"
                >
                  {copied ? <CheckCircle size={16} className="text-emerald-400" /> : <Copy size={16} />}
                </button>
              </div>
              <p className="text-slate-500 text-xs mt-2">
                Expires: {new Date(created.expires_at).toLocaleString()}
              </p>
            </div>
          )}
        </div>
      )}

      <h2 className="text-amber-400 font-semibold mb-3">Recent One-Time Secrets</h2>
      {isLoading ? (
        <div className="text-slate-400">Loading...</div>
      ) : (
        <div className="space-y-2">
          {(data?.items ?? []).map((ots) => (
            <div
              key={ots.id}
              className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                {ots.viewed_at ? (
                  <CheckCircle size={16} className="text-emerald-400" />
                ) : (
                  <Clock size={16} className="text-amber-400" />
                )}
                <div>
                  <p className="text-slate-400 text-sm">
                    {ots.viewed_at
                      ? `Viewed: ${new Date(ots.viewed_at).toLocaleString()}`
                      : 'Pending view'}
                  </p>
                  <p className="text-slate-500 text-xs">
                    Expires: {new Date(ots.expires_at).toLocaleString()}
                  </p>
                </div>
              </div>
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  ots.viewed_at
                    ? 'bg-emerald-900/50 text-emerald-300'
                    : 'bg-amber-900/50 text-amber-300'
                }`}
              >
                {ots.viewed_at ? 'consumed' : 'pending'}
              </span>
            </div>
          ))}
          {(data?.items ?? []).length === 0 && (
            <div className="text-slate-500 text-center py-8">No one-time secrets yet.</div>
          )}
        </div>
      )}
    </div>
  );
}
