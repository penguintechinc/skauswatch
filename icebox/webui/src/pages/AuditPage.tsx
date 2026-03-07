import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search } from 'lucide-react';
import apiClient from '../services/apiClient.ts';
import type { AuditEntry, ApiResponse, PaginatedResponse } from '../types/icebox.ts';

const ACTION_COLORS: Record<string, string> = {
  create: 'text-emerald-400',
  read: 'text-sky-400',
  update: 'text-amber-400',
  delete: 'text-rose-400',
  rotate: 'text-purple-400',
  approve: 'text-emerald-400',
  reject: 'text-rose-400',
  view: 'text-sky-400',
};

function actionColor(action: string): string {
  for (const [key, color] of Object.entries(ACTION_COLORS)) {
    if (action.includes(key)) return color;
  }
  return 'text-slate-400';
}

export default function AuditPage() {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['audit-log', page, search],
    queryFn: async () => {
      const params = new URLSearchParams({ page: String(page), per_page: '25' });
      if (search) params.set('action', search);
      const res = await apiClient.get<ApiResponse<PaginatedResponse<AuditEntry>>>(
        `/api/v1/audit/log?${params}`,
      );
      return res.data.data!;
    },
  });

  console.log('[AuditPage] mounted', { page, search });

  const totalPages = data ? Math.ceil(data.total / 25) : 1;

  return (
    <div>
      <h1 className="text-2xl font-bold text-amber-400 mb-6">Audit Log</h1>

      {/* Search */}
      <div className="relative mb-4">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          className="w-full bg-slate-800 border border-slate-700 rounded pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500"
          placeholder="Filter by action..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
      </div>

      {isLoading ? (
        <div className="text-slate-400">Loading audit log...</div>
      ) : (
        <>
          <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left px-4 py-2 text-slate-400 font-medium">Time</th>
                  <th className="text-left px-4 py-2 text-slate-400 font-medium">Actor</th>
                  <th className="text-left px-4 py-2 text-slate-400 font-medium">Action</th>
                  <th className="text-left px-4 py-2 text-slate-400 font-medium">Resource</th>
                  <th className="text-left px-4 py-2 text-slate-400 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {(data?.items ?? []).map((entry, i) => (
                  <tr
                    key={entry.id}
                    className={`border-b border-slate-700/50 ${i % 2 === 0 ? '' : 'bg-slate-800/50'}`}
                  >
                    <td className="px-4 py-2 text-slate-500 whitespace-nowrap">
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-slate-300 font-mono text-xs">
                      {entry.actor_id.slice(0, 8)}…
                    </td>
                    <td className={`px-4 py-2 font-medium ${actionColor(entry.action)}`}>
                      {entry.action}
                    </td>
                    <td className="px-4 py-2 text-slate-400">
                      {entry.resource_type}
                      {entry.resource_id && (
                        <span className="text-slate-500 ml-1 font-mono text-xs">
                          {entry.resource_id.slice(0, 8)}…
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-500">{entry.ip_address ?? '—'}</td>
                  </tr>
                ))}
                {(data?.items ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                      No audit entries.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="text-slate-400 hover:text-amber-400 disabled:opacity-40 transition-colors px-3 py-1 text-sm"
              >
                Previous
              </button>
              <span className="text-slate-500 text-sm">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="text-slate-400 hover:text-amber-400 disabled:opacity-40 transition-colors px-3 py-1 text-sm"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
