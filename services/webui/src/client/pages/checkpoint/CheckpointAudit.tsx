import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { CheckpointAuditEntry, CheckpointPaginatedResponse } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(ts: string): string {
  return new Date(ts).toLocaleString();
}

function exportCSV(entries: CheckpointAuditEntry[]): void {
  const headers = ['ID', 'Event Type', 'Actor UUID', 'Actor IP', 'Target UUID', 'Target Type', 'Client ID', 'Scopes', 'Created At'];
  const rows = entries.map(e => [
    e.id,
    e.event_type,
    e.actor_uuid ?? '',
    e.actor_ip ?? '',
    e.target_uuid ?? '',
    e.target_type ?? '',
    e.client_id ?? '',
    e.scopes ?? '',
    e.created_at,
  ]);
  const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `checkpoint-audit-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Detail row
// ---------------------------------------------------------------------------

function DetailRow({ entry }: { entry: CheckpointAuditEntry }) {
  return (
    <tr className="bg-dark-900 border-b border-dark-800">
      <td colSpan={6} className="px-4 py-3">
        <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-2 text-xs">
          <div>
            <dt className="text-dark-400">ID</dt>
            <dd className="font-mono text-dark-200 break-all">{entry.id}</dd>
          </div>
          <div>
            <dt className="text-dark-400">Actor UUID</dt>
            <dd className="font-mono text-dark-200 break-all">{entry.actor_uuid ?? '—'}</dd>
          </div>
          <div>
            <dt className="text-dark-400">Actor IP</dt>
            <dd className="font-mono text-dark-200">{entry.actor_ip ?? '—'}</dd>
          </div>
          <div>
            <dt className="text-dark-400">Target UUID</dt>
            <dd className="font-mono text-dark-200 break-all">{entry.target_uuid ?? '—'}</dd>
          </div>
          <div>
            <dt className="text-dark-400">Target Type</dt>
            <dd className="text-dark-200">{entry.target_type ?? '—'}</dd>
          </div>
          <div>
            <dt className="text-dark-400">Client ID</dt>
            <dd className="font-mono text-dark-200 break-all">{entry.client_id ?? '—'}</dd>
          </div>
          {entry.scopes && (
            <div className="col-span-2 sm:col-span-3">
              <dt className="text-dark-400">Scopes</dt>
              <dd className="font-mono text-dark-200">{entry.scopes}</dd>
            </div>
          )}
        </dl>
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const PER_PAGE = 50;

export default function CheckpointAudit() {
  const { modules } = useModules();
  const [entries, setEntries] = useState<CheckpointAuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Filters
  const [filterEventType, setFilterEventType] = useState('');
  const [filterActorIp, setFilterActorIp] = useState('');
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');

  const fetchAudit = useCallback(async (pg: number) => {
    console.log('[CheckpointAudit] Fetching audit log', { page: pg, filterEventType, filterActorIp });
    setIsLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = {
        page: pg,
        per_page: PER_PAGE,
      };
      if (filterEventType) params['event_type'] = filterEventType;
      if (filterActorIp) params['actor_ip'] = filterActorIp;
      if (filterDateFrom) params['date_from'] = filterDateFrom;
      if (filterDateTo) params['date_to'] = filterDateTo;

      const res = await api.get<CheckpointPaginatedResponse<CheckpointAuditEntry>>('/checkpoint/audit', { params });
      const data = res.data;
      if (data && typeof data === 'object' && 'items' in data) {
        setEntries(data.items);
        setTotal(data.total);
      } else {
        setEntries(data as unknown as CheckpointAuditEntry[]);
        setTotal((data as unknown as CheckpointAuditEntry[]).length);
      }
    } catch (err: unknown) {
      setError('Failed to load audit log.');
      console.error('[CheckpointAudit] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, [filterEventType, filterActorIp, filterDateFrom, filterDateTo]);

  useEffect(() => {
    console.log('[CheckpointAudit] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchAudit(1);
    setPage(1);
  }, [fetchAudit, modules.checkpoint]);

  const handleApplyFilters = () => {
    setPage(1);
    setExpandedId(null);
    void fetchAudit(1);
  };

  const handleClearFilters = () => {
    setFilterEventType('');
    setFilterActorIp('');
    setFilterDateFrom('');
    setFilterDateTo('');
  };

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
    setExpandedId(null);
    void fetchAudit(newPage);
  };

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  return (
    <div>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">Audit Log</h1>
          <p className="text-dark-400 mt-1">Identity and access events.</p>
        </div>
        <button
          data-testid="export-csv-btn"
          className="btn btn-secondary text-sm"
          onClick={() => exportCSV(entries)}
          disabled={entries.length === 0}
        >
          ↓ Export CSV
        </button>
      </div>

      {/* Filter Bar */}
      <Card className="mb-5">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Event Type</label>
            <input
              data-testid="filter-event-type"
              type="text"
              className="input w-full text-sm"
              placeholder="e.g. login, token_issued"
              value={filterEventType}
              onChange={(e) => setFilterEventType(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">Actor IP</label>
            <input
              data-testid="filter-actor-ip"
              type="text"
              className="input w-full text-sm"
              placeholder="e.g. 192.168.1.1"
              value={filterActorIp}
              onChange={(e) => setFilterActorIp(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">From (date)</label>
            <input
              data-testid="filter-date-from"
              type="date"
              className="input w-full text-sm"
              value={filterDateFrom}
              onChange={(e) => setFilterDateFrom(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">To (date)</label>
            <input
              data-testid="filter-date-to"
              type="date"
              className="input w-full text-sm"
              value={filterDateTo}
              onChange={(e) => setFilterDateTo(e.target.value)}
            />
          </div>
        </div>
        <div className="flex gap-2 mt-3">
          <button
            data-testid="apply-filters-btn"
            className="btn btn-primary text-sm"
            onClick={handleApplyFilters}
          >
            Apply Filters
          </button>
          <button
            data-testid="clear-filters-btn"
            className="btn btn-secondary text-sm"
            onClick={handleClearFilters}
          >
            Clear
          </button>
        </div>
      </Card>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading audit log…</div>
      ) : entries.length === 0 ? (
        <Card>
          <div className="text-dark-400 py-4 text-center">No audit events found.</div>
        </Card>
      ) : (
        <>
          <div className="text-xs text-dark-400 mb-2">
            Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, total)} of {total} events
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left border-b border-dark-700">
                  <th className="py-2 pr-4 text-dark-400 font-medium">Event Type</th>
                  <th className="py-2 pr-4 text-dark-400 font-medium">Actor IP</th>
                  <th className="py-2 pr-4 text-dark-400 font-medium">Target</th>
                  <th className="py-2 pr-4 text-dark-400 font-medium">Client</th>
                  <th className="py-2 pr-4 text-dark-400 font-medium">Timestamp</th>
                  <th className="py-2 pr-4 text-dark-400 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <>
                    <tr
                      key={entry.id}
                      data-testid={`audit-row-${i}`}
                      className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors"
                    >
                      <td className="py-2 pr-4 font-mono text-xs text-gold-400">{entry.event_type}</td>
                      <td className="py-2 pr-4 font-mono text-xs text-dark-400">{entry.actor_ip ?? '—'}</td>
                      <td className="py-2 pr-4 text-xs text-dark-400 max-w-xs truncate">
                        {entry.target_type ? `${entry.target_type}` : '—'}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs text-dark-400 max-w-xs truncate">{entry.client_id ?? '—'}</td>
                      <td className="py-2 pr-4 text-xs text-dark-400 whitespace-nowrap">{formatTimestamp(entry.created_at)}</td>
                      <td className="py-2 pr-4">
                        <button
                          data-testid={`expand-row-${i}`}
                          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                          onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                        >
                          {expandedId === entry.id ? '▲ Hide' : '▼ Show'}
                        </button>
                      </td>
                    </tr>
                    {expandedId === entry.id && <DetailRow key={`detail-${entry.id}`} entry={entry} />}
                  </>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center gap-2 mt-4 justify-end">
              <button
                data-testid="prev-page-btn"
                className="btn btn-secondary text-sm px-3 py-1"
                onClick={() => handlePageChange(page - 1)}
                disabled={page <= 1}
              >
                ← Prev
              </button>
              <span className="text-sm text-dark-400">
                Page {page} of {totalPages}
              </span>
              <button
                data-testid="next-page-btn"
                className="btn btn-secondary text-sm px-3 py-1"
                onClick={() => handlePageChange(page + 1)}
                disabled={page >= totalPages}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
