import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Play, Trash2, CheckCircle, XCircle } from 'lucide-react';
import apiIceBox from '../../lib/apiIceBox';
import type {
  CloudIntegration,
  CloudProvider,
  SyncDirection,
  ApiResponse,
  PaginatedResponse,
} from '../../types/icebox';
import { useAuth } from '../../context/IceBoxAuthContext';

const PROVIDER_LABELS: Record<CloudProvider, string> = {
  aws: 'AWS Secrets Manager',
  azure: 'Azure Key Vault',
  gcp: 'GCP Secret Manager',
  oracle: 'Oracle OCI Vault',
  kubernetes: 'Kubernetes Secrets',
};

const DIRECTION_LABELS: Record<SyncDirection, string> = {
  icebox_to_cloud: 'IceBox → Cloud',
  cloud_to_icebox: 'Cloud → IceBox',
  bidirectional: 'Bidirectional',
};

interface CreateIntegrationForm {
  provider: CloudProvider;
  name: string;
  description: string;
  sync_direction: SyncDirection;
}

export default function CloudSync() {
  const qc = useQueryClient();
  const { hasScope } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateIntegrationForm>({
    provider: 'aws',
    name: '',
    description: '',
    sync_direction: 'bidirectional',
  });

  const { data, isLoading } = useQuery({
    queryKey: ['sync-integrations'],
    queryFn: async () => {
      const res = await apiIceBox.get<ApiResponse<PaginatedResponse<CloudIntegration>>>(
        '/api/v1/sync/integrations',
      );
      return res.data.data!;
    },
  });

  const createMutation = useMutation({
    mutationFn: (payload: CreateIntegrationForm) =>
      apiIceBox.post('/api/v1/sync/integrations', payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-integrations'] });
      setShowCreate(false);
      setForm({ provider: 'aws', name: '', description: '', sync_direction: 'bidirectional' });
    },
  });

  const triggerMutation = useMutation({
    mutationFn: (id: string) =>
      apiIceBox.post(`/api/v1/sync/integrations/${id}/trigger`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sync-integrations'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiIceBox.delete(`/api/v1/sync/integrations/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sync-integrations'] }),
  });

  console.log('[CloudSync] mounted', { count: data?.total });

  const canAdmin = hasScope('sync:admin');

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-amber-400">Cloud Sync</h1>
        {canAdmin && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 bg-amber-500 hover:bg-amber-400 text-slate-900 font-semibold px-4 py-2 rounded-lg transition-colors"
          >
            <Plus size={16} />
            Add Integration
          </button>
        )}
      </div>

      {showCreate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md relative z-10">
            <h2 className="text-amber-400 font-bold text-lg mb-4">Add Cloud Integration</h2>
            <div className="space-y-3">
              <select
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200"
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value as CloudProvider })}
              >
                {(Object.keys(PROVIDER_LABELS) as CloudProvider[]).map((p) => (
                  <option key={p} value={p}>{PROVIDER_LABELS[p]}</option>
                ))}
              </select>
              <input
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder-slate-500"
                placeholder="Name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
              <input
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder-slate-500"
                placeholder="Description"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
              <select
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200"
                value={form.sync_direction}
                onChange={(e) =>
                  setForm({ ...form, sync_direction: e.target.value as SyncDirection })
                }
              >
                {(Object.keys(DIRECTION_LABELS) as SyncDirection[]).map((d) => (
                  <option key={d} value={d}>{DIRECTION_LABELS[d]}</option>
                ))}
              </select>
            </div>
            <div className="flex gap-3 mt-4">
              <button
                onClick={() => createMutation.mutate(form)}
                disabled={!form.name || createMutation.isPending}
                className="flex-1 bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-900 font-semibold py-2 rounded-lg transition-colors"
              >
                {createMutation.isPending ? 'Adding...' : 'Add'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-200 py-2 rounded-lg transition-colors"
                data-testid="modal-close"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-slate-400">Loading integrations...</div>
      ) : (
        <div className="space-y-3">
          {(data?.items ?? []).map((intg) => (
            <div
              key={intg.id}
              className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                {intg.enabled ? (
                  <CheckCircle size={16} className="text-emerald-400" />
                ) : (
                  <XCircle size={16} className="text-slate-500" />
                )}
                <div>
                  <p className="text-slate-200 font-medium">{intg.name}</p>
                  <p className="text-slate-500 text-xs">
                    {PROVIDER_LABELS[intg.provider]} · {DIRECTION_LABELS[intg.sync_direction]}
                    {intg.last_sync_at &&
                      ` · Last sync: ${new Date(intg.last_sync_at).toLocaleString()}`}
                  </p>
                </div>
              </div>
              {canAdmin && (
                <div className="flex gap-2">
                  <button
                    onClick={() => triggerMutation.mutate(intg.id)}
                    className="text-slate-400 hover:text-sky-400 transition-colors p-1"
                    title="Trigger sync"
                  >
                    <Play size={16} />
                  </button>
                  <button
                    onClick={() => {
                      if (confirm(`Remove "${intg.name}"?`)) deleteMutation.mutate(intg.id);
                    }}
                    className="text-slate-400 hover:text-rose-400 transition-colors p-1"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              )}
            </div>
          ))}
          {(data?.items ?? []).length === 0 && (
            <div className="text-slate-500 text-center py-8">No cloud integrations configured.</div>
          )}
        </div>
      )}
    </div>
  );
}
