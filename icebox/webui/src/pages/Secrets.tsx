import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2, Eye, RotateCcw } from 'lucide-react';
import apiClient from '../services/apiClient.ts';
import type { Secret, ApiResponse, PaginatedResponse, SecretType } from '../types/icebox.ts';
import { useAuth } from '../context/AuthContext.tsx';

const SECRET_TYPES: SecretType[] = [
  'api_key',
  'db_password',
  'token',
  'cloud_credential',
  'service_account',
  'certificate',
  'ssh_key',
];

function TypeBadge({ type }: { type: SecretType }) {
  const colors: Record<SecretType, string> = {
    api_key: 'bg-amber-900/50 text-amber-300',
    db_password: 'bg-sky-900/50 text-sky-300',
    token: 'bg-purple-900/50 text-purple-300',
    cloud_credential: 'bg-emerald-900/50 text-emerald-300',
    service_account: 'bg-blue-900/50 text-blue-300',
    certificate: 'bg-rose-900/50 text-rose-300',
    ssh_key: 'bg-indigo-900/50 text-indigo-300',
    one_time: 'bg-gray-900/50 text-gray-300',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${colors[type] ?? 'bg-slate-700 text-slate-300'}`}>
      {type.replace('_', ' ')}
    </span>
  );
}

interface CreateSecretForm {
  name: string;
  description: string;
  secret_type: SecretType;
  value: string;
}

export default function Secrets() {
  const qc = useQueryClient();
  const { hasScope } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [viewSecret, setViewSecret] = useState<{ id: string; value: string } | null>(null);
  const [form, setForm] = useState<CreateSecretForm>({
    name: '',
    description: '',
    secret_type: 'api_key',
    value: '',
  });

  const { data, isLoading } = useQuery({
    queryKey: ['secrets'],
    queryFn: async () => {
      const res = await apiClient.get<ApiResponse<PaginatedResponse<Secret>>>('/api/v1/secrets');
      return res.data.data!;
    },
  });

  const createMutation = useMutation({
    mutationFn: (payload: CreateSecretForm) => apiClient.post('/api/v1/secrets', payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['secrets'] });
      setShowCreate(false);
      setForm({ name: '', description: '', secret_type: 'api_key', value: '' });
      console.log('[Secrets] Created new secret');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/api/v1/secrets/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secrets'] }),
  });

  const rotateMutation = useMutation({
    mutationFn: ({ id, value }: { id: string; value: string }) =>
      apiClient.post(`/api/v1/secrets/${id}/rotate`, { new_value: value }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secrets'] }),
  });

  const handleViewValue = async (id: string) => {
    const res = await apiClient.get<ApiResponse<{ value: string }>>(`/api/v1/secrets/${id}/value`);
    setViewSecret({ id, value: res.data.data!.value });
  };

  console.log('[Secrets] mounted', { count: data?.total });

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-amber-400">Secrets</h1>
        {hasScope('secrets:write') && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 bg-amber-500 hover:bg-amber-400 text-slate-900 font-semibold px-4 py-2 rounded-lg transition-colors"
            data-testid="create-secret-btn"
          >
            <Plus size={16} />
            New Secret
          </button>
        )}
      </div>

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md relative z-10">
            <h2 className="text-amber-400 font-bold text-lg mb-4">Create Secret</h2>
            <div className="space-y-3">
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
                value={form.secret_type}
                onChange={(e) => setForm({ ...form, secret_type: e.target.value as SecretType })}
              >
                {SECRET_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace('_', ' ')}</option>
                ))}
              </select>
              <textarea
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder-slate-500 font-mono text-sm"
                placeholder="Secret value"
                rows={3}
                value={form.value}
                onChange={(e) => setForm({ ...form, value: e.target.value })}
              />
            </div>
            <div className="flex gap-3 mt-4">
              <button
                onClick={() => createMutation.mutate(form)}
                disabled={!form.name || !form.value || createMutation.isPending}
                className="flex-1 bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-900 font-semibold py-2 rounded-lg transition-colors"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
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

      {/* View value modal */}
      {viewSecret && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 w-full max-w-md relative z-10">
            <h2 className="text-amber-400 font-bold text-lg mb-3">Secret Value</h2>
            <pre className="bg-slate-900 p-3 rounded text-green-400 font-mono text-sm overflow-auto max-h-40">
              {viewSecret.value}
            </pre>
            <button
              onClick={() => setViewSecret(null)}
              className="mt-4 w-full bg-slate-700 hover:bg-slate-600 text-slate-200 py-2 rounded-lg transition-colors"
              data-testid="modal-close"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-slate-400">Loading secrets...</div>
      ) : (
        <div className="space-y-2">
          {(data?.items ?? []).map((secret) => (
            <div
              key={secret.id}
              className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <TypeBadge type={secret.secret_type} />
                <div>
                  <p className="text-slate-200 font-medium">{secret.name}</p>
                  {secret.description && (
                    <p className="text-slate-500 text-xs">{secret.description}</p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {hasScope('secrets:read') && (
                  <button
                    onClick={() => handleViewValue(secret.id)}
                    className="text-slate-400 hover:text-amber-400 transition-colors p-1"
                    title="View value"
                  >
                    <Eye size={16} />
                  </button>
                )}
                {hasScope('secrets:write') && (
                  <button
                    onClick={() => {
                      const val = prompt('New secret value:');
                      if (val) rotateMutation.mutate({ id: secret.id, value: val });
                    }}
                    className="text-slate-400 hover:text-sky-400 transition-colors p-1"
                    title="Rotate"
                  >
                    <RotateCcw size={16} />
                  </button>
                )}
                {hasScope('secrets:delete') && (
                  <button
                    onClick={() => {
                      if (confirm(`Delete "${secret.name}"?`)) deleteMutation.mutate(secret.id);
                    }}
                    className="text-slate-400 hover:text-rose-400 transition-colors p-1"
                    title="Delete"
                  >
                    <Trash2 size={16} />
                  </button>
                )}
              </div>
            </div>
          ))}
          {(data?.items ?? []).length === 0 && (
            <div className="text-slate-500 text-center py-8">No secrets yet.</div>
          )}
        </div>
      )}
    </div>
  );
}
