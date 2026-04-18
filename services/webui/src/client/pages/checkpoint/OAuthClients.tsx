import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { OAuthClient, OAuthClientCreated } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function GrantBadge({ grant }: { grant: string }) {
  const colors: Record<string, string> = {
    authorization_code: 'bg-blue-900/50 text-blue-400 border border-blue-700',
    client_credentials: 'bg-purple-900/50 text-purple-400 border border-purple-700',
    refresh_token: 'bg-green-900/50 text-green-400 border border-green-700',
    device_code: 'bg-yellow-900/50 text-yellow-400 border border-yellow-700',
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${colors[grant] ?? 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
      {grant.replace(/_/g, ' ')}
    </span>
  );
}

// ---------------------------------------------------------------------------
// New Client Secret Display (show-once modal)
// ---------------------------------------------------------------------------

interface SecretDisplayProps {
  client_id: string;
  client_secret: string;
  onClose: () => void;
}

function SecretDisplay({ client_id, client_secret, onClose }: SecretDisplayProps) {
  const [copiedId, setCopiedId] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);

  const copy = async (text: string, setCopied: (b: boolean) => void) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog" aria-modal="true">
      <div className="bg-dark-800 border border-yellow-700 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold text-yellow-400 mb-2">Save Your Client Secret</h2>
        <p className="text-sm text-dark-300 mb-4">
          The client secret is shown only once. Copy it now — it cannot be retrieved again.
        </p>
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-dark-400 mb-1">Client ID</label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-dark-900 border border-dark-700 rounded p-2 font-mono text-gold-400 break-all">
                {client_id}
              </code>
              <button
                data-testid="copy-client-id"
                onClick={() => void copy(client_id, setCopiedId)}
                className="btn btn-secondary text-xs px-2 py-1"
              >
                {copiedId ? '✓' : 'Copy'}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs text-dark-400 mb-1">Client Secret</label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs bg-dark-900 border border-dark-700 rounded p-2 font-mono text-yellow-300 break-all">
                {client_secret}
              </code>
              <button
                data-testid="copy-client-secret"
                onClick={() => void copy(client_secret, setCopiedSecret)}
                className="btn btn-secondary text-xs px-2 py-1"
              >
                {copiedSecret ? '✓' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
        <button
          data-testid="secret-display-close"
          className="btn btn-primary w-full mt-4"
          onClick={onClose}
        >
          I've saved the secret
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create Client Modal
// ---------------------------------------------------------------------------

interface CreateClientForm {
  name: string;
  description: string;
  redirect_uris: string;
  allowed_scopes: string;
  grant_types: string[];
  require_pkce: boolean;
}

const GRANT_OPTIONS = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'client_credentials', label: 'Client Credentials' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'device_code', label: 'Device Code' },
];

interface CreateClientModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (created: OAuthClientCreated) => void;
}

function CreateClientModal({ isOpen, onClose, onCreated }: CreateClientModalProps) {
  const [form, setForm] = useState<CreateClientForm>({
    name: '',
    description: '',
    redirect_uris: '',
    allowed_scopes: 'openid profile email',
    grant_types: ['authorization_code', 'refresh_token'],
    require_pkce: true,
  });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const toggleGrant = (grant: string) => {
    setForm((f) => ({
      ...f,
      grant_types: f.grant_types.includes(grant)
        ? f.grant_types.filter((g) => g !== grant)
        : [...f.grant_types, grant],
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name) { setError('Name is required.'); return; }
    if (form.grant_types.length === 0) { setError('At least one grant type is required.'); return; }
    console.log('[OAuthClients:CreateClientModal] Submitting', { name: form.name });
    setSubmitting(true);
    setError(null);
    try {
      const payload = {
        ...form,
        redirect_uris: form.redirect_uris.split('\n').map((u) => u.trim()).filter(Boolean),
      };
      const res = await api.post<OAuthClientCreated>('/checkpoint/clients', payload);
      onCreated(res.data);
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create client';
      setError(msg);
      console.error('[OAuthClients:CreateClientModal] Error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true">
      <div className="bg-dark-800 border border-dark-600 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold text-gold-400 mb-4">New OAuth2 Client</h2>
        {error && <div className="mb-3 text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Name</label>
            <input data-testid="client-name" type="text" className="input w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Description</label>
            <input data-testid="client-description" type="text" className="input w-full" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Redirect URIs (one per line)</label>
            <textarea
              data-testid="client-redirect-uris"
              className="input w-full h-20 font-mono text-xs resize-y"
              value={form.redirect_uris}
              onChange={(e) => setForm({ ...form, redirect_uris: e.target.value })}
              placeholder="https://app.example.com/callback"
            />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Allowed Scopes (space-separated)</label>
            <input data-testid="client-scopes" type="text" className="input w-full" value={form.allowed_scopes} onChange={(e) => setForm({ ...form, allowed_scopes: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-2">Grant Types</label>
            <div className="flex flex-wrap gap-2">
              {GRANT_OPTIONS.map((g) => (
                <label key={g.value} className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    data-testid={`grant-type-${g.value}`}
                    type="checkbox"
                    checked={form.grant_types.includes(g.value)}
                    onChange={() => toggleGrant(g.value)}
                  />
                  <span className="text-sm text-dark-300">{g.label}</span>
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                data-testid="client-require-pkce"
                type="checkbox"
                checked={form.require_pkce}
                onChange={(e) => setForm({ ...form, require_pkce: e.target.checked })}
              />
              <span className="text-sm text-dark-300">Require PKCE</span>
            </label>
          </div>
          <div className="flex gap-3 pt-2">
            <button data-testid="create-client-submit" type="submit" disabled={submitting} className="btn btn-primary flex-1">
              {submitting ? 'Creating…' : 'Create Client'}
            </button>
            <button data-testid="modal-close" type="button" className="btn btn-secondary flex-1" onClick={onClose}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Delete Confirmation
// ---------------------------------------------------------------------------

interface DeleteConfirmProps {
  clientName: string;
  onConfirm: () => void;
  onCancel: () => void;
}

function DeleteConfirm({ clientName, onConfirm, onCancel }: DeleteConfirmProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog" aria-modal="true">
      <div className="bg-dark-800 border border-red-700 rounded-lg p-6 w-full max-w-sm">
        <h2 className="text-lg font-semibold text-red-400 mb-2">Delete Client</h2>
        <p className="text-sm text-dark-300 mb-4">
          Delete <span className="text-dark-100 font-medium">{clientName}</span>? This cannot be undone.
        </p>
        <div className="flex gap-3">
          <button data-testid="delete-confirm-btn" className="btn bg-red-800 hover:bg-red-700 text-red-100 flex-1" onClick={onConfirm}>
            Delete
          </button>
          <button data-testid="delete-cancel-btn" className="btn btn-secondary flex-1" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function OAuthClients() {
  const { modules } = useModules();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newClientSecret, setNewClientSecret] = useState<OAuthClientCreated | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<OAuthClient | null>(null);

  const fetchClients = useCallback(async () => {
    console.log('[OAuthClients] Fetching clients');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: OAuthClient[] }>('/checkpoint/clients');
      setClients(res.data.items ?? (res.data as unknown as OAuthClient[]));
    } catch (err: unknown) {
      setError('Failed to load OAuth2 clients.');
      console.error('[OAuthClients] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    console.log('[OAuthClients] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchClients();
  }, [fetchClients, modules.checkpoint]);

  const handleDelete = async (client: OAuthClient) => {
    console.log('[OAuthClients] Deleting client', { id: client.id });
    try {
      await api.delete(`/checkpoint/clients/${client.id}`);
      await fetchClients();
    } catch (err: unknown) {
      console.error('[OAuthClients] Delete error:', err instanceof Error ? err.constructor.name : typeof err);
    }
    setDeleteTarget(null);
  };

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">OAuth2 Clients</h1>
          <p className="text-dark-400 mt-1">Registered OAuth2 / OIDC client applications.</p>
        </div>
        <button data-testid="new-client-btn" className="btn btn-primary" onClick={() => setShowCreate(true)}>
          + New Client
        </button>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading clients…</div>
      ) : clients.length === 0 ? (
        <Card>
          <div className="text-dark-400 py-4 text-center">No OAuth2 clients registered.</div>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">Client ID</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Name</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Scopes</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Grants</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">PKCE</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Status</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c, i) => (
                <tr key={c.id} data-testid={`client-row-${i}`} className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors">
                  <td className="py-2 pr-4 font-mono text-xs text-gold-400">{c.client_id}</td>
                  <td className="py-2 pr-4 text-dark-200">{c.name}</td>
                  <td className="py-2 pr-4 text-dark-400 text-xs max-w-xs truncate">{c.allowed_scopes}</td>
                  <td className="py-2 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {c.grant_types.map((g) => <GrantBadge key={g} grant={g} />)}
                    </div>
                  </td>
                  <td className="py-2 pr-4">
                    <span className={c.require_pkce ? 'text-green-400' : 'text-dark-500'}>{c.require_pkce ? '✓' : '—'}</span>
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-0.5 rounded-full text-xs ${c.is_active ? 'bg-green-900/50 text-green-400 border border-green-700' : 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
                      {c.is_active ? 'active' : 'inactive'}
                    </span>
                  </td>
                  <td className="py-2 pr-4">
                    <button
                      data-testid={`delete-client-${i}`}
                      className="text-xs text-red-400 hover:text-red-300 transition-colors"
                      onClick={() => setDeleteTarget(c)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <CreateClientModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(created) => {
          setNewClientSecret(created);
          void fetchClients();
        }}
      />

      {newClientSecret && (
        <SecretDisplay
          client_id={newClientSecret.client_id}
          client_secret={newClientSecret.client_secret}
          onClose={() => setNewClientSecret(null)}
        />
      )}

      {deleteTarget && (
        <DeleteConfirm
          clientName={deleteTarget.name}
          onConfirm={() => void handleDelete(deleteTarget)}
          onCancel={() => setDeleteTarget(null)}
        />
      )}
    </div>
  );
}
