import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { SAMLProvider } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Register SP Modal
// ---------------------------------------------------------------------------

interface RegisterSPForm {
  name: string;
  entity_id: string;
  acs_url: string;
  metadata_url: string;
  signing_cert: string;
}

interface RegisterSPModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function RegisterSPModal({ isOpen, onClose, onSuccess }: RegisterSPModalProps) {
  const [form, setForm] = useState<RegisterSPForm>({
    name: '',
    entity_id: '',
    acs_url: '',
    metadata_url: '',
    signing_cert: '',
  });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.entity_id || !form.acs_url) {
      setError('Name, Entity ID, and ACS URL are required.');
      return;
    }
    console.log('[SAMLProviders:RegisterSPModal] Submitting SP', { name: form.name });
    setSubmitting(true);
    setError(null);
    try {
      await api.post('/checkpoint/saml/providers', form);
      onSuccess();
      onClose();
      setForm({ name: '', entity_id: '', acs_url: '', metadata_url: '', signing_cert: '' });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to register SP';
      setError(msg);
      console.error('[SAMLProviders:RegisterSPModal] Error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true">
      <div className="bg-dark-800 border border-dark-600 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold text-gold-400 mb-4">Register Service Provider</h2>
        {error && <div className="mb-3 text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Name</label>
            <input data-testid="sp-name" type="text" className="input w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Entity ID</label>
            <input data-testid="sp-entity-id" type="text" className="input w-full" value={form.entity_id} onChange={(e) => setForm({ ...form, entity_id: e.target.value })} required />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">ACS URL</label>
            <input data-testid="sp-acs-url" type="url" className="input w-full" placeholder="https://app.example.com/saml/acs" value={form.acs_url} onChange={(e) => setForm({ ...form, acs_url: e.target.value })} required />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Metadata URL (optional)</label>
            <input data-testid="sp-metadata-url" type="url" className="input w-full" placeholder="https://app.example.com/saml/metadata" value={form.metadata_url} onChange={(e) => setForm({ ...form, metadata_url: e.target.value })} />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Signing Certificate (PEM, optional)</label>
            <textarea
              data-testid="sp-signing-cert"
              className="input w-full h-28 font-mono text-xs resize-y"
              value={form.signing_cert}
              onChange={(e) => setForm({ ...form, signing_cert: e.target.value })}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button data-testid="register-sp-submit" type="submit" disabled={submitting} className="btn btn-primary flex-1">
              {submitting ? 'Registering…' : 'Register SP'}
            </button>
            <button data-testid="modal-close" type="button" className="btn btn-secondary flex-1" onClick={onClose}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SAMLProviders() {
  const { modules } = useModules();
  const [providers, setProviders] = useState<SAMLProvider[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRegister, setShowRegister] = useState(false);

  const fetchProviders = useCallback(async () => {
    console.log('[SAMLProviders] Fetching SAML providers');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: SAMLProvider[] }>('/checkpoint/saml/providers');
      setProviders(res.data.items ?? (res.data as unknown as SAMLProvider[]));
    } catch (err: unknown) {
      setError('Failed to load SAML providers.');
      console.error('[SAMLProviders] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    console.log('[SAMLProviders] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchProviders();
  }, [fetchProviders, modules.checkpoint]);

  const downloadMetadata = async (id: string, name: string) => {
    console.log('[SAMLProviders] Downloading SP metadata', { name });
    try {
      const res = await api.get(`/checkpoint/saml/metadata/${id}`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${name.replace(/\s+/g, '-')}-metadata.xml`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      console.error('[SAMLProviders] Metadata download error:', err instanceof Error ? err.constructor.name : typeof err);
    }
  };

  const downloadIDPMetadata = async () => {
    console.log('[SAMLProviders] Downloading IDP metadata');
    try {
      const res = await api.get('/checkpoint/saml/idp-metadata', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'checkpoint-idp-metadata.xml';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      console.error('[SAMLProviders] IDP metadata download error:', err instanceof Error ? err.constructor.name : typeof err);
    }
  };

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  return (
    <div>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">SAML Providers</h1>
          <p className="text-dark-400 mt-1">Registered SAML 2.0 Service Providers.</p>
        </div>
        <div className="flex gap-2">
          <button
            data-testid="download-idp-metadata"
            className="btn btn-secondary text-sm"
            onClick={() => void downloadIDPMetadata()}
          >
            ↓ IDP Metadata
          </button>
          <button
            data-testid="register-sp-btn"
            className="btn btn-primary"
            onClick={() => setShowRegister(true)}
          >
            + Register SP
          </button>
        </div>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading SAML providers…</div>
      ) : providers.length === 0 ? (
        <Card>
          <div className="text-dark-400 py-4 text-center">No SAML Service Providers registered.</div>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">Name</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Entity ID</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">ACS URL</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Status</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((sp, i) => (
                <tr key={sp.id} data-testid={`sp-row-${i}`} className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors">
                  <td className="py-2 pr-4 text-dark-200 font-medium">{sp.name}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-dark-400 max-w-xs truncate">{sp.entity_id}</td>
                  <td className="py-2 pr-4 text-dark-400 text-xs max-w-xs truncate">{sp.acs_url}</td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-0.5 rounded-full text-xs ${sp.is_active ? 'bg-green-900/50 text-green-400 border border-green-700' : 'bg-dark-700 text-dark-400 border border-dark-600'}`}>
                      {sp.is_active ? 'active' : 'inactive'}
                    </span>
                  </td>
                  <td className="py-2 pr-4">
                    <button
                      data-testid={`download-sp-metadata-${i}`}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      onClick={() => void downloadMetadata(sp.id, sp.name)}
                    >
                      ↓ Metadata
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <RegisterSPModal
        isOpen={showRegister}
        onClose={() => setShowRegister(false)}
        onSuccess={() => void fetchProviders()}
      />
    </div>
  );
}
