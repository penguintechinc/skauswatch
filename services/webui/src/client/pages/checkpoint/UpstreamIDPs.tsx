import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { UpstreamIDP } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type IDPType = UpstreamIDP['type'];
type FederationMode = UpstreamIDP['federation_mode'];

function TypeBadge({ type }: { type: IDPType }) {
  const labels: Record<IDPType, string> = {
    oidc: 'OIDC',
    saml: 'SAML',
    ldap: 'LDAP',
    google: 'Google',
    okta: 'Okta',
  };
  const colors: Record<IDPType, string> = {
    oidc: 'bg-blue-900/50 text-blue-400 border border-blue-700',
    saml: 'bg-purple-900/50 text-purple-400 border border-purple-700',
    ldap: 'bg-orange-900/50 text-orange-400 border border-orange-700',
    google: 'bg-green-900/50 text-green-400 border border-green-700',
    okta: 'bg-cyan-900/50 text-cyan-400 border border-cyan-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colors[type]}`}>
      {labels[type]}
    </span>
  );
}

function ModeBadge({ mode }: { mode: FederationMode }) {
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-xs font-medium ${
        mode === 'sync'
          ? 'bg-blue-900/50 text-blue-400 border border-blue-700'
          : 'bg-purple-900/50 text-purple-400 border border-purple-700'
      }`}
    >
      {mode}
    </span>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------------
// Add IDP Modal
// ---------------------------------------------------------------------------

type Step = 'basic' | 'connection' | 'review';

interface AddIDPForm {
  name: string;
  type: IDPType;
  federation_mode: FederationMode;
  sync_interval_secs: number;
  // OIDC
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scope: string;
  // SAML
  metadata_url: string;
  entity_id: string;
  // LDAP
  ldap_url: string;
  bind_dn: string;
  bind_password: string;
  user_base_dn: string;
  group_base_dn: string;
  user_filter: string;
  // Google
  service_account_json: string;
  domain: string;
  // Okta
  okta_domain: string;
  api_token: string;
  attribute_mapping: string;
}

const defaultForm: AddIDPForm = {
  name: '',
  type: 'oidc',
  federation_mode: 'sync',
  sync_interval_secs: 3600,
  issuer_url: '',
  client_id: '',
  client_secret: '',
  scope: 'openid profile email',
  metadata_url: '',
  entity_id: '',
  ldap_url: '',
  bind_dn: '',
  bind_password: '',
  user_base_dn: '',
  group_base_dn: '',
  user_filter: '(objectClass=person)',
  service_account_json: '',
  domain: '',
  okta_domain: '',
  api_token: '',
  attribute_mapping: '{}',
};

interface AddIDPModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function ConnectionFields({ form, setForm }: { form: AddIDPForm; setForm: (f: AddIDPForm) => void }) {
  const inputCls = 'input w-full';
  const labelCls = 'block text-sm text-dark-300 mb-1';

  switch (form.type) {
    case 'oidc':
      return (
        <>
          <div>
            <label className={labelCls}>Issuer URL</label>
            <input data-testid="idp-issuer-url" type="url" className={inputCls} value={form.issuer_url} onChange={(e) => setForm({ ...form, issuer_url: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Client ID</label>
            <input data-testid="idp-client-id" type="text" className={inputCls} value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Client Secret</label>
            <input data-testid="idp-client-secret" type="password" className={inputCls} value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Scopes</label>
            <input data-testid="idp-scope" type="text" className={inputCls} value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
          </div>
        </>
      );
    case 'saml':
      return (
        <>
          <div>
            <label className={labelCls}>Metadata URL</label>
            <input data-testid="idp-metadata-url" type="url" className={inputCls} value={form.metadata_url} onChange={(e) => setForm({ ...form, metadata_url: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Entity ID</label>
            <input data-testid="idp-entity-id" type="text" className={inputCls} value={form.entity_id} onChange={(e) => setForm({ ...form, entity_id: e.target.value })} />
          </div>
        </>
      );
    case 'ldap':
      return (
        <>
          <div>
            <label className={labelCls}>LDAP URL</label>
            <input data-testid="idp-ldap-url" type="text" className={inputCls} placeholder="ldap://host:389" value={form.ldap_url} onChange={(e) => setForm({ ...form, ldap_url: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Bind DN</label>
            <input data-testid="idp-bind-dn" type="text" className={inputCls} value={form.bind_dn} onChange={(e) => setForm({ ...form, bind_dn: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Bind Password</label>
            <input data-testid="idp-bind-password" type="password" className={inputCls} value={form.bind_password} onChange={(e) => setForm({ ...form, bind_password: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>User Base DN</label>
            <input data-testid="idp-user-base-dn" type="text" className={inputCls} value={form.user_base_dn} onChange={(e) => setForm({ ...form, user_base_dn: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Group Base DN</label>
            <input data-testid="idp-group-base-dn" type="text" className={inputCls} value={form.group_base_dn} onChange={(e) => setForm({ ...form, group_base_dn: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>User Filter</label>
            <input data-testid="idp-user-filter" type="text" className={inputCls} value={form.user_filter} onChange={(e) => setForm({ ...form, user_filter: e.target.value })} />
          </div>
        </>
      );
    case 'google':
      return (
        <>
          <div>
            <label className={labelCls}>Domain</label>
            <input data-testid="idp-google-domain" type="text" className={inputCls} placeholder="company.com" value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Service Account JSON</label>
            <textarea
              data-testid="idp-service-account-json"
              className="input w-full h-28 font-mono text-xs resize-y"
              value={form.service_account_json}
              onChange={(e) => setForm({ ...form, service_account_json: e.target.value })}
              placeholder='{"type":"service_account",...}'
            />
          </div>
        </>
      );
    case 'okta':
      return (
        <>
          <div>
            <label className={labelCls}>Okta Domain</label>
            <input data-testid="idp-okta-domain" type="text" className={inputCls} placeholder="company.okta.com" value={form.okta_domain} onChange={(e) => setForm({ ...form, okta_domain: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>API Token</label>
            <input data-testid="idp-okta-api-token" type="password" className={inputCls} value={form.api_token} onChange={(e) => setForm({ ...form, api_token: e.target.value })} />
          </div>
          <div>
            <label className={labelCls}>Attribute Mapping (JSON)</label>
            <textarea
              data-testid="idp-attribute-mapping"
              className="input w-full h-24 font-mono text-xs resize-y"
              value={form.attribute_mapping}
              onChange={(e) => setForm({ ...form, attribute_mapping: e.target.value })}
            />
          </div>
        </>
      );
    default:
      return null;
  }
}

function AddIDPModal({ isOpen, onClose, onSuccess }: AddIDPModalProps) {
  const [step, setStep] = useState<Step>('basic');
  const [form, setForm] = useState<AddIDPForm>(defaultForm);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async () => {
    if (!form.name) {
      setError('Name is required.');
      return;
    }
    console.log('[UpstreamIDPs:AddIDPModal] Submitting IDP', { name: form.name, type: form.type });
    setSubmitting(true);
    setError(null);
    try {
      await api.post('/checkpoint/idps', form);
      onSuccess();
      onClose();
      setForm(defaultForm);
      setStep('basic');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to add IDP';
      setError(msg);
      console.error('[UpstreamIDPs:AddIDPModal] Error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSubmitting(false);
    }
  };

  const stepOrder: Step[] = ['basic', 'connection', 'review'];
  const stepIdx = stepOrder.indexOf(step);

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true">
      <div className="relative bg-dark-800 border border-dark-600 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold text-gold-400 mb-2">Add Upstream IDP</h2>

        {/* Step indicator */}
        <div className="flex gap-2 mb-6">
          {stepOrder.map((s, i) => (
            <span key={s} className={`text-xs px-2 py-0.5 rounded ${i <= stepIdx ? 'text-gold-400 bg-gold-900/20' : 'text-dark-500'}`}>
              {i + 1}. {s.charAt(0).toUpperCase() + s.slice(1)}
            </span>
          ))}
        </div>

        {error && <div className="mb-3 text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}

        {step === 'basic' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-dark-300 mb-1">Name</label>
              <input data-testid="idp-name" type="text" className="input w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <label className="block text-sm text-dark-300 mb-1">Type</label>
              <select data-testid="idp-type" className="input w-full" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as IDPType })}>
                <option value="oidc">OIDC</option>
                <option value="saml">SAML</option>
                <option value="ldap">LDAP</option>
                <option value="google">Google Workspace</option>
                <option value="okta">Okta</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-dark-300 mb-1">Federation Mode</label>
              <select data-testid="idp-federation-mode" className="input w-full" value={form.federation_mode} onChange={(e) => setForm({ ...form, federation_mode: e.target.value as FederationMode })}>
                <option value="sync">Sync (periodic import)</option>
                <option value="proxy">Proxy (JIT lookup)</option>
              </select>
            </div>
            {form.federation_mode === 'sync' && (
              <div>
                <label className="block text-sm text-dark-300 mb-1">Sync Interval (seconds)</label>
                <input data-testid="idp-sync-interval" type="number" min={60} className="input w-full" value={form.sync_interval_secs} onChange={(e) => setForm({ ...form, sync_interval_secs: parseInt(e.target.value, 10) || 3600 })} />
              </div>
            )}
          </div>
        )}

        {step === 'connection' && (
          <div className="space-y-4">
            <ConnectionFields form={form} setForm={setForm} />
          </div>
        )}

        {step === 'review' && (
          <div className="space-y-2 text-sm">
            <div className="flex justify-between border-b border-dark-700 py-2">
              <span className="text-dark-400">Name</span>
              <span className="text-dark-200">{form.name}</span>
            </div>
            <div className="flex justify-between border-b border-dark-700 py-2">
              <span className="text-dark-400">Type</span>
              <TypeBadge type={form.type} />
            </div>
            <div className="flex justify-between border-b border-dark-700 py-2">
              <span className="text-dark-400">Mode</span>
              <ModeBadge mode={form.federation_mode} />
            </div>
            {form.federation_mode === 'sync' && (
              <div className="flex justify-between py-2">
                <span className="text-dark-400">Sync Interval</span>
                <span className="text-dark-200">{form.sync_interval_secs}s</span>
              </div>
            )}
          </div>
        )}

        <div className="flex gap-3 pt-4 mt-4 border-t border-dark-700">
          {stepIdx > 0 && (
            <button data-testid="idp-prev-step" type="button" className="btn btn-secondary" onClick={() => setStep(stepOrder[stepIdx - 1])}>
              ← Back
            </button>
          )}
          {stepIdx < stepOrder.length - 1 && (
            <button data-testid="idp-next-step" type="button" className="btn btn-primary flex-1" onClick={() => setStep(stepOrder[stepIdx + 1])}>
              Next →
            </button>
          )}
          {step === 'review' && (
            <button data-testid="idp-submit" type="button" disabled={submitting} className="btn btn-primary flex-1" onClick={() => void handleSubmit()}>
              {submitting ? 'Adding…' : 'Add IDP'}
            </button>
          )}
          <button data-testid="modal-close" type="button" className="btn btn-secondary" onClick={() => { onClose(); setForm(defaultForm); setStep('basic'); }}>
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

export default function UpstreamIDPs() {
  const { modules } = useModules();
  const [idps, setIdps] = useState<UpstreamIDP[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const fetchIDPs = useCallback(async () => {
    console.log('[UpstreamIDPs] Fetching IDPs');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: UpstreamIDP[] }>('/checkpoint/idps');
      setIdps(res.data.items ?? (res.data as unknown as UpstreamIDP[]));
    } catch (err: unknown) {
      setError('Failed to load upstream IDPs.');
      console.error('[UpstreamIDPs] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    console.log('[UpstreamIDPs] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchIDPs();
  }, [fetchIDPs, modules.checkpoint]);

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">Upstream IDPs</h1>
          <p className="text-dark-400 mt-1">Federate with external identity providers.</p>
        </div>
        <button data-testid="add-idp-btn" className="btn btn-primary" onClick={() => setShowAdd(true)}>
          + Add IDP
        </button>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading IDPs…</div>
      ) : idps.length === 0 ? (
        <Card>
          <div className="text-dark-400 py-4 text-center">No upstream IDPs configured.</div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {idps.map((idp) => (
            <Card key={idp.id} className="hover:border-dark-500 transition-colors">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="text-dark-200 font-medium">{idp.name}</div>
                  <div className="flex gap-2 mt-1">
                    <TypeBadge type={idp.type} />
                    <ModeBadge mode={idp.federation_mode} />
                    {idp.is_active ? (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-green-900/50 text-green-400 border border-green-700">active</span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-dark-700 text-dark-400 border border-dark-600">inactive</span>
                    )}
                  </div>
                </div>
              </div>
              {idp.sync_error && (
                <div className="text-xs text-red-400 bg-red-900/20 border border-red-700 rounded p-2 mb-2">
                  Sync error: {idp.sync_error}
                </div>
              )}
              <div className="text-xs text-dark-500">Last sync: {formatDate(idp.last_sync_at)}</div>
            </Card>
          ))}
        </div>
      )}

      <AddIDPModal isOpen={showAdd} onClose={() => setShowAdd(false)} onSuccess={() => void fetchIDPs()} />
    </div>
  );
}
