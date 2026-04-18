import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { SigningKey, CheckpointConfig } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------

type Tab = 'tokens' | 'signing-keys' | 'elder-push' | 'rate-limits';

const TABS: { id: Tab; label: string }[] = [
  { id: 'tokens', label: 'Token Settings' },
  { id: 'signing-keys', label: 'Signing Keys' },
  { id: 'elder-push', label: 'Elder Push' },
  { id: 'rate-limits', label: 'Rate Limits' },
];

// ---------------------------------------------------------------------------
// Token Settings tab
// ---------------------------------------------------------------------------

function TokenSettingsTab({ config, onSave }: { config: CheckpointConfig | null; onSave: () => void }) {
  const [form, setForm] = useState({
    token_ttl: config?.token_ttl ?? 3600,
    refresh_token_ttl: config?.refresh_token_ttl ?? 86400,
    require_pkce: config?.require_pkce ?? true,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (config) {
      setForm({
        token_ttl: config.token_ttl,
        refresh_token_ttl: config.refresh_token_ttl,
        require_pkce: config.require_pkce,
      });
    }
  }, [config]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('[CheckpointSettings:Tokens] Saving token settings');
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      await api.patch('/checkpoint/config', form);
      setSuccess(true);
      onSave();
      setTimeout(() => setSuccess(false), 3000);
    } catch (err: unknown) {
      setError('Failed to save token settings.');
      console.error('[CheckpointSettings:Tokens] Save error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4 max-w-md">
        {error && <div className="text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        {success && <div className="text-sm text-green-400 bg-green-900/20 border border-green-700 rounded p-2">Settings saved.</div>}
        <div>
          <label className="block text-sm text-dark-300 mb-1">Access Token TTL (seconds)</label>
          <input
            data-testid="token-ttl"
            type="number"
            className="input w-full"
            value={form.token_ttl}
            min={60}
            max={86400}
            onChange={(e) => setForm({ ...form, token_ttl: Number(e.target.value) })}
          />
          <p className="text-xs text-dark-500 mt-1">Default: 3600 (1 hour). Max: 86400 (24 hours).</p>
        </div>
        <div>
          <label className="block text-sm text-dark-300 mb-1">Refresh Token TTL (seconds)</label>
          <input
            data-testid="refresh-token-ttl"
            type="number"
            className="input w-full"
            value={form.refresh_token_ttl}
            min={3600}
            max={2592000}
            onChange={(e) => setForm({ ...form, refresh_token_ttl: Number(e.target.value) })}
          />
          <p className="text-xs text-dark-500 mt-1">Default: 86400 (24 hours).</p>
        </div>
        <div className="flex items-center gap-3">
          <input
            data-testid="require-pkce"
            id="require_pkce"
            type="checkbox"
            className="w-4 h-4 accent-gold-400"
            checked={form.require_pkce}
            onChange={(e) => setForm({ ...form, require_pkce: e.target.checked })}
          />
          <label htmlFor="require_pkce" className="text-sm text-dark-300">Require PKCE for all OAuth2 flows</label>
        </div>
        <button data-testid="save-token-settings" type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Saving…' : 'Save Token Settings'}
        </button>
      </form>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Signing Keys tab
// ---------------------------------------------------------------------------

function SigningKeysTab() {
  const [keys, setKeys] = useState<SigningKey[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [revokingKid, setRevokingKid] = useState<string | null>(null);

  const fetchKeys = useCallback(async () => {
    console.log('[CheckpointSettings:SigningKeys] Fetching signing keys');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: SigningKey[] } | SigningKey[]>('/checkpoint/signing-keys');
      const data = res.data;
      setKeys(Array.isArray(data) ? data : (data as { items: SigningKey[] }).items ?? []);
    } catch (err: unknown) {
      setError('Failed to load signing keys.');
      console.error('[CheckpointSettings:SigningKeys] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { void fetchKeys(); }, [fetchKeys]);

  const handleGenerate = async () => {
    console.log('[CheckpointSettings:SigningKeys] Generating new key');
    setGenerating(true);
    setError(null);
    try {
      await api.post('/checkpoint/signing-keys/generate');
      await fetchKeys();
    } catch (err: unknown) {
      setError('Failed to generate key.');
      console.error('[CheckpointSettings:SigningKeys] Generate error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setGenerating(false);
    }
  };

  const handleRevoke = async (kid: string) => {
    console.log('[CheckpointSettings:SigningKeys] Revoking key', { kid: kid.slice(0, 8) });
    setRevokingKid(kid);
    setError(null);
    try {
      await api.post(`/checkpoint/signing-keys/${kid}/revoke`);
      await fetchKeys();
    } catch (err: unknown) {
      setError('Failed to revoke key.');
      console.error('[CheckpointSettings:SigningKeys] Revoke error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setRevokingKid(null);
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <p className="text-dark-400 text-sm">JWT signing keys used to issue and verify tokens.</p>
        <button
          data-testid="generate-key-btn"
          className="btn btn-primary text-sm"
          onClick={() => void handleGenerate()}
          disabled={generating}
        >
          {generating ? 'Generating…' : '+ Generate Key'}
        </button>
      </div>
      {error && <div className="text-sm text-red-400 mb-3">{error}</div>}
      {isLoading ? (
        <div className="text-dark-400 py-4 text-center">Loading…</div>
      ) : keys.length === 0 ? (
        <Card><div className="text-dark-400 py-4 text-center">No signing keys found.</div></Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">KID</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Algorithm</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Status</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Grace Until</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Created</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key, i) => (
                <tr key={key.kid} data-testid={`key-row-${i}`} className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors">
                  <td className="py-2 pr-4 font-mono text-xs text-dark-400">{key.kid}</td>
                  <td className="py-2 pr-4 text-dark-200">{key.algorithm}</td>
                  <td className="py-2 pr-4">
                    {key.revoked_at ? (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-red-900/50 text-red-400 border border-red-700">revoked</span>
                    ) : key.is_active ? (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-green-900/50 text-green-400 border border-green-700">active</span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700">grace</span>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-xs text-dark-400">
                    {key.grace_period_until ? new Date(key.grace_period_until).toLocaleDateString() : '—'}
                  </td>
                  <td className="py-2 pr-4 text-xs text-dark-400">
                    {new Date(key.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-2 pr-4">
                    {!key.revoked_at && (
                      <button
                        data-testid={`revoke-key-${i}`}
                        className="text-xs text-red-400 hover:text-red-300 transition-colors"
                        onClick={() => void handleRevoke(key.kid)}
                        disabled={revokingKid === key.kid}
                      >
                        {revokingKid === key.kid ? 'Revoking…' : 'Revoke'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Elder Push tab
// ---------------------------------------------------------------------------

function ElderPushTab({ config, onSave }: { config: CheckpointConfig | null; onSave: () => void }) {
  const [form, setForm] = useState({
    elder_push_enabled: config?.elder_push_enabled ?? false,
    elder_push_url: config?.elder_push_url ?? '',
    elder_push_api_key: '',
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    if (config) {
      setForm(prev => ({
        ...prev,
        elder_push_enabled: config.elder_push_enabled,
        elder_push_url: config.elder_push_url,
      }));
    }
  }, [config]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('[CheckpointSettings:ElderPush] Saving Elder Push config');
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      const payload: Record<string, unknown> = {
        elder_push_enabled: form.elder_push_enabled,
        elder_push_url: form.elder_push_url,
      };
      if (form.elder_push_api_key) payload['elder_push_api_key'] = form.elder_push_api_key;
      await api.patch('/checkpoint/config', payload);
      setSuccess(true);
      onSave();
      setTimeout(() => setSuccess(false), 3000);
    } catch (err: unknown) {
      setError('Failed to save Elder Push settings.');
      console.error('[CheckpointSettings:ElderPush] Save error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    console.log('[CheckpointSettings:ElderPush] Testing connection');
    setTesting(true);
    setTestResult(null);
    try {
      await api.post('/checkpoint/elder-push/test');
      setTestResult('Connection successful.');
    } catch (err: unknown) {
      setTestResult('Connection failed. Check the URL and API key.');
      console.error('[CheckpointSettings:ElderPush] Test error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card>
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4 max-w-md">
        {error && <div className="text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        {success && <div className="text-sm text-green-400 bg-green-900/20 border border-green-700 rounded p-2">Settings saved.</div>}
        {testResult && (
          <div className={`text-sm rounded p-2 ${testResult.includes('successful') ? 'text-green-400 bg-green-900/20 border border-green-700' : 'text-red-400 bg-red-900/20 border border-red-700'}`}>
            {testResult}
          </div>
        )}
        <div className="flex items-center gap-3">
          <input
            data-testid="elder-push-enabled"
            id="elder_push_enabled"
            type="checkbox"
            className="w-4 h-4 accent-gold-400"
            checked={form.elder_push_enabled}
            onChange={(e) => setForm({ ...form, elder_push_enabled: e.target.checked })}
          />
          <label htmlFor="elder_push_enabled" className="text-sm text-dark-300">Enable Elder Push integration</label>
        </div>
        <div>
          <label className="block text-sm text-dark-300 mb-1">Elder Push URL</label>
          <input
            data-testid="elder-push-url"
            type="url"
            className="input w-full"
            placeholder="https://elder.example.com/api/v1/push"
            value={form.elder_push_url}
            onChange={(e) => setForm({ ...form, elder_push_url: e.target.value })}
          />
        </div>
        <div>
          <label className="block text-sm text-dark-300 mb-1">API Key (leave blank to keep existing)</label>
          <input
            data-testid="elder-push-api-key"
            type="password"
            className="input w-full font-mono"
            placeholder="••••••••"
            value={form.elder_push_api_key}
            onChange={(e) => setForm({ ...form, elder_push_api_key: e.target.value })}
            autoComplete="new-password"
          />
          <p className="text-xs text-dark-500 mt-1">Stored encrypted. Current value is masked.</p>
        </div>
        <div className="flex gap-3 pt-2">
          <button data-testid="save-elder-push" type="submit" disabled={saving} className="btn btn-primary">
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            data-testid="test-elder-push"
            type="button"
            className="btn btn-secondary"
            onClick={() => void handleTest()}
            disabled={testing || !form.elder_push_url}
          >
            {testing ? 'Testing…' : 'Test Connection'}
          </button>
        </div>
      </form>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Rate Limits tab
// ---------------------------------------------------------------------------

function RateLimitsTab({ config, onSave }: { config: CheckpointConfig | null; onSave: () => void }) {
  const [form, setForm] = useState({
    auth_rate_limit_per_min: config?.auth_rate_limit_per_min ?? 20,
    auth_rate_limit_per_hour: config?.auth_rate_limit_per_hour ?? 200,
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (config) {
      setForm({
        auth_rate_limit_per_min: config.auth_rate_limit_per_min,
        auth_rate_limit_per_hour: config.auth_rate_limit_per_hour,
      });
    }
  }, [config]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('[CheckpointSettings:RateLimits] Saving rate limit config');
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      await api.patch('/checkpoint/config', form);
      setSuccess(true);
      onSave();
      setTimeout(() => setSuccess(false), 3000);
    } catch (err: unknown) {
      setError('Failed to save rate limit settings.');
      console.error('[CheckpointSettings:RateLimits] Save error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4 max-w-md">
        {error && <div className="text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        {success && <div className="text-sm text-green-400 bg-green-900/20 border border-green-700 rounded p-2">Settings saved.</div>}
        <div>
          <label className="block text-sm text-dark-300 mb-1">Auth requests per minute (per IP)</label>
          <input
            data-testid="rate-limit-per-min"
            type="number"
            className="input w-full"
            value={form.auth_rate_limit_per_min}
            min={1}
            max={1000}
            onChange={(e) => setForm({ ...form, auth_rate_limit_per_min: Number(e.target.value) })}
          />
        </div>
        <div>
          <label className="block text-sm text-dark-300 mb-1">Auth requests per hour (per IP)</label>
          <input
            data-testid="rate-limit-per-hour"
            type="number"
            className="input w-full"
            value={form.auth_rate_limit_per_hour}
            min={10}
            max={10000}
            onChange={(e) => setForm({ ...form, auth_rate_limit_per_hour: Number(e.target.value) })}
          />
        </div>
        <button data-testid="save-rate-limits" type="submit" disabled={saving} className="btn btn-primary">
          {saving ? 'Saving…' : 'Save Rate Limits'}
        </button>
      </form>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function CheckpointSettings() {
  const { modules } = useModules();
  const [activeTab, setActiveTab] = useState<Tab>('tokens');
  const [config, setConfig] = useState<CheckpointConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchConfig = useCallback(async () => {
    console.log('[CheckpointSettings] Fetching config');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<CheckpointConfig>('/checkpoint/config');
      setConfig(res.data);
    } catch (err: unknown) {
      setError('Failed to load settings.');
      console.error('[CheckpointSettings] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    console.log('[CheckpointSettings] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchConfig();
  }, [fetchConfig, modules.checkpoint]);

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Settings</h1>
        <p className="text-dark-400 mt-1">Checkpoint configuration and key management.</p>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-0 border-b border-dark-700 mb-6">
        {TABS.map(tab => (
          <button
            key={tab.id}
            data-testid={`tab-${tab.id}`}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-dark-400 hover:text-gold-400'
            }`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading settings…</div>
      ) : (
        <>
          {activeTab === 'tokens' && <TokenSettingsTab config={config} onSave={() => void fetchConfig()} />}
          {activeTab === 'signing-keys' && <SigningKeysTab />}
          {activeTab === 'elder-push' && <ElderPushTab config={config} onSave={() => void fetchConfig()} />}
          {activeTab === 'rate-limits' && <RateLimitsTab config={config} onSave={() => void fetchConfig()} />}
        </>
      )}
    </div>
  );
}
