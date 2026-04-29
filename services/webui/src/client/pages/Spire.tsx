import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import { spireApi } from '../api/spire';
import type {
  SpireStatus,
  SpireEntry,
  SpireNode,
  TrustDomainBundle,
  CreateJoinTokenResponse,
} from '../types/spire';
import Card from '../components/Card';
import Button from '../components/Button';
import TabNavigation from '../components/TabNavigation';

type Tab = 'overview' | 'workloads' | 'federation' | 'nodes' | 'datastore';

export default function Spire() {
  const { isAdmin } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'workloads', label: 'Workloads' },
    { id: 'federation', label: 'Federation' },
    { id: 'nodes', label: 'Nodes' },
    { id: 'datastore', label: 'Datastore' },
  ];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-amber-400">SPIFFE/SPIRE Management</h1>
        <p className="text-slate-400 mt-1">Manage SPIRE server, identities, and federation</p>
      </div>

      <TabNavigation
        tabs={tabs}
        activeTab={activeTab}
        onChange={(id) => setActiveTab(id as Tab)}
      />

      <div className="mt-6">
        {activeTab === 'overview' && <OverviewTab />}
        {activeTab === 'workloads' && <WorkloadsTab isAdmin={isAdmin()} />}
        {activeTab === 'federation' && <FederationTab isAdmin={isAdmin()} />}
        {activeTab === 'nodes' && <NodesTab isAdmin={isAdmin()} />}
        {activeTab === 'datastore' && <DatastoreTab isAdmin={isAdmin()} />}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// OVERVIEW TAB
// ─────────────────────────────────────────────────────────────────────────

function OverviewTab() {
  const [status, setStatus] = useState<SpireStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStatus = async () => {
      try {
        setLoading(true);
        const data = await spireApi.getStatus();
        setStatus(data);
        console.log('[Spire] Loaded status', { healthy: data.healthy });
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to load status';
        setError(msg);
        console.error('[Spire] Status load failed', { error: msg });
      } finally {
        setLoading(false);
      }
    };

    loadStatus();
    const interval = setInterval(loadStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !status) {
    return (
      <div className="space-y-4">
        {[...Array(5)].map((_, i) => (
          <div
            key={i}
            className="h-24 bg-slate-800 rounded-lg animate-pulse"
          />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <Card title="Error">
        <p className="text-red-400">{error}</p>
      </Card>
    );
  }

  if (!status) {
    return (
      <Card title="Overview">
        <p className="text-slate-400">No data available</p>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
      <Card title="Health">
        <div className="flex items-center gap-2">
          <div
            className={`w-3 h-3 rounded-full ${
              status.healthy ? 'bg-green-500' : 'bg-red-500'
            }`}
          />
          <span className="text-amber-400">
            {status.healthy ? 'Healthy' : 'Unhealthy'}
          </span>
        </div>
      </Card>

      <Card title="Uptime">
        <p className="text-amber-400 font-mono text-sm">{status.uptime}</p>
      </Card>

      <Card title="SPIFFE Endpoint">
        <p className="text-amber-400 font-mono text-xs break-all">
          {status.spiffe_endpoint}
        </p>
      </Card>

      <Card title="Agents Connected">
        <p className="text-2xl font-bold text-amber-400">
          {status.agents_connected}
        </p>
      </Card>

      <Card title="Active SVIDs">
        <p className="text-2xl font-bold text-amber-400">
          {status.active_svids}
        </p>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// WORKLOADS TAB
// ─────────────────────────────────────────────────────────────────────────

function WorkloadsTab({ isAdmin }: { isAdmin: boolean }) {
  const [entries, setEntries] = useState<SpireEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    spiffe_id: '',
    parent_id: '',
    selectors: '[]',
    ttl: '3600',
  });

  const loadEntries = async () => {
    try {
      setLoading(true);
      const res = await spireApi.listEntries();
      setEntries(res.entries || []);
      console.log('[Spire] Loaded entries', { count: res.entries?.length });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load entries';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEntries();
  }, []);

  const handleCreateEntry = async () => {
    if (!formData.spiffe_id.trim() || !formData.parent_id.trim()) {
      alert('SPIFFE ID and Parent ID are required');
      return;
    }

    try {
      setSubmitting(true);
      let selectors = [];
      try {
        selectors = JSON.parse(formData.selectors);
      } catch {
        alert('Invalid selectors JSON');
        return;
      }

      await spireApi.createEntry({
        spiffe_id: formData.spiffe_id.trim(),
        parent_id: formData.parent_id.trim(),
        selectors,
        ttl: parseInt(formData.ttl) || 3600,
      });

      console.log('[Spire] Entry created', { spiffe_id: formData.spiffe_id });
      setShowModal(false);
      setFormData({
        spiffe_id: '',
        parent_id: '',
        selectors: '[]',
        ttl: '3600',
      });
      await loadEntries();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create entry';
      alert(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this entry? This cannot be undone.')) return;

    try {
      await spireApi.deleteEntry(id);
      console.log('[Spire] Entry deleted', { id });
      await loadEntries();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete entry';
      alert(msg);
    }
  };

  if (loading) {
    return <div className="h-40 bg-slate-800 rounded-lg animate-pulse" />;
  }

  return (
    <div className="space-y-4">
      {isAdmin && (
        <div className="flex gap-2">
          <Button
            onClick={() => setShowModal(true)}
            variant="primary"
          >
            Register Entry
          </Button>
        </div>
      )}

      {error && (
        <Card title="Error">
          <p className="text-red-400">{error}</p>
        </Card>
      )}

      {entries.length === 0 ? (
        <Card title="Workloads">
          <p className="text-slate-400">No entries found</p>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-amber-400">SPIFFE ID</th>
                <th className="text-left py-3 px-4 text-amber-400">Parent ID</th>
                <th className="text-left py-3 px-4 text-amber-400">Selectors</th>
                <th className="text-left py-3 px-4 text-amber-400">TTL</th>
                <th className="text-left py-3 px-4 text-amber-400">Expires At</th>
                {isAdmin && <th className="text-left py-3 px-4 text-amber-400">Action</th>}
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr
                  key={entry.id}
                  className="border-b border-slate-700 hover:bg-slate-800"
                >
                  <td className="py-3 px-4 text-slate-200 font-mono text-xs break-all">
                    {entry.spiffe_id}
                  </td>
                  <td className="py-3 px-4 text-slate-200 font-mono text-xs break-all">
                    {entry.parent_id}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    <span className="text-xs">
                      {entry.selectors
                        .map((s) => `${s.type}:${s.value}`)
                        .join(', ')}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{entry.ttl}s</td>
                  <td className="py-3 px-4 text-slate-400 text-xs">
                    {entry.expires_at
                      ? new Date(entry.expires_at).toLocaleString()
                      : '—'}
                  </td>
                  {isAdmin && (
                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleDelete(entry.id)}
                        className="px-3 py-1 text-sm bg-red-900 text-red-200 rounded hover:bg-red-800 transition"
                      >
                        Delete
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Register Entry Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-slate-900 rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-amber-400 mb-4">Register Entry</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  SPIFFE ID
                </label>
                <input
                  type="text"
                  value={formData.spiffe_id}
                  onChange={(e) =>
                    setFormData({ ...formData, spiffe_id: e.target.value })
                  }
                  placeholder="spiffe://..."
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Parent ID
                </label>
                <input
                  type="text"
                  value={formData.parent_id}
                  onChange={(e) =>
                    setFormData({ ...formData, parent_id: e.target.value })
                  }
                  placeholder="spiffe://..."
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Selectors (JSON array)
                </label>
                <textarea
                  value={formData.selectors}
                  onChange={(e) =>
                    setFormData({ ...formData, selectors: e.target.value })
                  }
                  placeholder='[{"type":"docker","value":"label:app=myapp"}]'
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm font-mono"
                  rows={4}
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  TTL (seconds)
                </label>
                <input
                  type="number"
                  value={formData.ttl}
                  onChange={(e) =>
                    setFormData({ ...formData, ttl: e.target.value })
                  }
                  min="1"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
            </div>

            <div className="flex gap-2 mt-6">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 px-4 py-2 bg-slate-700 text-slate-200 rounded hover:bg-slate-600 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateEntry}
                disabled={submitting}
                className="flex-1 px-4 py-2 bg-amber-600 text-white rounded hover:bg-amber-700 transition disabled:opacity-50"
              >
                {submitting ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// FEDERATION TAB
// ─────────────────────────────────────────────────────────────────────────

function FederationTab({ isAdmin }: { isAdmin: boolean }) {
  const [bundles, setBundles] = useState<TrustDomainBundle[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    trust_domain: '',
    endpoint_url: '',
  });

  const loadFederation = async () => {
    try {
      setLoading(true);
      const res = await spireApi.getFederation();
      setBundles(res.bundles || []);
      console.log('[Spire] Loaded federation', { count: res.bundles?.length });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load federation';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFederation();
  }, []);

  const handleAddPeer = async () => {
    if (!formData.trust_domain.trim() || !formData.endpoint_url.trim()) {
      alert('Trust Domain and Endpoint URL are required');
      return;
    }

    try {
      setSubmitting(true);
      await spireApi.addFederationPeer({
        trust_domain: formData.trust_domain.trim(),
        endpoint_url: formData.endpoint_url.trim(),
      });

      console.log('[Spire] Federation peer added', {
        trust_domain: formData.trust_domain,
      });
      setShowModal(false);
      setFormData({ trust_domain: '', endpoint_url: '' });
      await loadFederation();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to add peer';
      alert(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemovePeer = async (td: string) => {
    if (!confirm(`Remove federation peer ${td}?`)) return;

    try {
      await spireApi.removeFederationPeer(td);
      console.log('[Spire] Federation peer removed', { trust_domain: td });
      await loadFederation();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to remove peer';
      alert(msg);
    }
  };

  if (loading) {
    return <div className="h-40 bg-slate-800 rounded-lg animate-pulse" />;
  }

  return (
    <div className="space-y-4">
      {isAdmin && (
        <div className="flex gap-2">
          <Button
            onClick={() => setShowModal(true)}
            variant="primary"
          >
            Add Peer
          </Button>
        </div>
      )}

      {error && (
        <Card title="Error">
          <p className="text-red-400">{error}</p>
        </Card>
      )}

      {bundles.length === 0 ? (
        <Card title="Federation">
          <p className="text-slate-400">No federation peers configured</p>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-amber-400">Trust Domain</th>
                <th className="text-left py-3 px-4 text-amber-400">Sequence Number</th>
                <th className="text-left py-3 px-4 text-amber-400">Refresh Hint</th>
                {isAdmin && <th className="text-left py-3 px-4 text-amber-400">Action</th>}
              </tr>
            </thead>
            <tbody>
              {bundles.map((b) => (
                <tr
                  key={b.trust_domain}
                  className="border-b border-slate-700 hover:bg-slate-800"
                >
                  <td className="py-3 px-4 text-slate-200 font-mono">
                    {b.trust_domain}
                  </td>
                  <td className="py-3 px-4 text-slate-300">{b.sequence_number}</td>
                  <td className="py-3 px-4 text-slate-300">{b.refresh_hint}s</td>
                  {isAdmin && (
                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleRemovePeer(b.trust_domain)}
                        className="px-3 py-1 text-sm bg-red-900 text-red-200 rounded hover:bg-red-800 transition"
                      >
                        Remove
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add Peer Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-slate-900 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-amber-400 mb-4">Add Federation Peer</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Trust Domain
                </label>
                <input
                  type="text"
                  value={formData.trust_domain}
                  onChange={(e) =>
                    setFormData({ ...formData, trust_domain: e.target.value })
                  }
                  placeholder="example.io"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Endpoint URL
                </label>
                <input
                  type="text"
                  value={formData.endpoint_url}
                  onChange={(e) =>
                    setFormData({ ...formData, endpoint_url: e.target.value })
                  }
                  placeholder="https://spire.example.io:8323"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
            </div>

            <div className="flex gap-2 mt-6">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 px-4 py-2 bg-slate-700 text-slate-200 rounded hover:bg-slate-600 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleAddPeer}
                disabled={submitting}
                className="flex-1 px-4 py-2 bg-amber-600 text-white rounded hover:bg-amber-700 transition disabled:opacity-50"
              >
                {submitting ? 'Adding...' : 'Add'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// NODES TAB
// ─────────────────────────────────────────────────────────────────────────

function NodesTab({ isAdmin }: { isAdmin: boolean }) {
  const [nodes, setNodes] = useState<SpireNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [tokenData, setTokenData] = useState<CreateJoinTokenResponse | null>(null);
  const [creatingToken, setCreatingToken] = useState(false);

  const loadNodes = async () => {
    try {
      setLoading(true);
      const res = await spireApi.listNodes();
      setNodes(res.nodes || []);
      console.log('[Spire] Loaded nodes', { count: res.nodes?.length });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load nodes';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNodes();
  }, []);

  const handleGenerateToken = async () => {
    try {
      setCreatingToken(true);
      const token = await spireApi.createJoinToken(600);
      setTokenData(token);
      console.log('[Spire] Join token created', { expires_at: token.expires_at });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create token';
      alert(msg);
    } finally {
      setCreatingToken(false);
    }
  };

  const handleCopyToken = () => {
    if (tokenData) {
      navigator.clipboard.writeText(tokenData.token);
      alert('Token copied to clipboard');
    }
  };

  if (loading) {
    return <div className="h-40 bg-slate-800 rounded-lg animate-pulse" />;
  }

  return (
    <div className="space-y-4">
      {isAdmin && (
        <div className="flex gap-2">
          <Button
            onClick={() => {
              setShowTokenModal(true);
              setTokenData(null);
            }}
            variant="primary"
          >
            Generate Join Token
          </Button>
        </div>
      )}

      {error && (
        <Card title="Error">
          <p className="text-red-400">{error}</p>
        </Card>
      )}

      {nodes.length === 0 ? (
        <Card title="Nodes">
          <p className="text-slate-400">No nodes registered</p>
        </Card>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-amber-400">SPIFFE ID</th>
                <th className="text-left py-3 px-4 text-amber-400">Attestation Type</th>
                <th className="text-left py-3 px-4 text-amber-400">Banned</th>
                <th className="text-left py-3 px-4 text-amber-400">Expires At</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((node) => (
                <tr
                  key={node.id}
                  className="border-b border-slate-700 hover:bg-slate-800"
                >
                  <td className="py-3 px-4 text-slate-200 font-mono text-xs break-all">
                    {node.spiffe_id}
                  </td>
                  <td className="py-3 px-4 text-slate-300">{node.attestation_type}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`text-xs px-2 py-1 rounded ${
                        node.banned
                          ? 'bg-red-900 text-red-200'
                          : 'bg-green-900 text-green-200'
                      }`}
                    >
                      {node.banned ? 'Yes' : 'No'}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-xs">
                    {new Date(node.expires_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Join Token Modal */}
      {showTokenModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-slate-900 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-amber-400 mb-4">Generate Join Token</h2>

            {!tokenData ? (
              <div>
                <p className="text-slate-300 text-sm mb-4">
                  Generate a new join token for agents to attest to this SPIRE server.
                </p>
                <p className="text-yellow-600 text-xs mb-4">
                  Warning: Tokens have a 10-minute TTL and can only be used once.
                </p>

                <div className="flex gap-2">
                  <button
                    onClick={() => setShowTokenModal(false)}
                    className="flex-1 px-4 py-2 bg-slate-700 text-slate-200 rounded hover:bg-slate-600 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleGenerateToken}
                    disabled={creatingToken}
                    className="flex-1 px-4 py-2 bg-amber-600 text-white rounded hover:bg-amber-700 transition disabled:opacity-50"
                  >
                    {creatingToken ? 'Generating...' : 'Generate'}
                  </button>
                </div>
              </div>
            ) : (
              <div>
                <p className="text-slate-300 text-sm mb-2">
                  Token (store securely — can only be shown once):
                </p>
                <textarea
                  readOnly
                  value={tokenData.token}
                  className="w-full h-24 px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs font-mono mb-2"
                />
                <p className="text-slate-400 text-xs mb-4">
                  Expires: {new Date(tokenData.expires_at).toLocaleString()}
                </p>

                <div className="flex gap-2">
                  <button
                    onClick={() => setShowTokenModal(false)}
                    className="flex-1 px-4 py-2 bg-slate-700 text-slate-200 rounded hover:bg-slate-600 transition"
                  >
                    Close
                  </button>
                  <button
                    onClick={handleCopyToken}
                    className="flex-1 px-4 py-2 bg-amber-600 text-white rounded hover:bg-amber-700 transition"
                  >
                    Copy
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// DATASTORE TAB
// ─────────────────────────────────────────────────────────────────────────

function DatastoreTab({ isAdmin }: { isAdmin: boolean }) {
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    host: 'marchproxy.nest.svc',
    port: '5432',
    db_name: 'spire',
    secret_name: '',
  });

  const handleMigrate = async () => {
    if (!formData.secret_name.trim()) {
      alert('Secret name is required');
      return;
    }

    if (
      !confirm(
        'This will restart the SPIRE server and migrate data to PostgreSQL. Are you sure?'
      )
    ) {
      return;
    }

    try {
      setSubmitting(true);
      await spireApi.migrateDatastore({
        type: 'postgresql',
        host: formData.host.trim(),
        port: parseInt(formData.port) || 5432,
        db_name: formData.db_name.trim(),
        secret_name: formData.secret_name.trim(),
      });

      console.log('[Spire] Datastore migration started', {
        host: formData.host,
      });
      alert('Migration started. Server is restarting...');
      setShowModal(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Migration failed';
      alert(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card title="SQLite">
          <p className="text-slate-300 text-sm mb-2">Current datastore</p>
          <p className="text-slate-400 text-xs">
            Development and testing use SQLite for simplicity.
          </p>
        </Card>

        <Card title="PostgreSQL">
          <p className="text-slate-300 text-sm mb-2">Production recommended</p>
          <p className="text-slate-400 text-xs mb-4">
            High-availability datastore via NEST (Marchproxy).
          </p>
          {isAdmin && (
            <Button
              onClick={() => setShowModal(true)}
              variant="primary"
            >
              Migrate to PostgreSQL
            </Button>
          )}
        </Card>
      </div>

      {/* Migration Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-slate-900 rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-amber-400 mb-4">
              Migrate to PostgreSQL
            </h2>

            <div className="space-y-4 mb-4">
              <p className="text-yellow-600 text-sm">
                Warning: This will restart the SPIRE server. Ensure NEST is online
                before proceeding.
              </p>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Host
                </label>
                <input
                  type="text"
                  value={formData.host}
                  onChange={(e) =>
                    setFormData({ ...formData, host: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Port
                </label>
                <input
                  type="number"
                  value={formData.port}
                  onChange={(e) =>
                    setFormData({ ...formData, port: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Database Name
                </label>
                <input
                  type="text"
                  value={formData.db_name}
                  onChange={(e) =>
                    setFormData({ ...formData, db_name: e.target.value })
                  }
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>

              <div>
                <label className="block text-amber-400 text-sm mb-1">
                  Secret Name (K8s)
                </label>
                <input
                  type="text"
                  value={formData.secret_name}
                  onChange={(e) =>
                    setFormData({ ...formData, secret_name: e.target.value })
                  }
                  placeholder="spire-db-secret"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded text-slate-200 text-sm"
                />
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 px-4 py-2 bg-slate-700 text-slate-200 rounded hover:bg-slate-600 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleMigrate}
                disabled={submitting}
                className="flex-1 px-4 py-2 bg-red-900 text-red-100 rounded hover:bg-red-800 transition disabled:opacity-50"
              >
                {submitting ? 'Migrating...' : 'Migrate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
