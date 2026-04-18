import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import { useModules } from '../../context/ModuleContext';
import type { LDAPAgent } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type AgentStatus = 'online' | 'degraded' | 'offline';

function computeStatus(lastSeenAt: string): AgentStatus {
  const diffSecs = (Date.now() - new Date(lastSeenAt).getTime()) / 1000;
  if (diffSecs < 120) return 'online';
  if (diffSecs < 600) return 'degraded';
  return 'offline';
}

function StatusBadge({ lastSeenAt }: { lastSeenAt: string }) {
  const status = computeStatus(lastSeenAt);
  const styles: Record<AgentStatus, string> = {
    online: 'bg-green-900/50 text-green-400 border border-green-700',
    degraded: 'bg-yellow-900/50 text-yellow-400 border border-yellow-700',
    offline: 'bg-red-900/50 text-red-400 border border-red-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs ${styles[status]}`}>
      {status}
    </span>
  );
}

function formatLastSeen(ts: string): string {
  const diffMs = Date.now() - new Date(ts).getTime();
  const secs = Math.floor(diffMs / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return new Date(ts).toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

function EmptyState() {
  return (
    <Card>
      <div className="py-8 text-center">
        <p className="text-dark-400 mb-4">No LDAP agents registered. Deploy the checkpoint-ldap-agent in your remote VPC.</p>
        <pre className="inline-block text-left bg-dark-900 border border-dark-700 rounded p-4 text-xs font-mono text-green-400 whitespace-pre-wrap">
{`kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: checkpoint-ldap-agent
spec:
  selector:
    matchLabels:
      app: checkpoint-ldap-agent
  template:
    metadata:
      labels:
        app: checkpoint-ldap-agent
    spec:
      containers:
      - name: agent
        image: penguintechinc/checkpoint-ldap-agent:latest
        env:
        - name: CHECKPOINT_URL
          value: "https://your-checkpoint-host"
        - name: CHECKPOINT_TOKEN
          valueFrom:
            secretKeyRef:
              name: checkpoint-ldap-secret
              key: token
EOF`}
        </pre>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function LDAPAdapters() {
  const { modules } = useModules();
  const [agents, setAgents] = useState<LDAPAgent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    console.log('[LDAPAdapters] Fetching LDAP agents');
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: LDAPAgent[] } | LDAPAgent[]>('/checkpoint/ldap/agents');
      const data = res.data;
      setAgents(Array.isArray(data) ? data : (data as { items: LDAPAgent[] }).items ?? []);
    } catch (err: unknown) {
      setError('Failed to load LDAP agents.');
      console.error('[LDAPAdapters] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    console.log('[LDAPAdapters] Mounted', { checkpointEnabled: modules.checkpoint });
    void fetchAgents();
  }, [fetchAgents, modules.checkpoint]);

  if (!modules.checkpoint) {
    return <div className="text-dark-400 py-8 text-center">Checkpoint module is not enabled.</div>;
  }

  const onlineCount = agents.filter(a => computeStatus(a.last_seen_at) === 'online').length;
  const offlineCount = agents.filter(a => computeStatus(a.last_seen_at) === 'offline').length;
  const degradedCount = agents.filter(a => computeStatus(a.last_seen_at) === 'degraded').length;

  return (
    <div>
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">LDAP Adapters</h1>
          <p className="text-dark-400 mt-1">Remote LDAP agent monitoring.</p>
          {!isLoading && agents.length > 0 && (
            <div className="flex gap-2 mt-2">
              <span className="px-2 py-0.5 rounded-full text-xs bg-green-900/50 text-green-400 border border-green-700">
                {onlineCount} online
              </span>
              {degradedCount > 0 && (
                <span className="px-2 py-0.5 rounded-full text-xs bg-yellow-900/50 text-yellow-400 border border-yellow-700">
                  {degradedCount} degraded
                </span>
              )}
              {offlineCount > 0 && (
                <span className="px-2 py-0.5 rounded-full text-xs bg-red-900/50 text-red-400 border border-red-700">
                  {offlineCount} offline
                </span>
              )}
            </div>
          )}
        </div>
        <button
          data-testid="refresh-agents-btn"
          className="btn btn-secondary text-sm"
          onClick={() => void fetchAgents()}
          disabled={isLoading}
        >
          {isLoading ? 'Refreshing…' : '↺ Refresh'}
        </button>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading LDAP agents…</div>
      ) : agents.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">Agent ID</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Hostname</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Site</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Version</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Last Seen</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent, i) => (
                <tr
                  key={agent.agent_id}
                  data-testid={`agent-row-${i}`}
                  className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors"
                >
                  <td className="py-2 pr-4 font-mono text-xs text-dark-400">{agent.agent_id}</td>
                  <td className="py-2 pr-4 text-dark-200">{agent.hostname}</td>
                  <td className="py-2 pr-4 text-dark-400">{agent.site_name}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-dark-400">{agent.version}</td>
                  <td className="py-2 pr-4 text-dark-400 text-xs">{formatLastSeen(agent.last_seen_at)}</td>
                  <td className="py-2 pr-4">
                    <StatusBadge lastSeenAt={agent.last_seen_at} />
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
