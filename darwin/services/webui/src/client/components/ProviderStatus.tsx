import React, { useState, useEffect } from 'react';

interface ProviderHealth {
  name: 'openai' | 'anthropic' | 'local';
  status: 'healthy' | 'degraded' | 'down';
  latency: number;
  lastChecked: string;
  errorRate: number;
}

interface ProviderStatusProps {
  providers?: ProviderHealth[];
  refreshInterval?: number;
  onRefresh?: () => Promise<void>;
}

const statusColors: Record<string, string> = {
  healthy: 'bg-green-900 text-green-200',
  degraded: 'bg-yellow-900 text-yellow-200',
  down: 'bg-red-900 text-red-200',
};

const statusLabels: Record<string, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
};

export default function ProviderStatus({
  providers = [],
  refreshInterval = 30000,
  onRefresh,
}: ProviderStatusProps) {
  const [health, setHealth] = useState<ProviderHealth[]>(providers);
  const [loading, setLoading] = useState(false);
  const [lastRefreshTime, setLastRefreshTime] = useState<Date>(new Date());

  useEffect(() => {
    const interval = setInterval(() => {
      handleRefresh();
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [refreshInterval, onRefresh]);

  const handleRefresh = async () => {
    if (onRefresh && !loading) {
      try {
        setLoading(true);
        await onRefresh();
        setLastRefreshTime(new Date());
      } catch (error) {
        console.error('Failed to refresh provider status:', error);
      } finally {
        setLoading(false);
      }
    }
  };

  const getHealthIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return '●';
      case 'degraded':
        return '◐';
      case 'down':
        return '○';
      default:
        return '?';
    }
  };

  const formatLatency = (ms: number) => {
    return `${Math.round(ms)}ms`;
  };

  const formatLastChecked = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);

    if (diffMins > 0) {
      return `${diffMins}m ago`;
    }
    return `${diffSecs}s ago`;
  };

  if (health.length === 0) {
    return (
      <div className="card">
        <p className="text-center text-elder-text-light py-4">No providers configured</p>
      </div>
    );
  }

  return (
    <div className="card space-y-3">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gold-400">AI Provider Status</h3>
        <button
          onClick={handleRefresh}
          disabled={loading}
          className="px-3 py-1 rounded text-xs bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors font-medium"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      <p className="text-xs text-elder-text-light">
        Last checked: {formatLastChecked(lastRefreshTime.toISOString())}
      </p>

      <div className="space-y-2">
        {health.map((provider) => {
          const statusColor = statusColors[provider.status];
          const statusLabel = statusLabels[provider.status];

          return (
            <div
              key={provider.name}
              className="flex items-center justify-between p-3 rounded bg-elder-bg-darker border border-elder-border"
            >
              <div className="flex items-center gap-3 flex-1">
                <span className={`text-lg ${statusColor.split(' ')[1].replace('text-', 'text-')}`}>
                  {getHealthIcon(provider.status)}
                </span>
                <div className="flex-1">
                  <p className="text-sm font-medium text-elder-text-base capitalize">
                    {provider.name}
                  </p>
                  <p className="text-xs text-elder-text-light">
                    Error rate: {(provider.errorRate * 100).toFixed(2)}%
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-xs text-elder-text-light">Latency</p>
                  <p className="text-sm font-medium text-elder-text-base">
                    {formatLatency(provider.latency)}
                  </p>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium whitespace-nowrap ${statusColor}`}>
                  {statusLabel}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
