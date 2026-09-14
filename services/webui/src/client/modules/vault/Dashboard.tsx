import { useQuery } from '@tanstack/react-query';
import { KeyRound, Timer, Cloud, ShieldAlert } from 'lucide-react';
import apiVault from '../../lib/api';
import type { ApiResponse } from '../../types/vault';

interface DashboardStats {
  secret_count: number;
  jit_pending: number;
  sync_integrations: number;
  expiring_certs_30d: number;
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  color: string;
}) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-5 flex items-center gap-4">
      <div className={`p-3 rounded-lg ${color}`}>
        <Icon size={24} className="text-white" />
      </div>
      <div>
        <p className="text-slate-400 text-sm">{label}</p>
        <p className="text-amber-400 text-2xl font-bold">{value}</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const res = await apiVault.get<ApiResponse<DashboardStats>>('/api/v1/dashboard');
      return res.data.data!;
    },
  });

  console.log('[Dashboard] mounted', { loading: isLoading });

  return (
    <div>
      <h1 className="text-2xl font-bold text-amber-400 mb-6">Vault Dashboard</h1>

      {isLoading ? (
        <div className="text-slate-400">Loading stats...</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            icon={KeyRound}
            label="Total Secrets"
            value={data?.secret_count ?? 0}
            color="bg-amber-600"
          />
          <StatCard
            icon={Timer}
            label="JIT Pending"
            value={data?.jit_pending ?? 0}
            color="bg-sky-600"
          />
          <StatCard
            icon={Cloud}
            label="Cloud Integrations"
            value={data?.sync_integrations ?? 0}
            color="bg-emerald-600"
          />
          <StatCard
            icon={ShieldAlert}
            label="Certs Expiring (30d)"
            value={data?.expiring_certs_30d ?? 0}
            color="bg-rose-600"
          />
        </div>
      )}

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-5">
        <h2 className="text-amber-400 font-semibold mb-2">Quick Actions</h2>
        <p className="text-slate-400 text-sm">
          Use the sidebar to navigate to Secrets, JIT Access, Cloud Sync, and more.
        </p>
      </div>
    </div>
  );
}
