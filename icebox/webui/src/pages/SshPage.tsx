import { useQuery } from '@tanstack/react-query';
import { Terminal, ExternalLink } from 'lucide-react';
import apiClient from '../services/apiClient.ts';
import type { ApiResponse } from '../types/icebox.ts';

interface SshSummary {
  total_keys: number;
  active_certs: number;
  expired_certs: number;
  principals: number;
}

export default function SshPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['ssh-summary'],
    queryFn: async () => {
      const res = await apiClient.get<ApiResponse<SshSummary>>('/api/v1/ssh/summary');
      return res.data.data!;
    },
  });

  console.log('[SshPage] mounted');

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-amber-400">SSH Certificate Authority</h1>
        <a
          href="/ssh"
          className="flex items-center gap-2 text-sky-400 hover:text-sky-300 text-sm transition-colors"
        >
          <ExternalLink size={14} />
          Open SSH CA
        </a>
      </div>

      <p className="text-slate-400 text-sm mb-6">
        SSH certificates are managed by the IceBox SSH CA service. This dashboard shows a summary.
      </p>

      {isLoading ? (
        <div className="text-slate-400">Loading SSH summary...</div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'SSH Keys', value: data?.total_keys ?? 0, color: 'text-amber-400' },
            { label: 'Active Certs', value: data?.active_certs ?? 0, color: 'text-emerald-400' },
            { label: 'Expired Certs', value: data?.expired_certs ?? 0, color: 'text-rose-400' },
            { label: 'Principals', value: data?.principals ?? 0, color: 'text-sky-400' },
          ].map((stat) => (
            <div
              key={stat.label}
              className="bg-slate-800 border border-slate-700 rounded-lg p-4 flex items-center gap-3"
            >
              <Terminal size={20} className={stat.color} />
              <div>
                <p className="text-slate-400 text-xs">{stat.label}</p>
                <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="mt-6 bg-slate-800 border border-slate-700 rounded-lg p-5">
        <p className="text-slate-400 text-sm">
          Use the SSH CA UI to issue user and host certificates, manage key revocation lists (KRL),
          and configure principals. The SSH CA API is available at{' '}
          <code className="text-amber-400">/api/v1/ssh/</code>.
        </p>
      </div>
    </div>
  );
}
