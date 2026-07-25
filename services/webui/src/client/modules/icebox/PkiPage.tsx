import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, ExternalLink } from 'lucide-react';
import apiIceBox from '../../lib/apiIceBox';
import type { ApiResponse } from '../../types/icebox';

interface PkiSummary {
  total_certs: number;
  expiring_30d: number;
  expired: number;
  cas: number;
}

export default function PkiPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['pki-summary'],
    queryFn: async () => {
      const res = await apiIceBox.get<ApiResponse<PkiSummary>>('/api/v1/pki/summary');
      return res.data.data!;
    },
  });

  console.log('[PkiPage] mounted');

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-amber-400">PKI Certificates</h1>
        <a
          href="/pki"
          className="flex items-center gap-2 text-sky-400 hover:text-sky-300 text-sm transition-colors"
        >
          <ExternalLink size={14} />
          Open PKI Server
        </a>
      </div>

      <p className="text-slate-400 text-sm mb-6">
        Certificate lifecycle is managed by the IceBox PKI service. This dashboard shows a summary.
      </p>

      {isLoading ? (
        <div className="text-slate-400">Loading PKI summary...</div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Total Certs', value: data?.total_certs ?? 0, color: 'text-amber-400' },
            { label: 'Certificate Authorities', value: data?.cas ?? 0, color: 'text-sky-400' },
            {
              label: 'Expiring in 30d',
              value: data?.expiring_30d ?? 0,
              color: 'text-amber-500',
            },
            { label: 'Expired', value: data?.expired ?? 0, color: 'text-rose-400' },
          ].map((stat) => (
            <div
              key={stat.label}
              className="bg-slate-800 border border-slate-700 rounded-lg p-4 flex items-center gap-3"
            >
              <ShieldCheck size={20} className={stat.color} />
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
          Use the PKI Server UI to issue certificates, manage CAs, revoke certificates, and download
          CRLs. The PKI service API is available at <code className="text-amber-400">/api/v1/pki/</code>.
        </p>
      </div>
    </div>
  );
}
