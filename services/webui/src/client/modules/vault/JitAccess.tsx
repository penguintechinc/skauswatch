import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { CheckCircle, XCircle, Clock } from 'lucide-react';
import apiVault from '../../lib/api';
import type { JitRequest, ApiResponse, PaginatedResponse, JitStatus } from '../../types/vault';
import { useAuth } from '../../context/VaultAuthContext';

const STATUS_COLORS: Record<JitStatus, string> = {
  pending: 'text-amber-400',
  approved: 'text-emerald-400',
  rejected: 'text-rose-400',
  expired: 'text-slate-500',
  revoked: 'text-slate-500',
};

function JitCard({
  req,
  isApprover,
  onApprove,
  onReject,
}: {
  req: JitRequest;
  isApprover: boolean;
  onApprove: (id: string, duration: number) => void;
  onReject: (id: string) => void;
}) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Clock size={14} className={STATUS_COLORS[req.status]} />
            <span className={`text-sm font-medium ${STATUS_COLORS[req.status]}`}>
              {req.status.toUpperCase()}
            </span>
          </div>
          <p className="text-slate-200 mt-1 font-medium">
            Secret: <span className="text-amber-400">{req.secret_id}</span>
          </p>
          <p className="text-slate-400 text-sm">Reason: {req.reason}</p>
          <p className="text-slate-400 text-sm">
            Requested: {Math.round(req.requested_duration_seconds / 60)} min
          </p>
        </div>
        {isApprover && req.status === 'pending' && (
          <div className="flex gap-2">
            <button
              onClick={() => onApprove(req.id, req.requested_duration_seconds)}
              className="text-emerald-400 hover:text-emerald-300 transition-colors p-1"
              title="Approve"
            >
              <CheckCircle size={20} />
            </button>
            <button
              onClick={() => onReject(req.id)}
              className="text-rose-400 hover:text-rose-300 transition-colors p-1"
              title="Reject"
            >
              <XCircle size={20} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function JitAccess() {
  const qc = useQueryClient();
  const { hasScope } = useAuth();
  const [activeTab, setActiveTab] = useState<'pending' | 'mine'>('pending');
  const isApprover = hasScope('jit:approve');

  const pendingQuery = useQuery({
    queryKey: ['jit-pending'],
    queryFn: async () => {
      const res = await apiVault.get<ApiResponse<PaginatedResponse<JitRequest>>>(
        '/api/v1/jit/requests?status=pending',
      );
      return res.data.data!;
    },
    enabled: isApprover,
  });

  const myQuery = useQuery({
    queryKey: ['jit-mine'],
    queryFn: async () => {
      const res = await apiVault.get<ApiResponse<PaginatedResponse<JitRequest>>>(
        '/api/v1/jit/requests?mine=true',
      );
      return res.data.data!;
    },
  });

  const approveMutation = useMutation({
    mutationFn: ({ id, duration }: { id: string; duration: number }) =>
      apiVault.patch(`/api/v1/jit/requests/${id}/approve`, { approved_duration_seconds: duration }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jit-pending'] });
      qc.invalidateQueries({ queryKey: ['jit-mine'] });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: (id: string) => apiVault.patch(`/api/v1/jit/requests/${id}/reject`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jit-pending'] });
      qc.invalidateQueries({ queryKey: ['jit-mine'] });
    },
  });

  const handleApprove = (id: string, duration: number) => {
    approveMutation.mutate({ id, duration });
  };

  const handleReject = (id: string) => {
    rejectMutation.mutate(id);
  };

  console.log('[JitAccess] mounted', { isApprover });

  const tabs = [
    ...(isApprover ? [{ key: 'pending' as const, label: 'Pending Approvals' }] : []),
    { key: 'mine' as const, label: 'My Requests' },
  ];

  const activeItems =
    activeTab === 'pending'
      ? (pendingQuery.data?.items ?? [])
      : (myQuery.data?.items ?? []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-amber-400 mb-6">JIT Access</h1>

      {/* Tabs */}
      <div className="flex border-b border-slate-700 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            data-testid={`tab-${tab.key}`}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 ${
              activeTab === tab.key
                ? 'border-sky-500 text-sky-400'
                : 'border-transparent text-amber-400 hover:text-amber-300'
            }`}
          >
            {tab.label}
            {tab.key === 'pending' && (pendingQuery.data?.total ?? 0) > 0 && (
              <span className="ml-2 bg-amber-500 text-slate-900 text-xs font-bold px-1.5 py-0.5 rounded-full">
                {pendingQuery.data!.total}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="space-y-3">
        {activeItems.map((req) => (
          <JitCard
            key={req.id}
            req={req}
            isApprover={isApprover}
            onApprove={handleApprove}
            onReject={handleReject}
          />
        ))}
        {activeItems.length === 0 && (
          <div className="text-slate-500 text-center py-8">No requests.</div>
        )}
      </div>
    </div>
  );
}
