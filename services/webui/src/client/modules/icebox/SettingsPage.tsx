import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { KeyRound, ShieldCheck, RotateCcw, CheckCircle, AlertTriangle } from 'lucide-react';
import apiIceBox from '../../lib/apiIceBox';
import type { LicenseInfo, ApiResponse } from '../../types/icebox';
import { useAuth } from '../../context/IceBoxAuthContext';

interface MekStatus {
  current_dek_version: number;
  last_rotated_at: string | null;
  secrets_count: number;
}

interface MekRotateResult {
  rows_updated: number;
  new_dek_version: number;
}

type SettingsTab = 'mek' | 'license';

export default function SettingsPage() {
  const { hasScope } = useAuth();
  const [activeTab, setActiveTab] = useState<SettingsTab>('license');
  const [licenseKey, setLicenseKey] = useState('');
  const [rotateConfirm, setRotateConfirm] = useState(false);
  const [rotateResult, setRotateResult] = useState<MekRotateResult | null>(null);

  const isAdmin = hasScope('secrets:admin');

  console.log('[SettingsPage] mounted', { isAdmin });

  // License info
  const {
    data: licenseData,
    isLoading: licenseLoading,
    refetch: refetchLicense,
  } = useQuery({
    queryKey: ['license-info'],
    queryFn: async () => {
      const res = await apiIceBox.get<ApiResponse<LicenseInfo>>('/api/v1/admin/license');
      return res.data.data!;
    },
    enabled: isAdmin,
  });

  // MEK status
  const { data: mekData, isLoading: mekLoading, refetch: refetchMek } = useQuery({
    queryKey: ['mek-status'],
    queryFn: async () => {
      const res = await apiIceBox.get<ApiResponse<MekStatus>>('/api/v1/admin/mek/status');
      return res.data.data!;
    },
    enabled: isAdmin && activeTab === 'mek',
  });

  // License update mutation
  const licenseMutation = useMutation({
    mutationFn: (key: string) =>
      apiIceBox.post<ApiResponse<LicenseInfo>>('/api/v1/admin/license', { license_key: key }),
    onSuccess: () => {
      setLicenseKey('');
      refetchLicense();
      console.log('[SettingsPage] License key updated');
    },
  });

  // MEK rotation mutation
  const mekMutation = useMutation({
    mutationFn: () =>
      apiIceBox.post<ApiResponse<MekRotateResult>>('/api/v1/admin/mek/rotate'),
    onSuccess: (res) => {
      setRotateResult(res.data.data!);
      setRotateConfirm(false);
      refetchMek();
      console.log('[SettingsPage] MEK rotation complete');
    },
  });

  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <ShieldCheck size={40} className="mb-4 text-slate-600" />
        <p className="text-lg font-medium">Administrator access required</p>
        <p className="text-sm mt-1">Settings are only available to vault administrators.</p>
      </div>
    );
  }

  const tabs: { key: SettingsTab; label: string; icon: React.ReactNode }[] = [
    { key: 'license', label: 'License', icon: <ShieldCheck size={16} /> },
    { key: 'mek', label: 'Encryption Key', icon: <KeyRound size={16} /> },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold text-amber-400 mb-6">Settings</h1>

      {/* Tabs */}
      <div className="flex border-b border-slate-700 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            data-testid={`tab-${tab.key}`}
            onClick={() => {
              setActiveTab(tab.key);
              setRotateConfirm(false);
              setRotateResult(null);
            }}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? 'border-sky-400 text-sky-400'
                : 'border-transparent text-amber-400 hover:text-amber-300'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* License Tab */}
      {activeTab === 'license' && (
        <div className="space-y-6">
          {/* Current Status */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 className="text-amber-400 font-semibold mb-4">License Status</h2>
            {licenseLoading ? (
              <p className="text-slate-400">Loading license info...</p>
            ) : licenseData ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  {licenseData.valid ? (
                    <CheckCircle size={18} className="text-emerald-400" />
                  ) : (
                    <AlertTriangle size={18} className="text-rose-400" />
                  )}
                  <span
                    className={`font-medium ${licenseData.valid ? 'text-emerald-400' : 'text-rose-400'}`}
                  >
                    {licenseData.valid ? 'Valid License' : 'No Valid License'}
                  </span>
                </div>

                {licenseData.validated_at && (
                  <p className="text-slate-400 text-sm">
                    Last validated:{' '}
                    <span className="text-slate-300">
                      {new Date(licenseData.validated_at).toLocaleString()}
                    </span>
                  </p>
                )}

                {licenseData.entitlements && licenseData.entitlements.length > 0 && (
                  <div>
                    <p className="text-slate-400 text-sm mb-2">Entitlements:</p>
                    <div className="flex flex-wrap gap-2">
                      {licenseData.entitlements.map((e) => (
                        <span
                          key={e}
                          className="text-xs bg-sky-900/50 text-sky-300 px-2 py-0.5 rounded"
                        >
                          {e}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {!licenseData.valid && (
                  <p className="text-slate-500 text-sm">
                    Auto-bypass active for Penguin Tech internal domains. Enter a license key
                    for external deployments.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-slate-500">Unable to load license information.</p>
            )}
          </div>

          {/* Update License Key */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 className="text-amber-400 font-semibold mb-4">Update License Key</h2>
            <div className="space-y-3">
              <input
                className="w-full bg-slate-900 border border-slate-600 rounded px-3 py-2 text-slate-200 placeholder-slate-500 font-mono text-sm"
                placeholder="PENG-XXXX-XXXX-XXXX-XXXX-ABCD"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
              />
              {licenseMutation.isError && (
                <p className="text-rose-400 text-sm">
                  Failed to update license key. Check that the key is valid and the license
                  server is reachable.
                </p>
              )}
              {licenseMutation.isSuccess && (
                <p className="text-emerald-400 text-sm">License key updated successfully.</p>
              )}
              <button
                onClick={() => licenseMutation.mutate(licenseKey)}
                disabled={!licenseKey || licenseMutation.isPending}
                className="bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-900 font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                {licenseMutation.isPending ? 'Validating...' : 'Save License Key'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MEK Rotation Tab */}
      {activeTab === 'mek' && (
        <div className="space-y-6">
          {/* Current MEK Status */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 className="text-amber-400 font-semibold mb-4">Master Encryption Key</h2>
            {mekLoading ? (
              <p className="text-slate-400">Loading encryption status...</p>
            ) : mekData ? (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <KeyRound size={18} className="text-amber-400" />
                  <div>
                    <p className="text-slate-300 text-sm">
                      Current DEK version:{' '}
                      <span className="font-mono text-amber-400 font-bold">
                        {mekData.current_dek_version}
                      </span>
                    </p>
                    {mekData.last_rotated_at && (
                      <p className="text-slate-500 text-xs">
                        Last rotated: {new Date(mekData.last_rotated_at).toLocaleString()}
                      </p>
                    )}
                  </div>
                </div>
                <p className="text-slate-400 text-sm">
                  {mekData.secrets_count} secret
                  {mekData.secrets_count !== 1 ? 's' : ''} will have their DEKs re-wrapped
                  during rotation.
                </p>
              </div>
            ) : (
              <p className="text-slate-500">Unable to load MEK status.</p>
            )}
          </div>

          {/* Rotation Result */}
          {rotateResult && (
            <div className="bg-emerald-900/30 border border-emerald-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle size={16} className="text-emerald-400" />
                <p className="text-emerald-400 font-semibold">Rotation complete</p>
              </div>
              <p className="text-slate-300 text-sm">
                {rotateResult.rows_updated} DEK
                {rotateResult.rows_updated !== 1 ? 's' : ''} re-wrapped. New version:{' '}
                <span className="font-mono font-bold text-amber-400">
                  {rotateResult.new_dek_version}
                </span>
              </p>
            </div>
          )}

          {/* Rotation Action */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-5">
            <h2 className="text-amber-400 font-semibold mb-3">Rotate Master Encryption Key</h2>
            <div className="bg-amber-900/30 border border-amber-700 rounded-lg p-4 mb-4">
              <div className="flex items-start gap-2">
                <AlertTriangle size={16} className="text-amber-400 mt-0.5 shrink-0" />
                <div className="text-sm text-amber-200">
                  <p className="font-medium mb-1">Before rotating:</p>
                  <ul className="list-disc list-inside space-y-1 text-amber-300/80">
                    <li>Update <code className="font-mono">ICEBOX_MEK</code> in all pod environments first</li>
                    <li>Rotation re-wraps all DEKs under the new MEK — this cannot be undone</li>
                    <li>Secret ciphertext is not re-encrypted (only DEK wrappers change)</li>
                    <li>The old MEK must remain available until rotation completes</li>
                  </ul>
                </div>
              </div>
            </div>

            {!rotateConfirm ? (
              <button
                onClick={() => setRotateConfirm(true)}
                className="flex items-center gap-2 bg-rose-700 hover:bg-rose-600 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                <RotateCcw size={16} />
                Rotate MEK
              </button>
            ) : (
              <div className="space-y-3">
                <p className="text-rose-300 text-sm font-medium">
                  Are you sure? This will re-wrap all secret DEKs under the new MEK.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => mekMutation.mutate()}
                    disabled={mekMutation.isPending}
                    className="flex items-center gap-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-semibold px-4 py-2 rounded-lg transition-colors"
                  >
                    <RotateCcw size={16} />
                    {mekMutation.isPending ? 'Rotating...' : 'Confirm Rotation'}
                  </button>
                  <button
                    onClick={() => setRotateConfirm(false)}
                    className="bg-slate-700 hover:bg-slate-600 text-slate-200 px-4 py-2 rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                </div>
                {mekMutation.isError && (
                  <p className="text-rose-400 text-sm">
                    Rotation failed. Ensure the new MEK is configured in the environment and
                    try again.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
