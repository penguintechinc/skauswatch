import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { svidTtlApi } from '../api/svidTtl';
import type { SvidTtlSettings as SvidTtlSettingsData } from '../types/svidTtl';
import { formatTtl, validateTtlInput, extractStatus } from '../utils/svidTtl';
import Card from './Card';

// Bounds/default fall back to the documented contract if the GET response
// hasn't loaded yet — the server remains authoritative (400 on PUT outside
// range) regardless of what the client assumes here.
const FALLBACK_MIN_SECONDS = 60;
const FALLBACK_MAX_SECONDS = 86400;
const FALLBACK_DEFAULT_SECONDS = 300;

/**
 * Super-admin-only settings panel for the SPIFFE X.509-SVID and JWT-SVID
 * TTLs (`GET`/`PUT /api/v1/admin/svid-ttl`). Renders nothing for
 * Admin/Maintainer/Viewer — a UX-only gate on top of the backend's own
 * super-admin enforcement.
 */
export default function SvidTtlSettings() {
  const { isSuperAdmin } = useAuth();
  const superAdmin = isSuperAdmin();

  const [settings, setSettings] = useState<SvidTtlSettingsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [x509Raw, setX509Raw] = useState('');
  const [jwtRaw, setJwtRaw] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await svidTtlApi.get();
      setSettings(data);
      setX509Raw(String(data.x509_ttl_seconds));
      setJwtRaw(String(data.jwt_ttl_seconds));
      console.log('[SvidTtlSettings] Loaded settings', {
        x509_ttl_seconds: data.x509_ttl_seconds,
        jwt_ttl_seconds: data.jwt_ttl_seconds,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load SVID TTL settings';
      setLoadError(msg);
      console.error('[SvidTtlSettings] Load failed', { error: msg });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!superAdmin) return;
    loadSettings();
  }, [superAdmin, loadSettings]);

  // Hidden entirely for non-super-admins — the backend also rejects with
  // 403, this just keeps the control off the page for anyone who can't use it.
  if (!superAdmin) {
    return null;
  }

  const min = settings?.min_seconds ?? FALLBACK_MIN_SECONDS;
  const max = settings?.max_seconds ?? FALLBACK_MAX_SECONDS;
  const defaultSeconds = settings?.default_seconds ?? FALLBACK_DEFAULT_SECONDS;

  const x509Validation = validateTtlInput(x509Raw, min, max);
  const jwtValidation = validateTtlInput(jwtRaw, min, max);
  const isValid = !x509Validation.error && !jwtValidation.error;

  const handleSave = async () => {
    if (!isValid) return;

    const payload = {
      x509_ttl_seconds: x509Validation.value,
      jwt_ttl_seconds: jwtValidation.value,
    };

    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    console.log('[SvidTtlSettings] Update submitted', payload);

    try {
      await svidTtlApi.update(payload);
      setSaveSuccess(true);
      console.log('[SvidTtlSettings] Update succeeded', payload);
      await loadSettings();
    } catch (err) {
      const status = extractStatus(err);
      const msg =
        status === 403
          ? 'Insufficient permissions — super-admin required'
          : status === 400
            ? `Value out of range — must be between ${formatTtl(min)} and ${formatTtl(max)}`
            : err instanceof Error
              ? err.message
              : 'Failed to update SVID TTL settings';
      setSaveError(msg);
      console.error('[SvidTtlSettings] Update failed', { status });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="SVID TTL">
      <div className="space-y-6" data-testid="svid-ttl-settings">
        <p className="text-dark-400 text-sm">
          Controls the lifetime of SPIFFE SVIDs issued to workloads. Default is{' '}
          {formatTtl(defaultSeconds)}. Allowed range: {formatTtl(min)}–{formatTtl(max)}.
        </p>

        {loading ? (
          <div
            data-testid="svid-ttl-loading"
            className="h-24 bg-dark-800 rounded-lg animate-pulse"
          />
        ) : loadError ? (
          <p className="text-red-400 text-sm" data-testid="svid-ttl-load-error">
            {loadError}
          </p>
        ) : (
          <>
            <div>
              <label htmlFor="svid-ttl-x509" className="block text-gold-400 text-sm mb-1">
                X.509-SVID TTL (seconds)
              </label>
              <input
                id="svid-ttl-x509"
                data-testid="svid-ttl-x509-input"
                type="number"
                className="input"
                value={x509Raw}
                min={min}
                max={max}
                onChange={(e) => {
                  setX509Raw(e.target.value);
                  setSaveSuccess(false);
                }}
                aria-invalid={Boolean(x509Validation.error)}
                aria-describedby={x509Validation.error ? 'svid-ttl-x509-error' : undefined}
              />
              <p className="text-dark-500 text-xs mt-1">
                Current: {settings ? formatTtl(settings.x509_ttl_seconds) : '—'}
              </p>
              {x509Validation.error && (
                <p
                  id="svid-ttl-x509-error"
                  data-testid="svid-ttl-x509-error"
                  className="text-red-400 text-xs mt-1"
                >
                  {x509Validation.error}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="svid-ttl-jwt" className="block text-gold-400 text-sm mb-1">
                JWT-SVID TTL (seconds)
              </label>
              <input
                id="svid-ttl-jwt"
                data-testid="svid-ttl-jwt-input"
                type="number"
                className="input"
                value={jwtRaw}
                min={min}
                max={max}
                onChange={(e) => {
                  setJwtRaw(e.target.value);
                  setSaveSuccess(false);
                }}
                aria-invalid={Boolean(jwtValidation.error)}
                aria-describedby={jwtValidation.error ? 'svid-ttl-jwt-error' : undefined}
              />
              <p className="text-dark-500 text-xs mt-1">
                Current: {settings ? formatTtl(settings.jwt_ttl_seconds) : '—'}
              </p>
              {jwtValidation.error && (
                <p
                  id="svid-ttl-jwt-error"
                  data-testid="svid-ttl-jwt-error"
                  className="text-red-400 text-xs mt-1"
                >
                  {jwtValidation.error}
                </p>
              )}
            </div>

            {saveError && (
              <p className="text-red-400 text-sm" data-testid="svid-ttl-save-error">
                {saveError}
              </p>
            )}
            {saveSuccess && (
              <p className="text-green-400 text-sm" data-testid="svid-ttl-save-success">
                SVID TTL settings updated.
              </p>
            )}

            <button
              type="button"
              onClick={handleSave}
              disabled={!isValid || saving}
              data-testid="svid-ttl-save-button"
              className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-gold-500"
              aria-label="Save SVID TTL settings"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </>
        )}
      </div>
    </Card>
  );
}
