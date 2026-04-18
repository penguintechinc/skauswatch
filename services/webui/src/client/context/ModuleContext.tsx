/**
 * ModuleContext — fetches the module registry from GET /api/v1/modules and
 * provides module availability flags to all components via React context.
 *
 * No auth is required for this endpoint; the server returns which sub-modules
 * are installed without any JWT.
 *
 * Usage:
 *   const { modules } = useModules();
 *   if (modules.checkpoint) { ... }
 *
 * The registry is fetched on mount and refreshed every 5 minutes so the UI
 * picks up modules that are installed while the app is open without requiring
 * a full page reload.
 */
import React, { createContext, useContext, useEffect, useRef, useState } from 'react';
import api from '../lib/api';
import type { ModuleMap } from '../types/modules';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MODULES: ModuleMap = {
  icebox: false,
  checkpoint: false,
  darwin: false,
  watcher: false,
  guardian: false,
  warden: false,
};

/** How often (ms) to re-fetch the module registry. */
const REFRESH_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// ---------------------------------------------------------------------------
// Context shape
// ---------------------------------------------------------------------------

interface ModuleContextValue {
  /** Current module availability map. All false until first fetch succeeds. */
  modules: ModuleMap;
  /** True while the initial fetch is in-flight. */
  isLoading: boolean;
}

const ModuleContext = createContext<ModuleContextValue>({
  modules: DEFAULT_MODULES,
  isLoading: true,
});

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Wrap the app (outside AuthProvider) with this so every component can read
 * module flags without extra prop-drilling.
 */
export function ModuleProvider({ children }: { children: React.ReactNode }) {
  const [modules, setModules] = useState<ModuleMap>(DEFAULT_MODULES);
  const [isLoading, setIsLoading] = useState(true);
  // Track whether the initial fetch has run so we can clear the loading flag.
  const initialFetchDone = useRef(false);

  const fetchModules = async () => {
    try {
      const response = await api.get<ModuleMap>('/modules');
      const data = response.data;

      // Merge with defaults so fields added to ModuleMap in the future don't
      // break older server responses that don't include the new keys.
      const merged: ModuleMap = { ...DEFAULT_MODULES, ...data };
      setModules(merged);

      console.log('[ModuleContext] modules loaded:', {
        icebox: merged.icebox,
        checkpoint: merged.checkpoint,
        darwin: merged.darwin,
        watcher: merged.watcher,
        guardian: merged.guardian,
        warden: merged.warden,
      });
    } catch (err) {
      // Silently keep the previous state — a failed refresh should not
      // collapse the UI. Log the error type only (no sensitive data).
      const errType = err instanceof Error ? err.constructor.name : typeof err;
      console.warn('[ModuleContext] module registry fetch failed:', errType);
    } finally {
      if (!initialFetchDone.current) {
        initialFetchDone.current = true;
        setIsLoading(false);
      }
    }
  };

  useEffect(() => {
    console.log('[ModuleContext] ModuleProvider mounted, fetching registry');
    fetchModules();

    const interval = setInterval(() => {
      console.log('[ModuleContext] periodic refresh');
      fetchModules();
    }, REFRESH_INTERVAL_MS);

    return () => {
      clearInterval(interval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <ModuleContext.Provider value={{ modules, isLoading }}>
      {children}
    </ModuleContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Returns the current module map and loading state.
 *
 * @example
 *   const { modules } = useModules();
 *   if (modules.icebox) { ... }
 */
export function useModules(): ModuleContextValue {
  return useContext(ModuleContext);
}
