import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import api from '../lib/api';

export interface LicenseFeatures {
  valid: boolean;
  tier: 'free' | 'professional' | 'enterprise';
  flags: Record<string, boolean>;
  features: Record<string, boolean>;
}

interface EntitlementsContextType {
  features: LicenseFeatures | null;
  isLoading: boolean;
  error: string | null;
  getFlag: (flag: string) => boolean;
  hasFeature: (feature: string) => boolean;
  getTier: () => 'free' | 'professional' | 'enterprise';
}

const EntitlementsContext = createContext<EntitlementsContextType | undefined>(undefined);

export function EntitlementsProvider({ children }: { children: ReactNode }) {
  const [features, setFeatures] = useState<LicenseFeatures | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchFeatures = async () => {
      try {
        setIsLoading(true);
        const response = await api.get<{ data: LicenseFeatures }>('/license/features');
        setFeatures(response.data.data);
        setError(null);
      } catch (err) {
        console.error('[EntitlementsProvider] Failed to fetch license features:', err);
        // Graceful degradation: assume all flags OFF on fetch failure
        setFeatures({
          valid: false,
          tier: 'free',
          flags: {
            'skauswatch.vault': false,
            'skauswatch.codescan': false,
          },
          features: {},
        });
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setIsLoading(false);
      }
    };

    fetchFeatures();
  }, []);

  const getFlag = (flag: string): boolean => {
    if (!features) return false;
    return features.flags[flag] ?? false;
  };

  const hasFeature = (feature: string): boolean => {
    if (!features) return false;
    return features.features[feature] ?? false;
  };

  const getTier = () => {
    return features?.tier ?? 'free';
  };

  const value: EntitlementsContextType = {
    features,
    isLoading,
    error,
    getFlag,
    hasFeature,
    getTier,
  };

  return (
    <EntitlementsContext.Provider value={value}>
      {children}
    </EntitlementsContext.Provider>
  );
}

export function useEntitlements() {
  const context = useContext(EntitlementsContext);
  if (context === undefined) {
    throw new Error('useEntitlements must be used within EntitlementsProvider');
  }
  return context;
}
