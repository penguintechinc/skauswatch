import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { AuthUser } from '../types/vault';
import apiVault from '../lib/api';

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (user: AuthUser) => void;
  logout: () => Promise<void>;
  hasScope: (scope: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Auth is cookie-based (H2 audit fix): the manager sets HttpOnly
  // sw_access/sw_refresh cookies on login, invisible to JS by design — so
  // there is no stored token to read on mount. Instead, ask the backend
  // whether the browser's cookie jar carries a valid session.
  useEffect(() => {
    apiVault
      .get<{ data: AuthUser }>('/api/v1/me')
      .then((res: { data: { data: AuthUser } }) => {
        setUser(res.data.data);
        console.log('[AuthContext] Session validated', { userId: res.data.data.id });
      })
      .catch(() => {
        setUser(null);
        console.log('[AuthContext] No active session');
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback((newUser: AuthUser) => {
    // The login cookies were already set by the backend response — nothing
    // to store client-side, just sync local UI state.
    setUser(newUser);
    console.log('[AuthContext] Login successful', { userId: newUser.id });
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiVault.post('/auth/logout');
    } catch {
      // Best-effort — local state is cleared below regardless.
    } finally {
      setUser(null);
      console.log('[AuthContext] Logged out');
    }
  }, []);

  const hasScope = useCallback(
    (scope: string) => {
      if (!user) return false;
      return user.scopes.includes(scope) || user.scopes.includes('*:admin');
    },
    [user],
  );

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, hasScope }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
