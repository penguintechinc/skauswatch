import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { AuthUser } from '../types/vault';
import apiVault from '../lib/api';

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  loading: boolean;
  login: (token: string, user: AuthUser) => void;
  logout: () => void;
  hasScope: (scope: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Validate stored token on mount
  useEffect(() => {
    const stored = localStorage.getItem('vaultToken');
    if (!stored) {
      setLoading(false);
      return;
    }

    apiVault
      .get<{ data: AuthUser }>('/api/v1/me', {
        headers: { Authorization: `Bearer ${stored}` },
      })
      .then((res: { data: { data: AuthUser } }) => {
        setToken(stored);
        setUser(res.data.data);
        console.log('[AuthContext] Token validated', { userId: res.data.data.id });
      })
      .catch(() => {
        localStorage.removeItem('vaultToken');
        console.log('[AuthContext] Stored token invalid — cleared');
      })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback((newToken: string, newUser: AuthUser) => {
    localStorage.setItem('vaultToken', newToken);
    setToken(newToken);
    setUser(newUser);
    console.log('[AuthContext] Login successful', { userId: newUser.id });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('vaultToken');
    setToken(null);
    setUser(null);
    console.log('[AuthContext] Logged out');
  }, []);

  const hasScope = useCallback(
    (scope: string) => {
      if (!user) return false;
      return user.scopes.includes(scope) || user.scopes.includes('*:admin');
    },
    [user],
  );

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout, hasScope }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
