import { create } from 'zustand';
import type { TokenSet } from '@penguintechinc/react-aaa';
import api, { tokenManager } from '../lib/api';
import type { User, LoginCredentials, AuthState } from '../types';

interface AuthStore extends AuthState {
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  fetchUser: () => Promise<void>;
  checkAuth: () => Promise<boolean>;
  setUser: (user: User | null) => void;
}

export const useAuthStore = create<AuthStore>()(
  (set) => ({
    user: null,
    accessToken: null,
    refreshToken: null,
    isAuthenticated: false,
    isLoading: true,

    login: async (credentials: LoginCredentials) => {
      try {
        const response = await api.post('/auth/login', credentials);
        const { access_token, refresh_token, expires_in, user } = response.data;

        // Store tokens via react-aaa TokenManager (sessionStorage + auto-refresh)
        const tokenSet: TokenSet = {
          access_token,
          refresh_token,
          expires_in: expires_in || 1800,
          token_type: 'Bearer' as const,
        };
        tokenManager.store(tokenSet);

        set({
          user,
          accessToken: access_token,
          refreshToken: refresh_token,
          isAuthenticated: true,
          isLoading: false,
        });
      } catch (error) {
        tokenManager.clear();
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
        });
        throw error;
      }
    },

    logout: async () => {
      try {
        await api.post('/auth/logout');
      } catch {
        // Ignore logout errors
      } finally {
        tokenManager.clear();
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
        });
      }
    },

    fetchUser: async () => {
      try {
        const response = await api.get('/auth/me');
        set({ user: response.data, isLoading: false });
      } catch {
        set({ user: null, isLoading: false });
      }
    },

    checkAuth: async () => {
      const token = tokenManager.getAccessToken();
      if (!token || tokenManager.isExpired()) {
        tokenManager.clear();
        set({ isAuthenticated: false, isLoading: false });
        return false;
      }

      try {
        const response = await api.get('/auth/me');
        set({
          user: response.data,
          accessToken: token,
          isAuthenticated: true,
          isLoading: false,
        });
        return true;
      } catch {
        tokenManager.clear();
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
        });
        return false;
      }
    },

    setUser: (user: User | null) => {
      set({ user });
    },
  })
);

// Hook for components — same interface as before
export const useAuth = () => {
  const store = useAuthStore();

  return {
    user: store.user,
    isAuthenticated: store.isAuthenticated,
    isLoading: store.isLoading,
    login: store.login,
    logout: store.logout,
    checkAuth: store.checkAuth,
    hasRole: (roles: string[]) => {
      if (!store.user) return false;
      return roles.includes(store.user.role);
    },
    isAdmin: () => store.user?.role === 'admin',
    isMaintainer: () => store.user?.role === 'maintainer',
    isViewer: () => store.user?.role === 'viewer',
  };
};
