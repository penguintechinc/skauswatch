import { create } from 'zustand';
import api from '../lib/api';
import type { User, LoginCredentials, AuthState } from '../types';

interface AuthStore extends AuthState {
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  fetchUser: () => Promise<void>;
  checkAuth: () => Promise<boolean>;
  setUser: (user: User | null) => void;
}

// Auth is cookie-based (H2 audit fix): the manager backend sets HttpOnly
// sw_access/sw_refresh cookies (and a JS-readable sw_csrf cookie) on
// login/register/refresh — invisible to JS by design. This store therefore
// has nothing to persist to localStorage; `isAuthenticated`/`user` are
// always re-derived from a live /auth/me call (see checkAuth) rather than
// cached client-side. NOTE: previously wrapped in zustand's `persist`
// middleware, which silently wrote accessToken/refreshToken to
// localStorage under the `auth-storage` key — a token-storage site not
// visible to a plain grep for "localStorage".
export const useAuthStore = create<AuthStore>()((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  login: async (credentials: LoginCredentials) => {
    try {
      // Cookies are set by the response itself; the body is not read for
      // tokens. Immediately hydrate user state from the new session.
      await api.post('/auth/login', credentials);
      const response = await api.get('/auth/me');
      set({
        user: response.data,
        isAuthenticated: true,
        isLoading: false,
      });
    } catch (error) {
      set({
        user: null,
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
      set({
        user: null,
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
    // No client-visible token to check for presence — the cookie (if any)
    // is HttpOnly, so the only way to know is to ask the backend.
    try {
      const response = await api.get('/auth/me');
      set({
        user: response.data,
        isAuthenticated: true,
        isLoading: false,
      });
      return true;
    } catch {
      set({
        user: null,
        isAuthenticated: false,
        isLoading: false,
      });
      return false;
    }
  },

  setUser: (user: User | null) => {
    set({ user });
  },
}));

// Hook for components
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
    isSuperAdmin: () => store.user?.role === 'super_admin',
  };
};
