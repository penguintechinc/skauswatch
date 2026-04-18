import { TokenManager } from '@penguintechinc/react-aaa';
import type { TokenSet } from '@penguintechinc/react-aaa';
import axios from 'axios';

// API base URL - uses proxy in development, direct in production
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

// TokenManager from react-aaa handles:
// - sessionStorage persistence (more secure than localStorage)
// - Automatic refresh scheduling (60s before expiry)
// - JWT expiry checking
export const tokenManager = new TokenManager({
  onTokenExpired: () => {
    window.location.href = '/login';
  },
  onRefresh: async (refreshToken: string): Promise<TokenSet> => {
    const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
      refresh_token: refreshToken,
    });
    return {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in: response.data.expires_in || 1800,
      token_type: 'Bearer' as const,
    };
  },
});

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add authorization header
api.interceptors.request.use(
  (config) => {
    const token = tokenManager.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh on 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const tokenSet = tokenManager.getTokenSet();
      if (!tokenSet?.refresh_token) {
        tokenManager.clear();
        window.location.href = '/login';
        return Promise.reject(error);
      }

      try {
        const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
          refresh_token: tokenSet.refresh_token,
        });

        const newTokenSet: TokenSet = {
          access_token: response.data.access_token,
          refresh_token: response.data.refresh_token,
          expires_in: response.data.expires_in || 1800,
          token_type: 'Bearer' as const,
        };
        tokenManager.store(newTokenSet);

        originalRequest.headers.Authorization = `Bearer ${newTokenSet.access_token}`;
        return api(originalRequest);
      } catch {
        tokenManager.clear();
        window.location.href = '/login';
        return Promise.reject(error);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
