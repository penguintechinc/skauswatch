import axios from 'axios';
import { getCsrfToken, isMutatingMethod, CSRF_HEADER_NAME } from '../utils/csrf';

// API base URL - uses proxy in development, direct in production
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

// Create axios instance. Auth is cookie-based (H2 audit fix): the manager
// backend sets HttpOnly `sw_access`/`sw_refresh` cookies on login/register/
// refresh, so the browser attaches them automatically — no JWT is ever read
// from or written to localStorage/sessionStorage.
const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach the CSRF token (read from the non-HttpOnly `sw_csrf` cookie) on
// every mutating request; GET/HEAD are exempt per the manager's CSRF policy.
api.interceptors.request.use(
  (config) => {
    if (isMutatingMethod(config.method)) {
      const csrfToken = getCsrfToken();
      if (csrfToken) {
        config.headers[CSRF_HEADER_NAME] = csrfToken;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor: on 401, attempt a single cookie-based refresh (the
// browser sends `sw_refresh` automatically) and retry. No tokens are ever
// read from or written to JS storage — the refresh endpoint rotates the
// HttpOnly cookies directly.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and we haven't retried yet, try to refresh the session
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const csrfToken = getCsrfToken();
        await axios.post(
          `${API_BASE_URL}/auth/refresh`,
          {},
          {
            withCredentials: true,
            headers: csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : {},
          }
        );

        // Refresh rotated the HttpOnly cookies; retry the original request.
        return api(originalRequest);
      } catch (refreshError) {
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
