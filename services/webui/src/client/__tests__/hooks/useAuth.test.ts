/**
 * useAuth hook and useAuthStore tests.
 *
 * Tests zustand auth store state transitions:
 * - Initial state
 * - Login success and failure
 * - Logout (with and without API error)
 * - checkAuth token validation
 * - setUser manual override
 * - hasRole/isAdmin/isMaintainer/isViewer helpers
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';

// Mock the TokenManager from react-aaa
const mockTokenManager = {
  store: vi.fn(),
  getAccessToken: vi.fn(),
  getTokenSet: vi.fn(),
  isExpired: vi.fn(),
  clear: vi.fn(),
};

// Mock the api module before importing the store
const mockApi = {
  post: vi.fn(),
  get: vi.fn(),
};

vi.mock('@/lib/api', () => ({
  default: mockApi,
  tokenManager: mockTokenManager,
}));

import { useAuthStore, useAuth } from '@/hooks/useAuth';

const mockUser = {
  id: 1,
  email: 'admin@test.com',
  full_name: 'Admin User',
  role: 'admin' as const,
  is_active: true,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: null,
};

describe('useAuthStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset store to initial state
    useAuthStore.setState({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
    });
  });

  it('has correct initial state', () => {
    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.accessToken).toBeNull();
    expect(state.refreshToken).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(state.isLoading).toBe(true);
  });

  describe('login', () => {
    it('sets user and tokens on success', async () => {
      mockApi.post.mockResolvedValueOnce({
        data: {
          access_token: 'access-123',
          refresh_token: 'refresh-456',
          expires_in: 1800,
          user: mockUser,
        },
      });

      await act(async () => {
        await useAuthStore
          .getState()
          .login({ email: 'admin@test.com', password: 'pass' });
      });

      const state = useAuthStore.getState();
      expect(state.user).toEqual(mockUser);
      expect(state.accessToken).toBe('access-123');
      expect(state.refreshToken).toBe('refresh-456');
      expect(state.isAuthenticated).toBe(true);
      expect(state.isLoading).toBe(false);
      expect(mockTokenManager.store).toHaveBeenCalledWith({
        access_token: 'access-123',
        refresh_token: 'refresh-456',
        expires_in: 1800,
        token_type: 'Bearer',
      });
    });

    it('clears state on failure', async () => {
      mockApi.post.mockRejectedValueOnce(new Error('Invalid credentials'));

      await expect(
        act(async () => {
          await useAuthStore
            .getState()
            .login({ email: 'bad@test.com', password: 'wrong' });
        })
      ).rejects.toThrow('Invalid credentials');

      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(mockTokenManager.clear).toHaveBeenCalled();
    });
  });

  describe('logout', () => {
    it('clears state and tokens', async () => {
      useAuthStore.setState({
        user: mockUser,
        accessToken: 'token',
        refreshToken: 'refresh',
        isAuthenticated: true,
      });
      mockApi.post.mockResolvedValueOnce({});

      await act(async () => {
        await useAuthStore.getState().logout();
      });

      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(mockTokenManager.clear).toHaveBeenCalled();
    });

    it('clears state even when API fails', async () => {
      useAuthStore.setState({
        user: mockUser,
        isAuthenticated: true,
      });
      mockApi.post.mockRejectedValueOnce(new Error('Network error'));

      await act(async () => {
        await useAuthStore.getState().logout();
      });

      expect(useAuthStore.getState().user).toBeNull();
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
      expect(mockTokenManager.clear).toHaveBeenCalled();
    });
  });

  describe('fetchUser', () => {
    it('sets user on success', async () => {
      mockApi.get.mockResolvedValueOnce({ data: mockUser });

      await act(async () => {
        await useAuthStore.getState().fetchUser();
      });

      expect(useAuthStore.getState().user).toEqual(mockUser);
      expect(useAuthStore.getState().isLoading).toBe(false);
    });

    it('sets user null on failure', async () => {
      mockApi.get.mockRejectedValueOnce(new Error('Unauthorized'));

      await act(async () => {
        await useAuthStore.getState().fetchUser();
      });

      expect(useAuthStore.getState().user).toBeNull();
      expect(useAuthStore.getState().isLoading).toBe(false);
    });
  });

  describe('checkAuth', () => {
    it('returns false when no token', async () => {
      mockTokenManager.getAccessToken.mockReturnValue(null);

      let result: boolean;
      await act(async () => {
        result = await useAuthStore.getState().checkAuth();
      });

      expect(result!).toBe(false);
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });

    it('returns false when token is expired', async () => {
      mockTokenManager.getAccessToken.mockReturnValue('expired-jwt');
      mockTokenManager.isExpired.mockReturnValue(true);

      let result: boolean;
      await act(async () => {
        result = await useAuthStore.getState().checkAuth();
      });

      expect(result!).toBe(false);
      expect(mockTokenManager.clear).toHaveBeenCalled();
    });

    it('returns true and sets user when token valid', async () => {
      mockTokenManager.getAccessToken.mockReturnValue('valid-token');
      mockTokenManager.isExpired.mockReturnValue(false);
      mockApi.get.mockResolvedValueOnce({ data: mockUser });

      let result: boolean;
      await act(async () => {
        result = await useAuthStore.getState().checkAuth();
      });

      expect(result!).toBe(true);
      expect(useAuthStore.getState().user).toEqual(mockUser);
      expect(useAuthStore.getState().isAuthenticated).toBe(true);
    });

    it('returns false and clears when API rejects', async () => {
      mockTokenManager.getAccessToken.mockReturnValue('expired-token');
      mockTokenManager.isExpired.mockReturnValue(false);
      mockApi.get.mockRejectedValueOnce(new Error('Token expired'));

      let result: boolean;
      await act(async () => {
        result = await useAuthStore.getState().checkAuth();
      });

      expect(result!).toBe(false);
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
      expect(mockTokenManager.clear).toHaveBeenCalled();
    });
  });

  describe('setUser', () => {
    it('sets user directly', () => {
      act(() => {
        useAuthStore.getState().setUser(mockUser);
      });
      expect(useAuthStore.getState().user).toEqual(mockUser);
    });

    it('clears user with null', () => {
      useAuthStore.setState({ user: mockUser });
      act(() => {
        useAuthStore.getState().setUser(null);
      });
      expect(useAuthStore.getState().user).toBeNull();
    });
  });
});

describe('useAuth hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: true,
    });
  });

  it('returns hasRole that checks user role', () => {
    useAuthStore.setState({ user: mockUser });
    const { result } = renderHook(() => useAuth());

    expect(result.current.hasRole(['admin'])).toBe(true);
    expect(result.current.hasRole(['viewer'])).toBe(false);
    expect(result.current.hasRole(['admin', 'maintainer'])).toBe(true);
  });

  it('hasRole returns false when no user', () => {
    const { result } = renderHook(() => useAuth());
    expect(result.current.hasRole(['admin'])).toBe(false);
  });

  it('isAdmin returns true for admin role', () => {
    useAuthStore.setState({ user: mockUser });
    const { result } = renderHook(() => useAuth());
    expect(result.current.isAdmin()).toBe(true);
    expect(result.current.isMaintainer()).toBe(false);
    expect(result.current.isViewer()).toBe(false);
  });

  it('isMaintainer returns true for maintainer role', () => {
    useAuthStore.setState({
      user: { ...mockUser, role: 'maintainer' },
    });
    const { result } = renderHook(() => useAuth());
    expect(result.current.isMaintainer()).toBe(true);
    expect(result.current.isAdmin()).toBe(false);
  });

  it('isViewer returns true for viewer role', () => {
    useAuthStore.setState({
      user: { ...mockUser, role: 'viewer' },
    });
    const { result } = renderHook(() => useAuth());
    expect(result.current.isViewer()).toBe(true);
  });
});
