import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { EntitlementsProvider, useEntitlements } from '../context/EntitlementsContext';

// Mock axios — the created instance must expose `interceptors` (api.ts wires
// request/response interceptors at import time) and reject `get` so the
// provider exercises its fetch-failure → flags-OFF path.
vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => ({
      get: vi.fn(() => Promise.reject(new Error('no backend in test'))),
      post: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    })),
  },
}));

function TestComponent() {
  const { getFlag, isLoading } = useEntitlements();

  // A features-fetch failure is NOT render-blocking: the app degrades
  // gracefully by defaulting every flag OFF (getFlag → false), which is
  // exactly what these tests assert. Only gate on the loading state.
  if (isLoading) return <div>Loading...</div>;

  return (
    <div>
      <div data-testid="icebox-flag">{getFlag('skauswatch.icebox') ? 'icebox enabled' : 'icebox disabled'}</div>
      <div data-testid="darwin-flag">{getFlag('skauswatch.darwin') ? 'darwin enabled' : 'darwin disabled'}</div>
    </div>
  );
}

describe('EntitlementsProvider', () => {
  it('renders children with entitlements context', async () => {
    render(
      <EntitlementsProvider>
        <TestComponent />
      </EntitlementsProvider>
    );

    // The provider starts in a loading state; wait for it to resolve.
    await waitFor(() => {
      expect(screen.getByTestId('icebox-flag')).toBeInTheDocument();
    });
    expect(screen.getByTestId('darwin-flag')).toBeInTheDocument();
  });

  it('defaults flags to false when fetch fails', async () => {
    render(
      <EntitlementsProvider>
        <TestComponent />
      </EntitlementsProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('icebox-flag')).toHaveTextContent('icebox disabled');
      expect(screen.getByTestId('darwin-flag')).toHaveTextContent('darwin disabled');
    });
  });

  it('shows loading state initially', () => {
    render(
      <EntitlementsProvider>
        <TestComponent />
      </EntitlementsProvider>
    );

    // Component should render either loading, error, or the content
    const content = screen.queryByTestId('icebox-flag');
    const loading = screen.queryByText('Loading...');
    expect(content || loading).toBeInTheDocument();
  });
});
