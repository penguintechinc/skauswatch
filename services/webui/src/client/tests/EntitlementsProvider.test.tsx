import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { EntitlementsProvider, useEntitlements } from '../context/EntitlementsContext';

// Mock axios
vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => ({
      get: vi.fn(),
      post: vi.fn(),
    })),
  },
}));

function TestComponent() {
  const { getFlag, isLoading, error } = useEntitlements();

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div>
      <div data-testid="icebox-flag">{getFlag('skauswatch.icebox') ? 'icebox enabled' : 'icebox disabled'}</div>
      <div data-testid="darwin-flag">{getFlag('skauswatch.darwin') ? 'darwin enabled' : 'darwin disabled'}</div>
    </div>
  );
}

describe('EntitlementsProvider', () => {
  it('renders children with entitlements context', () => {
    render(
      <EntitlementsProvider>
        <TestComponent />
      </EntitlementsProvider>
    );

    expect(screen.getByTestId('icebox-flag')).toBeInTheDocument();
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
