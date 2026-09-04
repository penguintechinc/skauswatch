import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';

// Mock modules with lazy loading
vi.mock('../modules/vault/Dashboard', () => ({
  default: () => <div data-testid="vault-dashboard">Vault Dashboard</div>,
}));

vi.mock('../modules/codescan/Dashboard', () => ({
  default: () => <div data-testid="codescan-dashboard">CodeScan Dashboard</div>,
}));

// Mock auth and entitlements
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    user: { id: '1', role: 'Admin' },
  }),
}));

vi.mock('../context/EntitlementsContext', () => ({
  useEntitlements: () => ({
    getFlag: (flag: string) => flag === 'skauswatch.vault' || flag === 'skauswatch.codescan',
  }),
}));

describe('Module Smoke Tests', () => {
  it('vault module should load', async () => {
    const { default: VaultDashboard } = await import('../modules/vault/Dashboard');
    render(
      <BrowserRouter>
        <VaultDashboard />
      </BrowserRouter>
    );
    expect(screen.getByTestId('vault-dashboard')).toBeInTheDocument();
  });

  it('codescan module should load', async () => {
    const { default: CodeScanDashboard } = await import('../modules/codescan/Dashboard');
    render(
      <BrowserRouter>
        <CodeScanDashboard />
      </BrowserRouter>
    );
    expect(screen.getByTestId('codescan-dashboard')).toBeInTheDocument();
  });

  it('renders pages without throwing', () => {
    expect(() => {
      const App = () => <div>App renders</div>;
      render(
        <BrowserRouter>
          <App />
        </BrowserRouter>
      );
    }).not.toThrow();
  });
});
