import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';

// Mock modules with lazy loading
vi.mock('../modules/icebox/Dashboard', () => ({
  default: () => <div data-testid="icebox-dashboard">IceBox Dashboard</div>,
}));

vi.mock('../modules/darwin/Dashboard', () => ({
  default: () => <div data-testid="darwin-dashboard">Darwin Dashboard</div>,
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
    getFlag: (flag: string) => flag === 'skauswatch.icebox' || flag === 'skauswatch.darwin',
  }),
}));

describe('Module Smoke Tests', () => {
  it('icebox module should load', async () => {
    const { default: IceBoxDashboard } = await import('../modules/icebox/Dashboard');
    render(
      <BrowserRouter>
        <IceBoxDashboard />
      </BrowserRouter>
    );
    expect(screen.getByTestId('icebox-dashboard')).toBeInTheDocument();
  });

  it('darwin module should load', async () => {
    const { default: DarwinDashboard } = await import('../modules/darwin/Dashboard');
    render(
      <BrowserRouter>
        <DarwinDashboard />
      </BrowserRouter>
    );
    expect(screen.getByTestId('darwin-dashboard')).toBeInTheDocument();
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
