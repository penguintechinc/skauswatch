/**
 * RoleGuard component tests.
 *
 * Tests role-based access control rendering:
 * - Redirects unauthenticated users to /login
 * - Redirects unauthorized roles to fallbackPath
 * - Renders children for allowed roles
 */
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

// Mock useAuth hook
const mockUseAuth = vi.fn();
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

import RoleGuard from '@/components/RoleGuard';

function renderWithRouter(ui: React.ReactElement, initialEntries = ['/']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
  );
}

describe('RoleGuard', () => {
  beforeEach(() => {
    mockUseAuth.mockReset();
  });

  it('renders children when user has allowed role', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 1, role: 'admin', email: 'a@t.com', full_name: 'Admin' },
      hasRole: (roles: string[]) => roles.includes('admin'),
    });

    renderWithRouter(
      <RoleGuard allowedRoles={['admin']}>
        <div>Protected Content</div>
      </RoleGuard>
    );

    expect(screen.getByText('Protected Content')).toBeInTheDocument();
  });

  it('redirects when user has disallowed role', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 2, role: 'viewer', email: 'v@t.com', full_name: 'Viewer' },
      hasRole: (roles: string[]) => roles.includes('viewer'),
    });

    renderWithRouter(
      <RoleGuard allowedRoles={['admin']}>
        <div>Admin Only</div>
      </RoleGuard>
    );

    expect(screen.queryByText('Admin Only')).not.toBeInTheDocument();
  });

  it('redirects unauthenticated users (no user)', () => {
    mockUseAuth.mockReturnValue({
      user: null,
      hasRole: () => false,
    });

    renderWithRouter(
      <RoleGuard allowedRoles={['admin']}>
        <div>Protected</div>
      </RoleGuard>
    );

    expect(screen.queryByText('Protected')).not.toBeInTheDocument();
  });

  it('allows maintainer when maintainer is in allowedRoles', () => {
    mockUseAuth.mockReturnValue({
      user: { id: 3, role: 'maintainer', email: 'm@t.com', full_name: 'Maint' },
      hasRole: (roles: string[]) => roles.includes('maintainer'),
    });

    renderWithRouter(
      <RoleGuard allowedRoles={['admin', 'maintainer']}>
        <div>Maintainer Access</div>
      </RoleGuard>
    );

    expect(screen.getByText('Maintainer Access')).toBeInTheDocument();
  });
});
