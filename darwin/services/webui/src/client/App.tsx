import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import RoleGuard from './components/RoleGuard';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import UserDetail from './pages/UserDetail';
import Profile from './pages/Profile';
import Settings from './pages/Settings';
import Repositories from './pages/Repositories';
import Tenants from './pages/Tenants';
import Teams from './pages/Teams';
import Roles from './pages/Roles';

function App() {
  const { isAuthenticated, isLoading, checkAuth } = useAuth();

  // Check authentication status on mount
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-950">
        <div className="text-gold-400 text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <Routes>
      {/* Public routes */}
      <Route
        path="/login"
        element={isAuthenticated ? <Navigate to="/" replace /> : <Login />}
      />

      {/* Protected routes with layout */}
      <Route
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        {/* Dashboard - all authenticated users */}
        <Route path="/" element={<Dashboard />} />
        <Route path="/dashboard" element={<Navigate to="/" replace />} />

        {/* Profile - all authenticated users */}
        <Route path="/profile" element={<Profile />} />

        {/* Repositories - Maintainer and Admin */}
        <Route
          path="/repositories"
          element={
            <RoleGuard allowedRoles={['admin', 'maintainer']}>
              <Repositories />
            </RoleGuard>
          }
        />

        {/* Settings - Maintainer and Admin */}
        <Route
          path="/settings"
          element={
            <RoleGuard allowedRoles={['admin', 'maintainer']}>
              <Settings />
            </RoleGuard>
          }
        />

        {/* User management - Admin only */}
        <Route
          path="/users"
          element={
            <RoleGuard allowedRoles={['admin']}>
              <Users />
            </RoleGuard>
          }
        />
        <Route
          path="/users/:id"
          element={
            <RoleGuard allowedRoles={['admin']}>
              <UserDetail />
            </RoleGuard>
          }
        />

        {/* Tenant management - Admin only */}
        <Route
          path="/tenants"
          element={
            <RoleGuard allowedRoles={['admin']}>
              <Tenants />
            </RoleGuard>
          }
        />

        {/* Team management - Admin and Maintainer */}
        <Route
          path="/teams"
          element={
            <RoleGuard allowedRoles={['admin', 'maintainer']}>
              <Teams />
            </RoleGuard>
          }
        />

        {/* Role management - Admin only */}
        <Route
          path="/roles"
          element={
            <RoleGuard allowedRoles={['admin']}>
              <Roles />
            </RoleGuard>
          }
        />
      </Route>

      {/* Catch all - redirect to dashboard or login */}
      <Route
        path="*"
        element={<Navigate to={isAuthenticated ? '/' : '/login'} replace />}
      />
    </Routes>
  );
}

export default App;
