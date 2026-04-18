import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { ModuleProvider } from './context/ModuleContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import RoleGuard from './components/RoleGuard';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Users from './pages/Users';
import UserDetail from './pages/UserDetail';
import Profile from './pages/Profile';
import Settings from './pages/Settings';
import ThreatIntel from './pages/ThreatIntel';
import S3Scan from './pages/S3Scan';
import Darwin from './pages/Darwin';
import UsersGroups from './pages/checkpoint/UsersGroups';
import UpstreamIDPs from './pages/checkpoint/UpstreamIDPs';
import OAuthClients from './pages/checkpoint/OAuthClients';
import SAMLProviders from './pages/checkpoint/SAMLProviders';
import LDAPAdapters from './pages/checkpoint/LDAPAdapters';
import CheckpointAudit from './pages/checkpoint/CheckpointAudit';
import CheckpointSettings from './pages/checkpoint/CheckpointSettings';

function App() {
  const { isAuthenticated, isLoading, checkAuth } = useAuth();

  useEffect(() => {
    console.log('[App] Starting auth check, isLoading:', isLoading);
    // Check auth with a fallback timeout
    const authPromise = checkAuth();

    authPromise
      .then((result) => {
        console.log('[App] Auth check completed, result:', result);
      })
      .catch((error) => {
        console.error('[App] Auth check failed:', error);
      });
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-dark-950">
        <div className="text-gold-400 text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <ModuleProvider>
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

        {/* Threat Intelligence - all authenticated users */}
        <Route path="/threat-intel" element={<ThreatIntel />} />

        {/* S3 Malware Scanning - all authenticated users */}
        <Route path="/s3-scan" element={<S3Scan />} />

        {/* Darwin AI Code Review - all authenticated users */}
        <Route path="/darwin" element={<Darwin />} />

        {/* Checkpoint Identity Platform - all authenticated users */}
        <Route path="/checkpoint/users" element={<UsersGroups />} />
        <Route path="/checkpoint/idps" element={<UpstreamIDPs />} />
        <Route path="/checkpoint/oauth2" element={<OAuthClients />} />
        <Route path="/checkpoint/saml" element={<SAMLProviders />} />
        <Route path="/checkpoint/ldap" element={<LDAPAdapters />} />
        <Route path="/checkpoint/audit" element={<CheckpointAudit />} />
        <Route
          path="/checkpoint/settings"
          element={
            <RoleGuard allowedRoles={['admin', 'maintainer']}>
              <CheckpointSettings />
            </RoleGuard>
          }
        />

        {/* Profile - all authenticated users */}
        <Route path="/profile" element={<Profile />} />

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
      </Route>

      {/* Catch all - redirect to dashboard or login */}
      <Route
        path="*"
        element={<Navigate to={isAuthenticated ? '/' : '/login'} replace />}
      />
    </Routes>
    </ModuleProvider>
  );
}

export default App;
