import { useEffect, lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';
import { useEntitlements } from './context/EntitlementsContext';
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
import Spire from './pages/Spire';

// Lazy-loaded module pages
const IceBoxDashboard = lazy(() => import('./modules/icebox/Dashboard'));
const IceBoxSecrets = lazy(() => import('./modules/icebox/Secrets'));
const IceBoxJitAccess = lazy(() => import('./modules/icebox/JitAccess'));
const IceBoxOneTime = lazy(() => import('./modules/icebox/OneTimePage'));
const IceBoxCloudSync = lazy(() => import('./modules/icebox/CloudSync'));
const IceBoxPki = lazy(() => import('./modules/icebox/PkiPage'));
const IceBoxSsh = lazy(() => import('./modules/icebox/SshPage'));
const IceBoxAudit = lazy(() => import('./modules/icebox/AuditPage'));
const IceBoxSettings = lazy(() => import('./modules/icebox/SettingsPage'));

// Loading fallback component
function LoadingFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900">
      <div className="text-amber-400 text-xl">Loading...</div>
    </div>
  );
}

function App() {
  const { isAuthenticated, isLoading, checkAuth } = useAuth();
  const { getFlag } = useEntitlements();

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

        {/* IceBox Vault Module - gated by license flag */}
        {getFlag('skauswatch.icebox') && (
          <Route path="/icebox/*" element={
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route index element={<IceBoxDashboard />} />
                <Route path="secrets" element={<IceBoxSecrets />} />
                <Route path="jit" element={<IceBoxJitAccess />} />
                <Route path="one-time" element={<IceBoxOneTime />} />
                <Route path="sync" element={<IceBoxCloudSync />} />
                <Route path="pki" element={<IceBoxPki />} />
                <Route path="ssh" element={<IceBoxSsh />} />
                <Route path="audit" element={<IceBoxAudit />} />
                <Route path="settings" element={<IceBoxSettings />} />
              </Routes>
            </Suspense>
          } />
        )}

        {/* SPIRE Identity Management - Maintainer and Admin */}
        <Route
          path="/security/spire"
          element={
            <RoleGuard allowedRoles={['admin', 'maintainer']}>
              <Spire />
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
  );
}

export default App;
