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
import CodeScan from './pages/CodeScan';
import Spire from './pages/Spire';

// Lazy-loaded module pages
const VaultDashboard = lazy(() => import('./modules/vault/Dashboard'));
const VaultSecrets = lazy(() => import('./modules/vault/Secrets'));
const VaultJitAccess = lazy(() => import('./modules/vault/JitAccess'));
const VaultOneTime = lazy(() => import('./modules/vault/OneTimePage'));
const VaultCloudSync = lazy(() => import('./modules/vault/CloudSync'));
const VaultPki = lazy(() => import('./modules/vault/PkiPage'));
const VaultSsh = lazy(() => import('./modules/vault/SshPage'));
const VaultAudit = lazy(() => import('./modules/vault/AuditPage'));
const VaultSettings = lazy(() => import('./modules/vault/SettingsPage'));

// CodeScan module pages
const CodeScanDashboard = lazy(() => import('./modules/codescan/Dashboard'));
const CodeScanAnalytics = lazy(() => import('./modules/codescan/Analytics'));
const CodeScanIssues = lazy(() => import('./modules/codescan/Issues'));
const CodeScanReviews = lazy(() => import('./modules/codescan/Reviews'));
const CodeScanRepositories = lazy(() => import('./modules/codescan/Repositories'));
const CodeScanSettings = lazy(() => import('./modules/codescan/Settings'));
const CodeScanUsers = lazy(() => import('./modules/codescan/Users'));
const CodeScanRoles = lazy(() => import('./modules/codescan/Roles'));
const CodeScanTeams = lazy(() => import('./modules/codescan/Teams'));
const CodeScanTenants = lazy(() => import('./modules/codescan/Tenants'));
const CodeScanReviewDetail = lazy(() => import('./modules/codescan/ReviewDetail'));
const CodeScanUserDetail = lazy(() => import('./modules/codescan/UserDetail'));
const CodeScanRepositorySettings = lazy(() => import('./modules/codescan/RepositorySettings'));

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

        {/* CodeScan AI Code Review - gated by license flag */}
        {getFlag('skauswatch.codescan') ? (
          <Route path="/codescan/*" element={
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route index element={<CodeScanDashboard />} />
                <Route path="analytics" element={<CodeScanAnalytics />} />
                <Route path="issues" element={<CodeScanIssues />} />
                <Route path="reviews" element={<CodeScanReviews />} />
                <Route path="reviews/:id" element={<CodeScanReviewDetail />} />
                <Route path="repositories" element={<CodeScanRepositories />} />
                <Route path="repositories/:id/settings" element={<CodeScanRepositorySettings />} />
                <Route path="settings" element={<CodeScanSettings />} />
                <Route path="users" element={<CodeScanUsers />} />
                <Route path="users/:id" element={<CodeScanUserDetail />} />
                <Route path="roles" element={<CodeScanRoles />} />
                <Route path="teams" element={<CodeScanTeams />} />
                <Route path="tenants" element={<CodeScanTenants />} />
              </Routes>
            </Suspense>
          } />
        ) : (
          <Route path="/codescan" element={<CodeScan />} />
        )}

        {/* Vault Vault Module - gated by license flag */}
        {getFlag('skauswatch.vault') && (
          <Route path="/vault/*" element={
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route index element={<VaultDashboard />} />
                <Route path="secrets" element={<VaultSecrets />} />
                <Route path="jit" element={<VaultJitAccess />} />
                <Route path="one-time" element={<VaultOneTime />} />
                <Route path="sync" element={<VaultCloudSync />} />
                <Route path="pki" element={<VaultPki />} />
                <Route path="ssh" element={<VaultSsh />} />
                <Route path="audit" element={<VaultAudit />} />
                <Route path="settings" element={<VaultSettings />} />
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
