import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppConsoleVersion } from '@penguintechinc/react-libs';
import { AuthProvider } from './context/AuthContext.tsx';
import ProtectedRoute from './components/ProtectedRoute.tsx';
import VaultLayout from './components/VaultLayout.tsx';
import LoginPage from './pages/LoginPage.tsx';
import Dashboard from './pages/Dashboard.tsx';
import Secrets from './pages/Secrets.tsx';
import JitAccess from './pages/JitAccess.tsx';
import OneTimePage from './pages/OneTimePage.tsx';
import CloudSync from './pages/CloudSync.tsx';
import PkiPage from './pages/PkiPage.tsx';
import SshPage from './pages/SshPage.tsx';
import AuditPage from './pages/AuditPage.tsx';
import SettingsPage from './pages/SettingsPage.tsx';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AppConsoleVersion
          appName="IceBox"
          webuiVersion={import.meta.env.VITE_VERSION || '0.0.0'}
          webuiBuildEpoch={Number(import.meta.env.VITE_BUILD_TIME) || 0}
          environment={import.meta.env.MODE}
          apiStatusUrl="/api/v1/status"
          metadata={{ 'Service': 'IceBox Vault' }}
        />
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/vault"
              element={
                <ProtectedRoute>
                  <VaultLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="secrets" element={<Secrets />} />
              <Route path="jit" element={<JitAccess />} />
              <Route path="one-time" element={<OneTimePage />} />
              <Route path="sync" element={<CloudSync />} />
              <Route path="pki" element={<PkiPage />} />
              <Route path="ssh" element={<SshPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
            <Route path="/" element={<Navigate to="/vault" replace />} />
            <Route path="*" element={<Navigate to="/vault" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}
