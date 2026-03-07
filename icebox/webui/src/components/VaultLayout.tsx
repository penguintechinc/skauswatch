import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { SidebarMenu } from '@penguintechinc/react-libs';
import {
  LayoutDashboard,
  KeyRound,
  Timer,
  Share2,
  Cloud,
  ShieldCheck,
  Terminal,
  ScrollText,
  Settings,
  LogOut,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.tsx';

const NAV_CATEGORIES = [
  {
    header: 'Vault',
    items: [
      { name: 'Dashboard', href: '/vault', icon: LayoutDashboard },
      { name: 'Secrets', href: '/vault/secrets', icon: KeyRound },
      { name: 'JIT Access', href: '/vault/jit', icon: Timer },
      { name: 'One-Time Secrets', href: '/vault/one-time', icon: Share2 },
    ],
  },
  {
    header: 'Cloud',
    items: [{ name: 'Cloud Sync', href: '/vault/sync', icon: Cloud }],
  },
  {
    header: 'PKI / SSH',
    items: [
      { name: 'PKI Certs', href: '/vault/pki', icon: ShieldCheck },
      { name: 'SSH CA', href: '/vault/ssh', icon: Terminal },
    ],
  },
  {
    header: 'Security',
    items: [
      { name: 'Audit Log', href: '/vault/audit', icon: ScrollText },
      { name: 'Settings', href: '/vault/settings', icon: Settings },
    ],
  },
];

export default function VaultLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex min-h-screen bg-slate-900">
      <SidebarMenu
        logo={
          <div className="flex items-center gap-2 px-4 py-3">
            <KeyRound className="text-amber-400" size={24} />
            <span className="text-amber-400 font-bold text-lg">IceBox</span>
          </div>
        }
        categories={NAV_CATEGORIES}
        currentPath={location.pathname}
        onNavigate={(href) => navigate(href)}
        footer={
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
            <span className="text-slate-400 text-sm truncate">{user?.email}</span>
            <button
              onClick={handleLogout}
              className="text-slate-400 hover:text-amber-400 transition-colors"
              aria-label="Logout"
            >
              <LogOut size={18} />
            </button>
          </div>
        }
      />
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
