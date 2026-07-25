import { useLocation, useNavigate } from 'react-router-dom';
import { SidebarMenu } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';
import type { NavCategory } from '../types';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

// Navigation structure - Elder pattern with categories
const navigation: NavCategory[] = [
  {
    label: 'Main',
    items: [
      { label: 'Dashboard', path: '/', icon: '📊' },
      { label: 'Profile', path: '/profile', icon: '👤' },
    ],
  },
  {
    label: 'Security',
    items: [
      { label: 'SPIRE Identity', path: '/security/spire', icon: '🔐', roles: ['admin', 'maintainer'] },
      { label: 'Threat Intel', path: '/threat-intel', icon: '🛡️' },
      { label: 'S3 Scanning', path: '/s3-scan', icon: '🔍' },
      { label: 'Darwin AI Review', path: '/darwin', icon: '🤖' },
    ],
  },
  {
    label: 'Management',
    roles: ['admin', 'maintainer'],
    items: [
      { label: 'Settings', path: '/settings', icon: '⚙️', roles: ['admin', 'maintainer'] },
    ],
  },
  {
    label: 'Administration',
    roles: ['admin'],
    items: [
      { label: 'Users', path: '/users', icon: '👥', roles: ['admin'] },
    ],
  },
];

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleNavigate = (path: string) => {
    navigate(path);
  };

  // Footer items for user info and logout
  const footerItems = user
    ? [
        {
          label: user.full_name,
          subtitle: user.email,
          badge: user.role,
          badgeColor: user.role === 'admin' ? 'gold' : user.role === 'maintainer' ? 'blue' : 'gray',
        },
        {
          label: 'Logout',
          icon: '🚪',
          onClick: logout,
          color: 'red',
        },
      ]
    : [];

  return (
    <SidebarMenu
      // @ts-expect-error - NavCategory vs MenuCategory type mismatch in shared library
      categories={navigation}
      currentPath={location.pathname}
      onNavigate={handleNavigate}
      userRole={user?.role}
      isCollapsed={collapsed}
      onToggleCollapse={onToggle}
      // @ts-expect-error - footerItems type mismatch in shared library
      footerItems={footerItems}
      appName="SkausWatch"
      theme={{
        sidebarBackground: '#1A1A1F',
        sidebarBorder: '#2A2A2F',
        activeItemBackground: '#2A2A35',
        activeItemColor: '#D4AF37',
        itemHoverBackground: '#25252A',
        categoryColor: '#9CA3AF',
        itemColor: '#E5E7EB',
        accentColor: '#D4AF37',
      }}
    />
  );
}
