import { useLocation, useNavigate } from 'react-router-dom';
import { SidebarMenu } from '@penguintechinc/react-libs';
import { useAuth } from '../hooks/useAuth';
import { useModules } from '../context/ModuleContext';
import type { NavCategory } from '../types';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

// Static navigation — always shown regardless of installed modules.
const STATIC_NAVIGATION: NavCategory[] = [
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

// IceBox nav section — shown only when modules.icebox is true.
const ICEBOX_CATEGORY: NavCategory = {
  label: 'IceBox',
  items: [
    { label: 'Secrets', path: '/icebox/secrets', icon: '🔑' },
    { label: 'JIT Access', path: '/icebox/jit', icon: '⏱️' },
    { label: 'One-Time', path: '/icebox/one-time', icon: '📨' },
    { label: 'Cloud Sync', path: '/icebox/sync', icon: '☁️' },
    { label: 'PKI', path: '/icebox/pki', icon: '🔒' },
    { label: 'SSH CA', path: '/icebox/ssh-ca', icon: '🖥️' },
    { label: 'Audit', path: '/icebox/audit', icon: '📋' },
  ],
};

// Checkpoint nav section — shown only when modules.checkpoint is true.
const CHECKPOINT_CATEGORY: NavCategory = {
  label: 'Checkpoint',
  items: [
    { label: 'Users & Groups', path: '/checkpoint/users', icon: '👥' },
    { label: 'Upstream IDPs', path: '/checkpoint/idps', icon: '🔗' },
    { label: 'OAuth2 Clients', path: '/checkpoint/oauth2', icon: '🔐' },
    { label: 'SAML Providers', path: '/checkpoint/saml', icon: '🏛️' },
    { label: 'LDAP Adapters', path: '/checkpoint/ldap', icon: '📁' },
    { label: 'Audit Log', path: '/checkpoint/audit', icon: '📋' },
    { label: 'Settings', path: '/checkpoint/settings', icon: '⚙️' },
  ],
};

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { modules } = useModules();

  // Build nav dynamically — module sections are appended between the static
  // Security section and the Management/Administration sections.
  const navigation: NavCategory[] = [
    STATIC_NAVIGATION[0], // Main
    STATIC_NAVIGATION[1], // Security
    ...(modules.icebox ? [ICEBOX_CATEGORY] : []),
    ...(modules.checkpoint ? [CHECKPOINT_CATEGORY] : []),
    STATIC_NAVIGATION[2], // Management
    STATIC_NAVIGATION[3], // Administration
  ];

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
      categories={navigation}
      currentPath={location.pathname}
      onNavigate={handleNavigate}
      userRole={user?.role}
      isCollapsed={collapsed}
      onToggleCollapse={onToggle}
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
