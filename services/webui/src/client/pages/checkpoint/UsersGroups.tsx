import { useState, useEffect, useCallback } from 'react';
import api from '../../lib/api';
import Card from '../../components/Card';
import TabNavigation from '../../components/TabNavigation';
import { useModules } from '../../context/ModuleContext';
import type { IdentityUser, IdentityGroup, CheckpointPaginatedResponse } from '../../types/checkpoint';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: IdentityUser['status'] }) {
  const classes: Record<IdentityUser['status'], string> = {
    active: 'bg-green-900/50 text-green-400 border border-green-700',
    suspended: 'bg-red-900/50 text-red-400 border border-red-700',
    pending: 'bg-yellow-900/50 text-yellow-400 border border-yellow-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${classes[status]}`}>
      {status}
    </span>
  );
}

function GroupTypeBadge({ type }: { type: IdentityGroup['type'] }) {
  const classes: Record<IdentityGroup['type'], string> = {
    local: 'bg-blue-900/50 text-blue-400 border border-blue-700',
    external: 'bg-slate-700 text-slate-400 border border-slate-600',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${classes[type]}`}>
      {type}
    </span>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------------
// Invite User Modal
// ---------------------------------------------------------------------------

interface InviteUserModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function InviteUserModal({ isOpen, onClose, onSuccess }: InviteUserModalProps) {
  const [form, setForm] = useState({ email: '', given_name: '', family_name: '', role: 'viewer' });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.email || !form.given_name || !form.family_name) {
      setError('All fields are required.');
      return;
    }
    console.log('[UsersGroups:InviteUserModal] Submitting invite', { emailDomain: form.email.split('@')[1] });
    setSubmitting(true);
    setError(null);
    try {
      await api.post('/checkpoint/users', form);
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to invite user';
      setError(msg);
      console.error('[UsersGroups:InviteUserModal] Error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog" aria-modal="true">
      <div className="relative bg-dark-800 border border-dark-600 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold text-gold-400 mb-4">Invite User</h2>
        {error && <div className="mb-3 text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Email</label>
            <input
              data-testid="invite-user-email"
              type="email"
              className="input w-full"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-dark-300 mb-1">First Name</label>
              <input
                data-testid="invite-user-given-name"
                type="text"
                className="input w-full"
                value={form.given_name}
                onChange={(e) => setForm({ ...form, given_name: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="block text-sm text-dark-300 mb-1">Last Name</label>
              <input
                data-testid="invite-user-family-name"
                type="text"
                className="input w-full"
                value={form.family_name}
                onChange={(e) => setForm({ ...form, family_name: e.target.value })}
                required
              />
            </div>
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Role</label>
            <select
              data-testid="invite-user-role"
              className="input w-full"
              value={form.role}
              onChange={(e) => setForm({ ...form, role: e.target.value })}
            >
              <option value="admin">Admin</option>
              <option value="maintainer">Maintainer</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              data-testid="invite-user-submit"
              type="submit"
              disabled={submitting}
              className="btn btn-primary flex-1"
            >
              {submitting ? 'Inviting…' : 'Send Invite'}
            </button>
            <button
              data-testid="modal-close"
              type="button"
              className="btn btn-secondary flex-1"
              onClick={onClose}
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create Group Modal
// ---------------------------------------------------------------------------

interface CreateGroupModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function CreateGroupModal({ isOpen, onClose, onSuccess }: CreateGroupModalProps) {
  const [form, setForm] = useState({ name: '', display_name: '', description: '', type: 'local' as 'local' | 'external' });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name || !form.display_name) {
      setError('Name and Display Name are required.');
      return;
    }
    console.log('[UsersGroups:CreateGroupModal] Submitting group', { name: form.name });
    setSubmitting(true);
    setError(null);
    try {
      await api.post('/checkpoint/groups', form);
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create group';
      setError(msg);
      console.error('[UsersGroups:CreateGroupModal] Error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" role="dialog" aria-modal="true">
      <div className="relative bg-dark-800 border border-dark-600 rounded-lg p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold text-gold-400 mb-4">Create Group</h2>
        {error && <div className="mb-3 text-sm text-red-400 bg-red-900/20 border border-red-700 rounded p-2">{error}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Name (slug)</label>
            <input
              data-testid="create-group-name"
              type="text"
              className="input w-full"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value.toLowerCase().replace(/\s+/g, '-') })}
              placeholder="my-group"
              required
            />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Display Name</label>
            <input
              data-testid="create-group-display-name"
              type="text"
              className="input w-full"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-1">Description</label>
            <input
              data-testid="create-group-description"
              type="text"
              className="input w-full"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm text-dark-300 mb-2">Type</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  data-testid="create-group-type-local"
                  type="radio"
                  name="type"
                  value="local"
                  checked={form.type === 'local'}
                  onChange={() => setForm({ ...form, type: 'local' })}
                />
                <span className="text-dark-300 text-sm">Local</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  data-testid="create-group-type-external"
                  type="radio"
                  name="type"
                  value="external"
                  checked={form.type === 'external'}
                  onChange={() => setForm({ ...form, type: 'external' })}
                />
                <span className="text-dark-300 text-sm">External</span>
              </label>
            </div>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              data-testid="create-group-submit"
              type="submit"
              disabled={submitting}
              className="btn btn-primary flex-1"
            >
              {submitting ? 'Creating…' : 'Create Group'}
            </button>
            <button
              data-testid="modal-close"
              type="button"
              className="btn btn-secondary flex-1"
              onClick={onClose}
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Users Tab
// ---------------------------------------------------------------------------

function UsersTab() {
  const [users, setUsers] = useState<IdentityUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [showInvite, setShowInvite] = useState(false);

  const PER_PAGE = 20;

  const fetchUsers = useCallback(async () => {
    console.log('[UsersGroups:UsersTab] Fetching users', { page, statusFilter, hasSearch: search.length > 0 });
    setIsLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, per_page: PER_PAGE };
      if (search) params.q = search;
      if (statusFilter) params.status = statusFilter;
      const res = await api.get<CheckpointPaginatedResponse<IdentityUser>>('/checkpoint/users', { params });
      setUsers(res.data.items);
      setTotal(res.data.total);
    } catch (err: unknown) {
      setError('Failed to load users.');
      console.error('[UsersGroups:UsersTab] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, [page, search, statusFilter]);

  useEffect(() => {
    void fetchUsers();
  }, [fetchUsers]);

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div>
      <div className="flex flex-col sm:flex-row gap-3 mb-4">
        <input
          data-testid="users-search"
          type="text"
          className="input flex-1"
          placeholder="Search by email or name…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <select
          data-testid="users-status-filter"
          className="input sm:w-40"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
        >
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="pending">Pending</option>
        </select>
        <button
          data-testid="invite-user-btn"
          className="btn btn-primary whitespace-nowrap"
          onClick={() => setShowInvite(true)}
        >
          + Invite User
        </button>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading users…</div>
      ) : users.length === 0 ? (
        <div className="text-dark-400 py-8 text-center">No users found.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">Email</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Name</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Status</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">MFA</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Last Login</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => (
                <tr
                  key={u.uuid}
                  data-testid={`user-row-${i}`}
                  className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors"
                >
                  <td className="py-2 pr-4 text-gold-400 font-mono text-xs">{u.email}</td>
                  <td className="py-2 pr-4 text-dark-200">{u.display_name || `${u.given_name} ${u.family_name}`}</td>
                  <td className="py-2 pr-4"><StatusBadge status={u.status} /></td>
                  <td className="py-2 pr-4">
                    <span className={u.mfa_enabled ? 'text-green-400' : 'text-dark-500'}>
                      {u.mfa_enabled ? '✓' : '—'}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-dark-400 text-xs">{formatDate(u.last_login_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center gap-2 mt-4">
          <button
            data-testid="users-prev-page"
            className="btn btn-secondary text-xs px-3 py-1"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
          >
            ← Prev
          </button>
          <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
          <button
            data-testid="users-next-page"
            className="btn btn-secondary text-xs px-3 py-1"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next →
          </button>
        </div>
      )}

      <InviteUserModal
        isOpen={showInvite}
        onClose={() => setShowInvite(false)}
        onSuccess={() => void fetchUsers()}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Groups Tab
// ---------------------------------------------------------------------------

function GroupsTab() {
  const [groups, setGroups] = useState<IdentityGroup[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showCreate, setShowCreate] = useState(false);

  const PER_PAGE = 20;

  const fetchGroups = useCallback(async () => {
    console.log('[UsersGroups:GroupsTab] Fetching groups', { page });
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.get<CheckpointPaginatedResponse<IdentityGroup>>('/checkpoint/groups', {
        params: { page, per_page: PER_PAGE },
      });
      setGroups(res.data.items);
      setTotal(res.data.total);
    } catch (err: unknown) {
      setError('Failed to load groups.');
      console.error('[UsersGroups:GroupsTab] Fetch error:', err instanceof Error ? err.constructor.name : typeof err);
    } finally {
      setIsLoading(false);
    }
  }, [page]);

  useEffect(() => {
    void fetchGroups();
  }, [fetchGroups]);

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div>
      <div className="flex justify-end mb-4">
        <button
          data-testid="create-group-btn"
          className="btn btn-primary"
          onClick={() => setShowCreate(true)}
        >
          + Create Group
        </button>
      </div>

      {error && <div className="text-red-400 text-sm mb-3">{error}</div>}

      {isLoading ? (
        <div className="text-dark-400 py-8 text-center">Loading groups…</div>
      ) : groups.length === 0 ? (
        <div className="text-dark-400 py-8 text-center">No groups found.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-dark-700">
                <th className="py-2 pr-4 text-dark-400 font-medium">Name</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Display Name</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Type</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Members</th>
                <th className="py-2 pr-4 text-dark-400 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g, i) => (
                <tr
                  key={g.uuid}
                  data-testid={`group-row-${i}`}
                  className="border-b border-dark-800 hover:bg-dark-800/50 transition-colors cursor-pointer"
                >
                  <td className="py-2 pr-4 text-gold-400 font-mono text-xs">{g.name}</td>
                  <td className="py-2 pr-4 text-dark-200">{g.display_name}</td>
                  <td className="py-2 pr-4"><GroupTypeBadge type={g.type} /></td>
                  <td className="py-2 pr-4 text-dark-300">{g.member_count}</td>
                  <td className="py-2 pr-4 text-dark-400 text-xs">{formatDate(g.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center gap-2 mt-4">
          <button
            data-testid="groups-prev-page"
            className="btn btn-secondary text-xs px-3 py-1"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
          >
            ← Prev
          </button>
          <span className="text-dark-400 text-sm">Page {page} of {totalPages}</span>
          <button
            data-testid="groups-next-page"
            className="btn btn-secondary text-xs px-3 py-1"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next →
          </button>
        </div>
      )}

      <CreateGroupModal
        isOpen={showCreate}
        onClose={() => setShowCreate(false)}
        onSuccess={() => void fetchGroups()}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const TABS = [
  { id: 'users', label: 'Users' },
  { id: 'groups', label: 'Groups' },
];

export default function UsersGroups() {
  const { modules } = useModules();
  const [activeTab, setActiveTab] = useState('users');

  useEffect(() => {
    console.log('[UsersGroups] Mounted', { checkpointEnabled: modules.checkpoint });
  }, [modules.checkpoint]);

  if (!modules.checkpoint) {
    return (
      <div className="text-dark-400 py-8 text-center">
        Checkpoint module is not enabled.
      </div>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Users &amp; Groups</h1>
        <p className="text-dark-400 mt-1">Manage identity users and groups in Checkpoint.</p>
      </div>

      <TabNavigation tabs={TABS} activeTab={activeTab} onChange={setActiveTab} />

      <Card className="mt-6">
        {activeTab === 'users' && <UsersTab />}
        {activeTab === 'groups' && <GroupsTab />}
      </Card>
    </div>
  );
}
