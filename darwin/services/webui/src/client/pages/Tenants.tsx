import { useState, useEffect } from 'react';
import { tenantsApi } from '../api/tenants';
import { usersApi } from '../hooks/useApi';
import Card from '../components/Card';
import Button from '../components/Button';
import type { Tenant, TenantMember, User } from '../types';

export default function Tenants() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [showTenantDetail, setShowTenantDetail] = useState(false);

  // Create tenant form state
  const [newTenant, setNewTenant] = useState({
    name: '',
    slug: '',
    is_active: true,
  });
  const [createLoading, setCreateLoading] = useState(false);

  // Member management state
  const [tenantMembers, setTenantMembers] = useState<TenantMember[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [showAddMemberModal, setShowAddMemberModal] = useState(false);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [newMemberData, setNewMemberData] = useState({
    user_id: 0,
    role: 'viewer' as const,
  });
  const [addMemberLoading, setAddMemberLoading] = useState(false);

  // Create new user state
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [newUserData, setNewUserData] = useState({
    email: '',
    password: '',
    full_name: '',
    role: 'viewer' as const,
  });
  const [createUserLoading, setCreateUserLoading] = useState(false);

  const fetchTenants = async () => {
    setIsLoading(true);
    try {
      const response = await tenantsApi.list();
      setTenants((response as any).tenants || []);
      setError(null);
    } catch (err) {
      setError('Failed to load tenants');
      console.error('Error loading tenants:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTenants();
  }, []);

  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true);
    try {
      await tenantsApi.create(newTenant);
      setShowCreateModal(false);
      setNewTenant({ name: '', slug: '', is_active: true });
      fetchTenants();
    } catch (err) {
      setError('Failed to create tenant');
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDeleteTenant = async (id: number) => {
    if (!confirm('Are you sure you want to delete this tenant?')) return;
    try {
      await tenantsApi.delete(id);
      fetchTenants();
    } catch (err) {
      setError('Failed to delete tenant');
    }
  };

  const openTenantDetail = async (tenant: Tenant) => {
    setSelectedTenant(tenant);
    setShowTenantDetail(true);
    await fetchTenantMembers(tenant.id);
  };

  const fetchTenantMembers = async (tenantId: number) => {
    setMembersLoading(true);
    try {
      const response = await tenantsApi.getMembers(tenantId);
      setTenantMembers((response as any).members || []);
    } catch (err) {
      console.error('Error loading tenant members:', err);
      setError('Failed to load tenant members');
    } finally {
      setMembersLoading(false);
    }
  };

  const handleRemoveMember = async (tenantId: number, userId: number) => {
    if (!confirm('Are you sure you want to remove this member?')) return;
    try {
      await tenantsApi.removeMember(tenantId, userId);
      if (selectedTenant) {
        await fetchTenantMembers(selectedTenant.id);
      }
    } catch (err) {
      setError('Failed to remove member');
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTenant || !newMemberData.user_id) return;

    setAddMemberLoading(true);
    try {
      await tenantsApi.addMember(selectedTenant.id, {
        user_id: newMemberData.user_id,
        role: newMemberData.role,
      });
      setShowAddMemberModal(false);
      setNewMemberData({ user_id: 0, role: 'viewer' });
      await fetchTenantMembers(selectedTenant.id);
    } catch (err) {
      setError('Failed to add member');
      console.error('Error adding member:', err);
    } finally {
      setAddMemberLoading(false);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTenant) return;

    setCreateUserLoading(true);
    try {
      // Create user - backend will automatically assign to current user's tenant
      // or we can explicitly pass tenant_id if global admin
      await usersApi.create({
        ...newUserData,
        tenant_id: selectedTenant.id,
      });
      setShowCreateUserModal(false);
      setNewUserData({ email: '', password: '', full_name: '', role: 'viewer' });
      await fetchTenantMembers(selectedTenant.id);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to create user');
      console.error('Error creating user:', err);
    } finally {
      setCreateUserLoading(false);
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">🏢 Tenant Management</h1>
          <p className="text-dark-400 mt-1">Manage system tenants and their configurations</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>+ Add Tenant</Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Tenants Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          <>
            {[1, 2, 3].map((i) => (
              <Card key={i}>
                <div className="animate-pulse space-y-3">
                  <div className="h-6 bg-dark-700 rounded w-3/4"></div>
                  <div className="h-4 bg-dark-700 rounded w-1/2"></div>
                  <div className="h-4 bg-dark-700 rounded w-2/3"></div>
                </div>
              </Card>
            ))}
          </>
        ) : (
          tenants.map((tenant) => (
            <Card key={tenant.id} className="cursor-pointer hover:border-gold-400/50 transition-colors">
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-gold-400">{tenant.name}</h3>
                    <p className="text-sm text-dark-400">slug: {tenant.slug}</p>
                  </div>
                  <span className={tenant.is_active ? 'text-green-400' : 'text-red-400'}>
                    {tenant.is_active ? '● Active' : '○ Inactive'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 py-2 border-t border-dark-700">
                  <div>
                    <p className="text-xs text-dark-400">Members</p>
                    <p className="text-lg font-semibold text-gold-400">{tenant.member_count || 0}</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-400">Teams</p>
                    <p className="text-lg font-semibold text-gold-400">{tenant.team_count || 0}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-3 border-t border-dark-700">
                  <button
                    onClick={() => openTenantDetail(tenant)}
                    className="flex-1 text-center px-3 py-2 rounded text-gold-400 hover:bg-dark-700 text-sm"
                  >
                    Manage
                  </button>
                  <button
                    onClick={() => handleDeleteTenant(tenant.id)}
                    className="text-red-400 hover:text-red-300 px-3 py-2"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </Card>
          ))
        )}
      </div>

      {/* Create Tenant Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card w-full max-w-md">
            <h2 className="text-xl font-bold text-gold-400 mb-4">Create New Tenant</h2>
            <form onSubmit={handleCreateTenant} className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Tenant Name</label>
                <input
                  type="text"
                  value={newTenant.name}
                  onChange={(e) => {
                    const name = e.target.value;
                    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
                    setNewTenant({ ...newTenant, name, slug });
                  }}
                  className="input"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-dark-400 mb-1">
                  Slug <span className="text-xs text-dark-500">(auto-generated, editable)</span>
                </label>
                <input
                  type="text"
                  value={newTenant.slug}
                  onChange={(e) => setNewTenant({ ...newTenant, slug: e.target.value })}
                  className="input"
                  required
                  pattern="^[a-z0-9\-]+$"
                  title="Slug must contain only lowercase letters, numbers, and hyphens"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_active"
                  checked={newTenant.is_active}
                  onChange={(e) => setNewTenant({ ...newTenant, is_active: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor="is_active" className="text-sm text-dark-400">
                  Active
                </label>
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={createLoading}>
                  Create Tenant
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Tenant Detail Modal */}
      {showTenantDetail && selectedTenant && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-gold-400">{selectedTenant.name}</h2>
              <button
                onClick={() => setShowTenantDetail(false)}
                className="text-dark-400 hover:text-gold-400 text-2xl"
              >
                ×
              </button>
            </div>

            {/* Members Section */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gold-400">Members</h3>
                <div className="flex gap-2">
                  <Button size="sm" variant="secondary" onClick={() => setShowAddMemberModal(true)}>
                    Add Existing
                  </Button>
                  <Button size="sm" onClick={() => setShowCreateUserModal(true)}>
                    + Create New User
                  </Button>
                </div>
              </div>

              {membersLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-12 bg-dark-700 rounded animate-pulse"></div>
                  ))}
                </div>
              ) : tenantMembers.length > 0 ? (
                <div className="border border-dark-700 rounded-lg overflow-hidden">
                  {tenantMembers.map((member) => (
                    <div
                      key={member.id}
                      className="flex items-center justify-between p-4 border-b border-dark-700 last:border-b-0 hover:bg-dark-800 transition-colors"
                    >
                      <div className="flex-1">
                        <p className="text-sm font-semibold text-gold-400">
                          {member.user?.full_name || member.user?.email || 'Unknown'}
                        </p>
                        <p className="text-xs text-dark-400">{member.user?.email}</p>
                      </div>
                      <span className="text-xs px-2 py-1 bg-gold-400/20 text-gold-400 rounded capitalize mr-4">
                        {member.role}
                      </span>
                      <button
                        onClick={() =>
                          handleRemoveMember(selectedTenant.id, member.user_id)
                        }
                        className="text-red-400 hover:text-red-300 text-sm"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-dark-400">
                  No members in this tenant
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-dark-700">
              <Button
                variant="secondary"
                onClick={() => setShowTenantDetail(false)}
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Add Member Modal */}
      {showAddMemberModal && selectedTenant && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4">
          <div className="card w-full max-w-md">
            <h2 className="text-xl font-bold text-gold-400 mb-4">Add Member to {selectedTenant.name}</h2>
            <form onSubmit={handleAddMember} className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">User Email</label>
                <input
                  type="email"
                  placeholder="Search by email..."
                  value={
                    newMemberData.user_id
                      ? (allUsers.find((u) => u.id === newMemberData.user_id)
                          ?.email || '')
                      : ''
                  }
                  onChange={(e) => {
                    const user = allUsers.find((u) =>
                      u.email
                        .toLowerCase()
                        .includes(e.target.value.toLowerCase())
                    );
                    if (user) {
                      setNewMemberData({ ...newMemberData, user_id: user.id });
                    }
                  }}
                  className="input"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-dark-400 mb-1">Role</label>
                <select
                  value={newMemberData.role}
                  onChange={(e) =>
                    setNewMemberData({
                      ...newMemberData,
                      role: e.target.value as 'admin' | 'maintainer' | 'viewer',
                    })
                  }
                  className="input"
                >
                  <option value="viewer">Viewer (Read-only)</option>
                  <option value="maintainer">Maintainer (Read/Write)</option>
                  <option value="admin">Admin (Full Access)</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setShowAddMemberModal(false);
                    setNewMemberData({ user_id: 0, role: 'viewer' });
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={addMemberLoading}>
                  Add Member
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create New User Modal */}
      {showCreateUserModal && selectedTenant && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4">
          <div className="card w-full max-w-md">
            <h2 className="text-xl font-bold text-gold-400 mb-4">
              Create New User for {selectedTenant.name}
            </h2>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Email</label>
                <input
                  type="email"
                  value={newUserData.email}
                  onChange={(e) => setNewUserData({ ...newUserData, email: e.target.value })}
                  className="input"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-dark-400 mb-1">Password</label>
                <input
                  type="password"
                  value={newUserData.password}
                  onChange={(e) => setNewUserData({ ...newUserData, password: e.target.value })}
                  className="input"
                  required
                  minLength={8}
                />
                <p className="text-xs text-dark-500 mt-1">Minimum 8 characters</p>
              </div>
              <div>
                <label className="block text-sm text-dark-400 mb-1">Full Name</label>
                <input
                  type="text"
                  value={newUserData.full_name}
                  onChange={(e) => setNewUserData({ ...newUserData, full_name: e.target.value })}
                  className="input"
                />
              </div>
              <div>
                <label className="block text-sm text-dark-400 mb-1">Role in Tenant</label>
                <select
                  value={newUserData.role}
                  onChange={(e) =>
                    setNewUserData({
                      ...newUserData,
                      role: e.target.value as 'admin' | 'maintainer' | 'viewer',
                    })
                  }
                  className="input"
                >
                  <option value="viewer">Viewer (Read-only)</option>
                  <option value="maintainer">Maintainer (Read/Write)</option>
                  <option value="admin">Admin (Full Access)</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 mt-6">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setShowCreateUserModal(false);
                    setNewUserData({ email: '', password: '', full_name: '', role: 'viewer' });
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={createUserLoading}>
                  Create User
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
