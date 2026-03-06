import { useState, useEffect } from 'react';
import { rolesApi, type Role, type Scope } from '../api/roles';
import Card from '../components/Card';
import Button from '../components/Button';

type RoleLevel = 'global' | 'tenant' | 'team' | 'resource';

export default function Roles() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [filterLevel, setFilterLevel] = useState<RoleLevel | ''>('');
  const [editingRole, setEditingRole] = useState<Role | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    description: '',
    level: 'global' as RoleLevel,
    scope_ids: [] as number[],
    is_active: true,
  });
  const [formLoading, setFormLoading] = useState(false);

  const fetchRoles = async () => {
    setIsLoading(true);
    try {
      const response = await rolesApi.listRoles(filterLevel || undefined);
      setRoles((response as any).items || []);
      setError(null);
    } catch (err) {
      setError('Failed to load roles');
      console.error('Error loading roles:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchScopes = async () => {
    try {
      const scopeList = await rolesApi.listScopes();
      setScopes(scopeList);
    } catch (err) {
      console.error('Error loading scopes:', err);
    }
  };

  useEffect(() => {
    fetchScopes();
  }, []);

  useEffect(() => {
    fetchRoles();
  }, [filterLevel]);

  const resetForm = () => {
    setFormData({
      name: '',
      slug: '',
      description: '',
      level: 'global',
      scope_ids: [],
      is_active: true,
    });
    setEditingRole(null);
  };

  const openCreateModal = () => {
    resetForm();
    setShowCreateModal(true);
  };

  const openEditModal = (role: Role) => {
    setFormData({
      name: role.name,
      slug: role.slug,
      description: role.description || '',
      level: role.level,
      scope_ids: role.scopes?.map((s) => s.id) || [],
      is_active: role.is_active,
    });
    setEditingRole(role);
    setShowCreateModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormLoading(true);
    try {
      if (editingRole) {
        await rolesApi.update(editingRole.id, formData);
      } else {
        await rolesApi.create(formData);
      }
      setShowCreateModal(false);
      resetForm();
      fetchRoles();
    } catch (err) {
      setError('Failed to save role');
      console.error('Error saving role:', err);
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteRole = async (id: number) => {
    if (!confirm('Are you sure you want to delete this role?')) return;
    try {
      await rolesApi.delete(id);
      fetchRoles();
    } catch (err) {
      setError('Failed to delete role');
      console.error('Error deleting role:', err);
    }
  };

  const groupedScopes = scopes.reduce(
    (acc, scope) => {
      if (!acc[scope.category]) {
        acc[scope.category] = [];
      }
      acc[scope.category].push(scope);
      return acc;
    },
    {} as Record<string, Scope[]>
  );

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">🔑 Role Management</h1>
          <p className="text-dark-400 mt-1">Manage custom roles and permissions</p>
        </div>
        <Button onClick={openCreateModal}>+ Create Role</Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="mb-6 flex gap-2">
        <select
          value={filterLevel}
          onChange={(e) => setFilterLevel(e.target.value as RoleLevel | '')}
          className="input max-w-xs"
        >
          <option value="">All Levels</option>
          <option value="global">Global</option>
          <option value="tenant">Tenant</option>
          <option value="team">Team</option>
          <option value="resource">Resource</option>
        </select>
      </div>

      {/* Roles List */}
      <div className="grid grid-cols-1 gap-4">
        {isLoading ? (
          <>
            {[1, 2, 3].map((i) => (
              <Card key={i}>
                <div className="animate-pulse space-y-3">
                  <div className="h-6 bg-dark-700 rounded w-3/4"></div>
                  <div className="h-4 bg-dark-700 rounded w-1/2"></div>
                </div>
              </Card>
            ))}
          </>
        ) : roles.length > 0 ? (
          roles.map((role) => (
            <Card key={role.id} className="hover:border-gold-400/50 transition-colors">
              <div className="space-y-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-lg font-semibold text-gold-400">{role.name}</h3>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        role.is_active
                          ? 'bg-green-400/20 text-green-400'
                          : 'bg-red-400/20 text-red-400'
                      }`}>
                        {role.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    <p className="text-sm text-dark-400">
                      {role.description || 'No description'}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 py-3 border-t border-dark-700">
                  <div>
                    <p className="text-xs text-dark-400">Slug</p>
                    <p className="text-sm font-mono text-gold-400">{role.slug}</p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-400">Level</p>
                    <p className="text-sm font-semibold text-gold-400 capitalize">
                      {role.level}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-dark-400">Scopes</p>
                    <p className="text-sm font-semibold text-gold-400">
                      {role.scope_count}
                    </p>
                  </div>
                </div>

                {role.scopes && role.scopes.length > 0 && (
                  <div className="pt-2">
                    <p className="text-xs text-dark-400 mb-2">Assigned Scopes:</p>
                    <div className="flex flex-wrap gap-1">
                      {role.scopes.map((scope) => (
                        <span
                          key={scope.id}
                          className="text-xs px-2 py-1 bg-dark-700 text-dark-300 rounded"
                        >
                          {scope.slug}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex items-center gap-2 pt-3 border-t border-dark-700">
                  <button
                    onClick={() => openEditModal(role)}
                    className="flex-1 text-center px-3 py-2 rounded text-gold-400 hover:bg-dark-700 text-sm transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDeleteRole(role.id)}
                    className="text-red-400 hover:text-red-300 px-3 py-2 transition-colors"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </Card>
          ))
        ) : (
          <Card>
            <div className="text-center py-8">
              <p className="text-dark-400">No custom roles found</p>
            </div>
          </Card>
        )}
      </div>

      {/* Create/Edit Role Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-gold-400 mb-4">
              {editingRole ? 'Edit Role' : 'Create New Role'}
            </h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Row 1: Name and Slug */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Role Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="input"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Slug</label>
                  <input
                    type="text"
                    value={formData.slug}
                    onChange={(e) => setFormData({ ...formData, slug: e.target.value })}
                    className="input"
                    required
                    pattern="^[a-z0-9\-_]+$"
                    title="Slug must contain only lowercase letters, numbers, hyphens, and underscores"
                  />
                </div>
              </div>

              {/* Row 2: Description and Level */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Description</label>
                  <textarea
                    value={formData.description}
                    onChange={(e) =>
                      setFormData({ ...formData, description: e.target.value })
                    }
                    className="input min-h-[80px]"
                    placeholder="Optional description"
                  />
                </div>
                <div>
                  <label className="block text-sm text-dark-400 mb-1">Role Level</label>
                  <select
                    value={formData.level}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        level: e.target.value as RoleLevel,
                      })
                    }
                    className="input"
                    required
                  >
                    <option value="global">Global</option>
                    <option value="tenant">Tenant</option>
                    <option value="team">Team</option>
                    <option value="resource">Resource</option>
                  </select>
                </div>
              </div>

              {/* Scopes Selection */}
              <div>
                <label className="block text-sm text-dark-400 mb-2">
                  Scopes ({formData.scope_ids.length} selected)
                </label>
                <div className="border border-dark-700 rounded-lg p-4 max-h-64 overflow-y-auto space-y-3">
                  {Object.entries(groupedScopes).length > 0 ? (
                    Object.entries(groupedScopes).map(([category, categoryScopes]) => (
                      <div key={category}>
                        <p className="text-xs font-semibold text-gold-400 mb-2 uppercase">
                          {category}
                        </p>
                        <div className="space-y-2 ml-2">
                          {categoryScopes.map((scope) => (
                            <div key={scope.id} className="flex items-start gap-2">
                              <input
                                type="checkbox"
                                id={`scope-${scope.id}`}
                                checked={formData.scope_ids.includes(scope.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setFormData({
                                      ...formData,
                                      scope_ids: [
                                        ...formData.scope_ids,
                                        scope.id,
                                      ],
                                    });
                                  } else {
                                    setFormData({
                                      ...formData,
                                      scope_ids: formData.scope_ids.filter(
                                        (id) => id !== scope.id
                                      ),
                                    });
                                  }
                                }}
                                className="mt-0.5"
                              />
                              <label
                                htmlFor={`scope-${scope.id}`}
                                className="flex-1 text-sm text-dark-300 cursor-pointer"
                              >
                                <span className="font-semibold">{scope.slug}</span>
                                {scope.description && (
                                  <p className="text-xs text-dark-400">
                                    {scope.description}
                                  </p>
                                )}
                              </label>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-dark-400 text-sm">No scopes available</p>
                  )}
                </div>
              </div>

              {/* Active Toggle */}
              {editingRole && (
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="is_active"
                    checked={formData.is_active}
                    onChange={(e) =>
                      setFormData({ ...formData, is_active: e.target.checked })
                    }
                    className="rounded"
                  />
                  <label htmlFor="is_active" className="text-sm text-dark-400">
                    Active
                  </label>
                </div>
              )}

              {/* Form Actions */}
              <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-dark-700">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setShowCreateModal(false);
                    resetForm();
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={formLoading}>
                  {editingRole ? 'Update Role' : 'Create Role'}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
