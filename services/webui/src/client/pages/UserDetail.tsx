import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { usersApi } from '../hooks/useApi';
import Card from '../components/Card';
import Button from '../components/Button';
import type { User, UpdateUserData } from '../types';

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState<UpdateUserData>({});

  useEffect(() => {
    const fetchUser = async () => {
      if (!id) return;
      setIsLoading(true);
      try {
        const userData = await usersApi.get(parseInt(id, 10));
        setUser(userData);
        setFormData({
          email: userData.email,
          full_name: userData.full_name,
          role: userData.role,
          is_active: userData.is_active,
        });
        setError(null);
      } catch (err) {
        setError('Failed to load user');
      } finally {
        setIsLoading(false);
      }
    };

    fetchUser();
  }, [id]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!id) return;

    setIsSaving(true);
    try {
      await usersApi.update(parseInt(id, 10), formData);
      navigate('/users');
    } catch (err) {
      setError('Failed to update user');
    } finally {
      setIsSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 bg-dark-700 rounded w-1/4 mb-6"></div>
        <div className="h-64 bg-dark-700 rounded"></div>
      </div>
    );
  }

  if (!user) {
    return (
      <Card>
        <p className="text-red-400">User not found</p>
      </Card>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Edit User</h1>
        <p className="text-dark-400 mt-1">Update user information and permissions</p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Edit Form */}
      <Card>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm text-dark-400 mb-1">Full Name</label>
              <input
                type="text"
                value={formData.full_name || ''}
                onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                className="input"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-dark-400 mb-1">Email</label>
              <input
                type="email"
                value={formData.email || ''}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                className="input"
                required
              />
            </div>

            <div>
              <label className="block text-sm text-dark-400 mb-1">Role</label>
              <select
                value={formData.role || 'viewer'}
                onChange={(e) => setFormData({ ...formData, role: e.target.value as 'admin' | 'maintainer' | 'viewer' })}
                className="input"
              >
                <option value="viewer">Viewer</option>
                <option value="maintainer">Maintainer</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div>
              <label className="block text-sm text-dark-400 mb-1">Status</label>
              <select
                value={formData.is_active ? 'active' : 'inactive'}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.value === 'active' })}
                className="input"
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block text-sm text-dark-400 mb-1">
                New Password (leave blank to keep current)
              </label>
              <input
                type="password"
                value={formData.password || ''}
                onChange={(e) => setFormData({ ...formData, password: e.target.value || undefined })}
                className="input"
                minLength={8}
                placeholder="••••••••"
              />
            </div>
          </div>

          {/* User Info */}
          <div className="border-t border-dark-700 pt-4 mt-6">
            <h3 className="text-sm font-medium text-dark-400 mb-3">User Information</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-dark-500">Created:</span>
                <span className="text-dark-300 ml-2">
                  {new Date(user.created_at).toLocaleDateString()}
                </span>
              </div>
              <div>
                <span className="text-dark-500">Last Updated:</span>
                <span className="text-dark-300 ml-2">
                  {user.updated_at ? new Date(user.updated_at).toLocaleDateString() : 'Never'}
                </span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3">
            <Button type="button" variant="secondary" onClick={() => navigate('/users')}>
              Cancel
            </Button>
            <Button type="submit" isLoading={isSaving}>
              Save Changes
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
