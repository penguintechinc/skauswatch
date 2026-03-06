import { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import Card from '../components/Card';
import Button from '../components/Button';
import api from '../lib/api';

export default function Profile() {
  const { user, checkAuth } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    full_name: user?.full_name || '',
    current_password: '',
    new_password: '',
    confirm_password: '',
  });

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    // Validate password match if changing password
    if (formData.new_password && formData.new_password !== formData.confirm_password) {
      setError('New passwords do not match');
      return;
    }

    setIsSaving(true);
    try {
      await api.put('/auth/me', {
        full_name: formData.full_name,
        current_password: formData.current_password || undefined,
        new_password: formData.new_password || undefined,
      });

      setSuccess('Profile updated successfully');
      setIsEditing(false);
      setFormData({ ...formData, current_password: '', new_password: '', confirm_password: '' });
      checkAuth(); // Refresh user data
    } catch (err) {
      setError('Failed to update profile');
    } finally {
      setIsSaving(false);
    }
  };

  if (!user) {
    return (
      <Card>
        <p className="text-dark-400">Loading...</p>
      </Card>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Your Profile</h1>
        <p className="text-dark-400 mt-1">Manage your account settings</p>
      </div>

      {/* Messages */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 p-3 bg-green-900/30 border border-green-700 rounded-lg text-green-400">
          {success}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Info */}
        <Card className="lg:col-span-2" title="Profile Information">
          {isEditing ? (
            <form onSubmit={handleSave} className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Full Name</label>
                <input
                  type="text"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  className="input"
                  required
                />
              </div>

              <div>
                <label className="block text-sm text-dark-400 mb-1">Email</label>
                <input
                  type="email"
                  value={user.email}
                  className="input opacity-50"
                  disabled
                />
                <p className="text-xs text-dark-500 mt-1">Contact admin to change email</p>
              </div>

              <div className="border-t border-dark-700 pt-4 mt-4">
                <h3 className="text-sm font-medium text-gold-400 mb-3">Change Password</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-dark-400 mb-1">Current Password</label>
                    <input
                      type="password"
                      value={formData.current_password}
                      onChange={(e) => setFormData({ ...formData, current_password: e.target.value })}
                      className="input"
                      placeholder="Required to change password"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-400 mb-1">New Password</label>
                    <input
                      type="password"
                      value={formData.new_password}
                      onChange={(e) => setFormData({ ...formData, new_password: e.target.value })}
                      className="input"
                      minLength={8}
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-dark-400 mb-1">Confirm New Password</label>
                    <input
                      type="password"
                      value={formData.confirm_password}
                      onChange={(e) => setFormData({ ...formData, confirm_password: e.target.value })}
                      className="input"
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-3 mt-6">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setIsEditing(false);
                    setFormData({
                      full_name: user.full_name,
                      current_password: '',
                      new_password: '',
                      confirm_password: '',
                    });
                  }}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={isSaving}>
                  Save Changes
                </Button>
              </div>
            </form>
          ) : (
            <div className="space-y-4">
              <div>
                <span className="text-dark-400 text-sm">Full Name</span>
                <p className="text-gold-400">{user.full_name}</p>
              </div>
              <div>
                <span className="text-dark-400 text-sm">Email</span>
                <p className="text-gold-400">{user.email}</p>
              </div>
              <div>
                <span className="text-dark-400 text-sm">Password</span>
                <p className="text-dark-300">••••••••</p>
              </div>
              <Button variant="secondary" onClick={() => setIsEditing(true)}>
                Edit Profile
              </Button>
            </div>
          )}
        </Card>

        {/* Account Summary */}
        <Card title="Account Summary">
          <div className="space-y-4">
            <div>
              <span className="text-dark-400 text-sm">Role</span>
              <p>
                <span className={`badge badge-${user.role}`}>{user.role}</span>
              </p>
            </div>
            <div>
              <span className="text-dark-400 text-sm">Status</span>
              <p className={user.is_active ? 'text-green-400' : 'text-red-400'}>
                {user.is_active ? '● Active' : '○ Inactive'}
              </p>
            </div>
            <div>
              <span className="text-dark-400 text-sm">Member Since</span>
              <p className="text-dark-300">
                {new Date(user.created_at).toLocaleDateString()}
              </p>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
