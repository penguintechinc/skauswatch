import { useState, useEffect } from 'react';
import { teamsApi } from '../api/teams';
import Card from '../components/Card';
import Button from '../components/Button';
import type { Team, TeamMember, User } from '../types';

export default function Teams() {
  const [teams, setTeams] = useState<Team[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null);
  const [showTeamDetail, setShowTeamDetail] = useState(false);

  // Create team form state
  const [newTeam, setNewTeam] = useState({
    name: '',
    slug: '',
    is_default: false,
  });
  const [createLoading, setCreateLoading] = useState(false);

  // Member management state
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [showAddMemberModal, setShowAddMemberModal] = useState(false);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [newMemberData, setNewMemberData] = useState({
    user_id: 0,
    role: 'viewer' as const,
  });
  const [addMemberLoading, setAddMemberLoading] = useState(false);

  const fetchTeams = async () => {
    setIsLoading(true);
    try {
      const response = await teamsApi.list();
      setTeams((response as any).teams || []);
      setError(null);
    } catch (err) {
      setError('Failed to load teams');
      console.error('Error loading teams:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTeams();
  }, []);

  const handleCreateTeam = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateLoading(true);
    try {
      await teamsApi.create(newTeam);
      setShowCreateModal(false);
      setNewTeam({ name: '', slug: '', is_default: false });
      fetchTeams();
    } catch (err) {
      setError('Failed to create team');
    } finally {
      setCreateLoading(false);
    }
  };

  const handleDeleteTeam = async (id: number) => {
    if (!confirm('Are you sure you want to delete this team?')) return;
    try {
      await teamsApi.delete(id);
      fetchTeams();
    } catch (err) {
      setError('Failed to delete team');
    }
  };

  const openTeamDetail = async (team: Team) => {
    setSelectedTeam(team);
    setShowTeamDetail(true);
    await fetchTeamMembers(team.id);
  };

  const fetchTeamMembers = async (teamId: number) => {
    setMembersLoading(true);
    try {
      const response = await teamsApi.getMembers(teamId);
      setTeamMembers((response as any).items || []);
    } catch (err) {
      console.error('Error loading team members:', err);
      setError('Failed to load team members');
    } finally {
      setMembersLoading(false);
    }
  };

  const handleRemoveMember = async (teamId: number, userId: number) => {
    if (!confirm('Are you sure you want to remove this member?')) return;
    try {
      await teamsApi.removeMember(teamId, userId);
      if (selectedTeam) {
        await fetchTeamMembers(selectedTeam.id);
      }
    } catch (err) {
      setError('Failed to remove member');
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTeam || !newMemberData.user_id) return;

    setAddMemberLoading(true);
    try {
      await teamsApi.addMember(selectedTeam.id, {
        user_id: newMemberData.user_id,
        role: newMemberData.role,
      });
      setShowAddMemberModal(false);
      setNewMemberData({ user_id: 0, role: 'viewer' });
      await fetchTeamMembers(selectedTeam.id);
    } catch (err) {
      setError('Failed to add member');
      console.error('Error adding member:', err);
    } finally {
      setAddMemberLoading(false);
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">👥 Team Management</h1>
          <p className="text-dark-400 mt-1">Manage teams and team memberships</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>+ Add Team</Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Teams Grid */}
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
          teams.map((team) => (
            <Card key={team.id} className="cursor-pointer hover:border-gold-400/50 transition-colors">
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-gold-400">{team.name}</h3>
                    <p className="text-sm text-dark-400">slug: {team.slug}</p>
                  </div>
                  {team.is_default && (
                    <span className="text-xs px-2 py-1 bg-gold-400/20 text-gold-400 rounded">
                      Default
                    </span>
                  )}
                </div>

                <div className="py-2 border-t border-dark-700">
                  <p className="text-xs text-dark-400">Members</p>
                  <p className="text-lg font-semibold text-gold-400">{team.member_count || 0}</p>
                </div>

                <div className="flex items-center gap-2 pt-3 border-t border-dark-700">
                  <button
                    onClick={() => openTeamDetail(team)}
                    className="flex-1 text-center px-3 py-2 rounded text-gold-400 hover:bg-dark-700 text-sm"
                  >
                    Manage
                  </button>
                  <button
                    onClick={() => handleDeleteTeam(team.id)}
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

      {/* Create Team Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="card w-full max-w-md">
            <h2 className="text-xl font-bold text-gold-400 mb-4">Create New Team</h2>
            <form onSubmit={handleCreateTeam} className="space-y-4">
              <div>
                <label className="block text-sm text-dark-400 mb-1">Team Name</label>
                <input
                  type="text"
                  value={newTeam.name}
                  onChange={(e) => {
                    const name = e.target.value;
                    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
                    setNewTeam({ ...newTeam, name, slug });
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
                  value={newTeam.slug}
                  onChange={(e) => setNewTeam({ ...newTeam, slug: e.target.value })}
                  className="input"
                  required
                  pattern="^[a-z0-9\-]+$"
                  title="Slug must contain only lowercase letters, numbers, and hyphens"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_default"
                  checked={newTeam.is_default}
                  onChange={(e) => setNewTeam({ ...newTeam, is_default: e.target.checked })}
                  className="rounded"
                />
                <label htmlFor="is_default" className="text-sm text-dark-400">
                  Set as default team
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
                  Create Team
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Team Detail Modal */}
      {showTeamDetail && selectedTeam && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-gold-400">{selectedTeam.name}</h2>
              <button
                onClick={() => setShowTeamDetail(false)}
                className="text-dark-400 hover:text-gold-400 text-2xl"
              >
                ×
              </button>
            </div>

            {/* Members Section */}
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gold-400">Members</h3>
                <Button size="sm" onClick={() => setShowAddMemberModal(true)}>
                  + Add Member
                </Button>
              </div>

              {membersLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-12 bg-dark-700 rounded animate-pulse"></div>
                  ))}
                </div>
              ) : teamMembers.length > 0 ? (
                <div className="border border-dark-700 rounded-lg overflow-hidden">
                  {teamMembers.map((member) => (
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
                          handleRemoveMember(selectedTeam.id, member.user_id)
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
                  No members in this team
                </div>
              )}
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-dark-700">
              <Button
                variant="secondary"
                onClick={() => setShowTeamDetail(false)}
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Add Member Modal */}
      {showAddMemberModal && selectedTeam && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4">
          <div className="card w-full max-w-md">
            <h2 className="text-xl font-bold text-gold-400 mb-4">Add Member to {selectedTeam.name}</h2>
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
    </div>
  );
}
