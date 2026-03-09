import React, { useState } from 'react';

interface GitCredential {
  id: string;
  type: 'ssh_key' | 'personal_access_token' | 'oauth';
  provider: 'github' | 'gitlab' | 'gitea';
  label: string;
  isValid: boolean;
  lastValidated: string;
}

interface CredentialFormProps {
  credentials?: GitCredential[];
  onAddCredential?: (
    provider: 'github' | 'gitlab' | 'gitea',
    type: 'ssh_key' | 'personal_access_token' | 'oauth',
    credential: string,
    label: string
  ) => Promise<void>;
  onDeleteCredential?: (id: string) => Promise<void>;
  isReadOnly?: boolean;
}

export default function CredentialForm({
  credentials = [],
  onAddCredential,
  onDeleteCredential,
  isReadOnly = false,
}: CredentialFormProps) {
  const [provider, setProvider] = useState<'github' | 'gitlab' | 'gitea'>('github');
  const [type, setType] = useState<'ssh_key' | 'personal_access_token' | 'oauth'>('personal_access_token');
  const [credential, setCredential] = useState('');
  const [label, setLabel] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const handleAdd = async () => {
    if (!credential.trim() || !label.trim() || !onAddCredential) return;

    try {
      setSubmitting(true);
      await onAddCredential(provider, type, credential, label);
      setCredential('');
      setLabel('');
    } catch (error) {
      console.error('Failed to add credential:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!onDeleteCredential) return;

    try {
      setDeletingId(id);
      await onDeleteCredential(id);
    } catch (error) {
      console.error('Failed to delete credential:', error);
    } finally {
      setDeletingId(null);
    }
  };

  const getStatusColor = (isValid: boolean) => {
    return isValid ? 'text-green-400' : 'text-red-400';
  };

  const getStatusLabel = (isValid: boolean) => {
    return isValid ? 'Valid' : 'Invalid';
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  return (
    <div className="card space-y-4">
      <h3 className="text-lg font-semibold text-gold-400">Git Credentials</h3>

      {credentials.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-elder-text-light">Stored Credentials</h4>
          {credentials.map((cred) => (
            <div
              key={cred.id}
              className="flex items-center justify-between p-2 rounded bg-elder-bg-darker border border-elder-border"
            >
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-elder-text-base truncate">{cred.label}</p>
                <p className="text-xs text-elder-text-light">
                  {cred.provider} • {cred.type.replace('_', ' ')}
                </p>
                <p className={`text-xs font-medium ${getStatusColor(cred.isValid)}`}>
                  {getStatusLabel(cred.isValid)} - {formatDate(cred.lastValidated)}
                </p>
              </div>
              {!isReadOnly && onDeleteCredential && (
                <button
                  onClick={() => handleDelete(cred.id)}
                  disabled={deletingId === cred.id}
                  className="ml-2 px-2 py-1 rounded text-xs bg-red-900 text-red-200 hover:bg-red-800 disabled:opacity-50 transition-colors"
                >
                  {deletingId === cred.id ? 'Deleting...' : 'Delete'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {!isReadOnly && onAddCredential && (
        <div className="space-y-3 pt-4 border-t border-elder-border">
          <h4 className="text-sm font-medium text-elder-text-light">Add New Credential</h4>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gold-400 mb-1">Provider</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value as 'github' | 'gitlab' | 'gitea')}
                className="w-full px-2 py-1.5 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none text-sm"
              >
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="gitea">Gitea</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gold-400 mb-1">Type</label>
              <select
                value={type}
                onChange={(e) =>
                  setType(e.target.value as 'ssh_key' | 'personal_access_token' | 'oauth')
                }
                className="w-full px-2 py-1.5 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none text-sm"
              >
                <option value="personal_access_token">Personal Access Token</option>
                <option value="ssh_key">SSH Key</option>
                <option value="oauth">OAuth</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gold-400 mb-1">Label</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g., GitHub Personal Token"
              className="w-full px-2 py-1.5 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gold-400 mb-1">Credential</label>
            <textarea
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              placeholder="Paste your credential here (token, key, etc.)"
              className="w-full px-2 py-1.5 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none text-sm resize-none"
              rows={3}
            />
          </div>

          <button
            onClick={handleAdd}
            disabled={!credential.trim() || !label.trim() || submitting}
            className="w-full px-3 py-2 rounded bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors font-medium text-sm"
          >
            {submitting ? 'Adding...' : 'Add Credential'}
          </button>
        </div>
      )}
    </div>
  );
}
