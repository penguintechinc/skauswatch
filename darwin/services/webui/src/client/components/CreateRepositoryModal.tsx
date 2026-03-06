import { useState, useEffect } from 'react';
import { repositoriesApi } from '../hooks/useApi';
import Button from './Button';
import type { Platform, CreateRepositoryData } from '../types';

interface CreateRepositoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export default function CreateRepositoryModal({
  isOpen,
  onClose,
  onSuccess,
}: CreateRepositoryModalProps) {
  const [formData, setFormData] = useState<CreateRepositoryData>({
    platform: 'github',
    repository: '',
    platform_organization: '',
    display_name: '',
    description: '',
    enabled: true,
    polling_enabled: false,
    polling_interval_minutes: 5,
    auto_review: true,
    default_categories: ['security', 'best_practices'],
    default_ai_provider: 'ollama',
  });

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen) {
      setFormData({
        platform: 'github',
        repository: '',
        platform_organization: '',
        display_name: '',
        description: '',
        enabled: true,
        polling_enabled: false,
        polling_interval_minutes: 5,
        auto_review: true,
        default_categories: ['security', 'best_practices'],
        default_ai_provider: 'ollama',
      });
      setError(null);
      setValidationErrors({});
    }
  }, [isOpen]);

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    // Required fields
    if (!formData.repository.trim()) {
      errors.repository = 'Repository is required';
    } else {
      // Platform-specific validation
      if (formData.platform === 'github' || formData.platform === 'gitlab') {
        if (!formData.repository.includes('/')) {
          errors.repository = 'Repository must be in "owner/repo" format';
        }
      } else if (formData.platform === 'git') {
        if (!formData.repository.startsWith('http') && !formData.repository.startsWith('git@')) {
          errors.repository = 'Git repository must be a valid URL (https:// or git@)';
        }
      }
    }

    // Polling interval validation
    if (formData.polling_enabled && formData.polling_interval_minutes) {
      if (formData.polling_interval_minutes < 1 || formData.polling_interval_minutes > 60) {
        errors.polling_interval_minutes = 'Polling interval must be between 1 and 60 minutes';
      }
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      await repositoriesApi.create(formData);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create repository');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCategoryToggle = (category: string) => {
    const current = formData.default_categories || [];
    const updated = current.includes(category)
      ? current.filter((c) => c !== category)
      : [...current, category];
    setFormData({ ...formData, default_categories: updated });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <h2 className="text-xl font-bold text-gold-400 mb-4">Add Repository</h2>

        {error && (
          <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded-lg text-red-400">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Platform Selection */}
          <div>
            <label className="block text-sm text-dark-400 mb-2">Platform *</label>
            <div className="flex gap-3">
              {(['github', 'gitlab', 'git'] as Platform[]).map((platform) => (
                <label key={platform} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="platform"
                    value={platform}
                    checked={formData.platform === platform}
                    onChange={(e) =>
                      setFormData({ ...formData, platform: e.target.value as Platform })
                    }
                    className="w-4 h-4"
                  />
                  <span className="text-dark-300 capitalize">{platform}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Repository */}
          <div>
            <label className="block text-sm text-dark-400 mb-1">
              Repository *
              <span className="text-xs ml-2">
                {formData.platform === 'git'
                  ? '(https://... or git@...)'
                  : '(owner/repo format)'}
              </span>
            </label>
            <input
              type="text"
              value={formData.repository}
              onChange={(e) => setFormData({ ...formData, repository: e.target.value })}
              placeholder={
                formData.platform === 'git'
                  ? 'https://github.com/owner/repo.git'
                  : 'owner/repository'
              }
              className={`input ${validationErrors.repository ? 'border-red-500' : ''}`}
              required
            />
            {validationErrors.repository && (
              <p className="text-red-400 text-sm mt-1">{validationErrors.repository}</p>
            )}
          </div>

          {/* Organization */}
          <div>
            <label className="block text-sm text-dark-400 mb-1">
              Organization
              <span className="text-xs ml-2">(for grouping in dashboard)</span>
            </label>
            <input
              type="text"
              value={formData.platform_organization}
              onChange={(e) =>
                setFormData({ ...formData, platform_organization: e.target.value })
              }
              placeholder="e.g., penguintechinc"
              className="input"
            />
          </div>

          {/* Display Name */}
          <div>
            <label className="block text-sm text-dark-400 mb-1">Display Name</label>
            <input
              type="text"
              value={formData.display_name}
              onChange={(e) => setFormData({ ...formData, display_name: e.target.value })}
              placeholder="Optional friendly name"
              className="input"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm text-dark-400 mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Optional description"
              className="input"
              rows={2}
            />
          </div>

          {/* Settings Row 1 */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.enabled}
                  onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="text-dark-300">Enable Repository</span>
              </label>
            </div>
            <div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.auto_review}
                  onChange={(e) => setFormData({ ...formData, auto_review: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="text-dark-300">Auto-Review PRs</span>
              </label>
            </div>
          </div>

          {/* Polling Configuration */}
          <div className="border border-dark-700 rounded-lg p-4">
            <label className="flex items-center gap-2 cursor-pointer mb-3">
              <input
                type="checkbox"
                checked={formData.polling_enabled}
                onChange={(e) =>
                  setFormData({ ...formData, polling_enabled: e.target.checked })
                }
                className="w-4 h-4"
              />
              <span className="text-dark-300 font-medium">Enable Polling</span>
            </label>

            {formData.polling_enabled && (
              <div>
                <label className="block text-sm text-dark-400 mb-1">
                  Polling Interval (minutes)
                </label>
                <input
                  type="number"
                  min="1"
                  max="60"
                  value={formData.polling_interval_minutes}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      polling_interval_minutes: parseInt(e.target.value) || 5,
                    })
                  }
                  className={`input w-32 ${
                    validationErrors.polling_interval_minutes ? 'border-red-500' : ''
                  }`}
                />
                {validationErrors.polling_interval_minutes && (
                  <p className="text-red-400 text-sm mt-1">
                    {validationErrors.polling_interval_minutes}
                  </p>
                )}
                <p className="text-xs text-dark-500 mt-1">
                  Check for new PRs/MRs every N minutes
                </p>
              </div>
            )}
          </div>

          {/* Review Categories */}
          <div>
            <label className="block text-sm text-dark-400 mb-2">Review Categories</label>
            <div className="flex flex-wrap gap-2">
              {['security', 'best_practices', 'framework', 'iac'].map((category) => (
                <label
                  key={category}
                  className="flex items-center gap-2 px-3 py-2 bg-dark-700 rounded cursor-pointer hover:bg-dark-600"
                >
                  <input
                    type="checkbox"
                    checked={formData.default_categories?.includes(category)}
                    onChange={() => handleCategoryToggle(category)}
                    className="w-4 h-4"
                  />
                  <span className="text-dark-300 capitalize">
                    {category.replace('_', ' ')}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* AI Provider */}
          <div>
            <label className="block text-sm text-dark-400 mb-1">Default AI Provider</label>
            <select
              value={formData.default_ai_provider}
              onChange={(e) =>
                setFormData({ ...formData, default_ai_provider: e.target.value })
              }
              className="input"
            >
              <option value="ollama">Ollama (Local)</option>
              <option value="anthropic">Anthropic Claude</option>
              <option value="openai">OpenAI</option>
            </select>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end gap-3 pt-4 border-t border-dark-700">
            <Button type="button" variant="secondary" onClick={onClose} disabled={isLoading}>
              Cancel
            </Button>
            <Button type="submit" isLoading={isLoading}>
              Create Repository
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
