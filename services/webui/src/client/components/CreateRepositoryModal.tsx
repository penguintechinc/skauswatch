import { useState } from 'react';
import type { CreateRepositoryData } from '../modules/codescan/types';

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
    name: '',
    url: '',
    access_token: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
    const { name, value } = e.currentTarget;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      // Simulate API call - actual implementation will use repositoriesApi.create()
      // For now, just trigger success callback
      setFormData({ name: '', url: '', access_token: '' });
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create repository');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-slate-800 rounded-lg p-6 max-w-md w-full shadow-xl">
        <h2 className="text-xl font-bold text-amber-400 mb-4">Create Repository</h2>

        {error && (
          <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded text-red-400 text-sm">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="name" className="block text-sm font-medium text-slate-300 mb-1">
              Repository Name
            </label>
            <input
              id="name"
              type="text"
              name="name"
              value={formData.name}
              onChange={handleChange}
              required
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-400"
              placeholder="my-repo"
            />
          </div>

          <div>
            <label htmlFor="url" className="block text-sm font-medium text-slate-300 mb-1">
              Repository URL
            </label>
            <input
              id="url"
              type="url"
              name="url"
              value={formData.url}
              onChange={handleChange}
              required
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-400"
              placeholder="https://github.com/user/repo"
            />
          </div>

          <div>
            <label htmlFor="access_token" className="block text-sm font-medium text-slate-300 mb-1">
              Access Token
            </label>
            <input
              id="access_token"
              type="password"
              name="access_token"
              value={formData.access_token}
              onChange={handleChange}
              required
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-amber-400"
              placeholder="••••••••"
            />
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="flex-1 px-4 py-2 bg-slate-700 text-slate-300 rounded hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex-1 px-4 py-2 bg-amber-600 text-white rounded hover:bg-amber-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {isSubmitting ? 'Creating...' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
