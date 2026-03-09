import React, { useState } from 'react';

interface ReviewOptions {
  repository: string;
  owner: string;
  branch?: string;
  enableSecurityReview: boolean;
  enablePerformanceReview: boolean;
  enableStyleReview: boolean;
  excludePatterns: string[];
}

interface RepoReviewFormProps {
  onSubmit?: (options: ReviewOptions) => Promise<void>;
  isReadOnly?: boolean;
  submitButtonLabel?: string;
}

export default function RepoReviewForm({
  onSubmit,
  isReadOnly = false,
  submitButtonLabel = 'Start Review',
}: RepoReviewFormProps) {
  const [repository, setRepository] = useState('');
  const [owner, setOwner] = useState('');
  const [branch, setBranch] = useState('main');
  const [securityReview, setSecurityReview] = useState(true);
  const [performanceReview, setPerformanceReview] = useState(true);
  const [styleReview, setStyleReview] = useState(true);
  const [patternInput, setPatternInput] = useState('');
  const [excludePatterns, setExcludePatterns] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const handleAddPattern = () => {
    if (!patternInput.trim()) return;
    if (!excludePatterns.includes(patternInput)) {
      setExcludePatterns([...excludePatterns, patternInput]);
    }
    setPatternInput('');
  };

  const handleRemovePattern = (index: number) => {
    setExcludePatterns(excludePatterns.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!repository.trim() || !owner.trim() || !onSubmit) return;

    try {
      setSubmitting(true);
      await onSubmit({
        repository,
        owner,
        branch: branch || 'main',
        enableSecurityReview: securityReview,
        enablePerformanceReview: performanceReview,
        enableStyleReview: styleReview,
        excludePatterns,
      });
      // Reset form on success
      setRepository('');
      setOwner('');
      setBranch('main');
      setExcludePatterns([]);
    } catch (error) {
      console.error('Failed to submit review:', error);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="card space-y-4">
      <h3 className="text-lg font-semibold text-gold-400">Trigger Repository Review</h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gold-400 mb-2">Repository</label>
          <input
            type="text"
            value={repository}
            onChange={(e) => setRepository(e.target.value)}
            disabled={isReadOnly}
            required
            className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
            placeholder="e.g., darwin"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gold-400 mb-2">Owner</label>
          <input
            type="text"
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            disabled={isReadOnly}
            required
            className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
            placeholder="e.g., penguintechinc"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gold-400 mb-2">Branch</label>
        <input
          type="text"
          value={branch}
          onChange={(e) => setBranch(e.target.value)}
          disabled={isReadOnly}
          className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
          placeholder="e.g., main"
        />
      </div>

      <div className="space-y-2 pt-2 border-t border-elder-border">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={securityReview}
            onChange={(e) => setSecurityReview(e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Security Review</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={performanceReview}
            onChange={(e) => setPerformanceReview(e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Performance Review</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={styleReview}
            onChange={(e) => setStyleReview(e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Style Review</span>
        </label>
      </div>

      <div className="pt-2 border-t border-elder-border">
        <label className="block text-sm font-medium text-gold-400 mb-2">Exclude Patterns</label>
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={patternInput}
            onChange={(e) => setPatternInput(e.target.value)}
            disabled={isReadOnly}
            className="flex-1 px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
            placeholder="e.g., *.test.ts"
          />
          <button
            type="button"
            onClick={handleAddPattern}
            disabled={isReadOnly || !patternInput.trim()}
            className="px-3 py-2 rounded bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors text-sm font-medium"
          >
            Add
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {excludePatterns.map((pattern, idx) => (
            <span
              key={idx}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-elder-bg-darker text-elder-text-base text-xs"
            >
              {pattern}
              {!isReadOnly && (
                <button
                  type="button"
                  onClick={() => handleRemovePattern(idx)}
                  className="text-red-400 hover:text-red-300 cursor-pointer ml-1"
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
      </div>

      {!isReadOnly && (
        <button
          type="submit"
          disabled={!repository.trim() || !owner.trim() || submitting}
          className="w-full px-4 py-2 rounded bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors font-medium"
        >
          {submitting ? 'Starting Review...' : submitButtonLabel}
        </button>
      )}
    </form>
  );
}
