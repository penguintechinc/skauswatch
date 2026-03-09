import React, { useState, useEffect } from 'react';

interface RepositoryConfig {
  name: string;
  owner: string;
  url: string;
  excludePatterns: string[];
  includePatterns: string[];
  maxFileSize: number;
  enableSecurityChecks: boolean;
  enablePerformanceChecks: boolean;
  enableStyleChecks: boolean;
}

interface ConfigEditorProps {
  initialConfig?: RepositoryConfig;
  onSave?: (config: RepositoryConfig) => Promise<void>;
  isReadOnly?: boolean;
}

export default function ConfigEditor({
  initialConfig,
  onSave,
  isReadOnly = false,
}: ConfigEditorProps) {
  const [config, setConfig] = useState<RepositoryConfig>(
    initialConfig || {
      name: '',
      owner: '',
      url: '',
      excludePatterns: [],
      includePatterns: [],
      maxFileSize: 5242880,
      enableSecurityChecks: true,
      enablePerformanceChecks: true,
      enableStyleChecks: true,
    }
  );
  const [saving, setSaving] = useState(false);
  const [patternInput, setPatternInput] = useState('');

  const handleInputChange = (
    field: keyof RepositoryConfig,
    value: string | number | boolean
  ) => {
    setConfig((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const addPattern = (type: 'exclude' | 'include') => {
    if (!patternInput.trim()) return;
    setConfig((prev) => ({
      ...prev,
      [type === 'exclude' ? 'excludePatterns' : 'includePatterns']: [
        ...(type === 'exclude' ? prev.excludePatterns : prev.includePatterns),
        patternInput,
      ],
    }));
    setPatternInput('');
  };

  const removePattern = (type: 'exclude' | 'include', index: number) => {
    setConfig((prev) => ({
      ...prev,
      [type === 'exclude' ? 'excludePatterns' : 'includePatterns']: (
        type === 'exclude' ? prev.excludePatterns : prev.includePatterns
      ).filter((_, i) => i !== index),
    }));
  };

  const handleSave = async () => {
    if (!onSave) return;
    try {
      setSaving(true);
      await onSave(config);
    } catch (error) {
      console.error('Failed to save config:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card space-y-4">
      <div>
        <label className="block text-sm font-medium text-gold-400 mb-2">Repository Name</label>
        <input
          type="text"
          value={config.name}
          onChange={(e) => handleInputChange('name', e.target.value)}
          disabled={isReadOnly}
          className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
          placeholder="e.g., darwin"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gold-400 mb-2">Owner</label>
          <input
            type="text"
            value={config.owner}
            onChange={(e) => handleInputChange('owner', e.target.value)}
            disabled={isReadOnly}
            className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
            placeholder="e.g., penguintechinc"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gold-400 mb-2">Max File Size (bytes)</label>
          <input
            type="number"
            value={config.maxFileSize}
            onChange={(e) => handleInputChange('maxFileSize', parseInt(e.target.value, 10))}
            disabled={isReadOnly}
            className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gold-400 mb-2">Repository URL</label>
        <input
          type="url"
          value={config.url}
          onChange={(e) => handleInputChange('url', e.target.value)}
          disabled={isReadOnly}
          className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none disabled:opacity-50"
          placeholder="https://github.com/..."
        />
      </div>

      <div className="space-y-2">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enableSecurityChecks}
            onChange={(e) => handleInputChange('enableSecurityChecks', e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Enable Security Checks</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enablePerformanceChecks}
            onChange={(e) => handleInputChange('enablePerformanceChecks', e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Enable Performance Checks</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enableStyleChecks}
            onChange={(e) => handleInputChange('enableStyleChecks', e.target.checked)}
            disabled={isReadOnly}
            className="rounded"
          />
          <span className="text-sm text-elder-text-base">Enable Style Checks</span>
        </label>
      </div>

      <div>
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
            onClick={() => addPattern('exclude')}
            disabled={isReadOnly || !patternInput.trim()}
            className="px-3 py-2 rounded bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors text-sm font-medium"
          >
            Add
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {config.excludePatterns.map((pattern, idx) => (
            <span
              key={idx}
              className="inline-flex items-center gap-1 px-2 py-1 rounded bg-elder-bg-darker text-elder-text-base text-xs"
            >
              {pattern}
              {!isReadOnly && (
                <button
                  onClick={() => removePattern('exclude', idx)}
                  className="text-red-400 hover:text-red-300 cursor-pointer"
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
      </div>

      {!isReadOnly && onSave && (
        <button
          onClick={handleSave}
          disabled={saving}
          className="w-full px-4 py-2 rounded bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors font-medium"
        >
          {saving ? 'Saving...' : 'Save Configuration'}
        </button>
      )}
    </div>
  );
}
