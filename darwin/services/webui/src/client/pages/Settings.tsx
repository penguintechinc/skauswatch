import { useState, useEffect } from 'react';
import Card from '../components/Card';
import TabNavigation from '../components/TabNavigation';
import { configApi, elderApi } from '../hooks/useApi';

export default function Settings() {
  const [activeTab, setActiveTab] = useState('ai');
  const [config, setConfig] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Elder integration state
  const [elderStats, setElderStats] = useState<any>(null);
  const [elderTestResult, setElderTestResult] = useState<string | null>(null);
  const [elderTesting, setElderTesting] = useState(false);
  const [elderPushing, setElderPushing] = useState(false);

  const tabs = [
    { id: 'ai', label: 'AI Configuration' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'general', label: 'General' },
  ];

  useEffect(() => {
    fetchConfig();
    if (activeTab === 'integrations') {
      fetchElderStats();
    }
  }, [activeTab]);

  const fetchConfig = async () => {
    setIsLoading(true);
    try {
      const data = await configApi.get();
      setConfig(data);
      setError(null);
    } catch (err) {
      setError('Failed to load configuration');
      console.error('Error loading config:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchElderStats = async () => {
    try {
      const stats = await elderApi.getStats();
      setElderStats(stats);
    } catch (err) {
      console.error('Error loading Elder stats:', err);
    }
  };

  const saveConfig = async () => {
    setIsSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await configApi.update(config);
      setSuccess('Configuration saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError('Failed to save configuration');
      console.error('Error saving config:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const testElderConnection = async () => {
    setElderTesting(true);
    setElderTestResult(null);
    try {
      const result = await elderApi.test();
      setElderTestResult(`Success: ${result.message}`);
    } catch (err: any) {
      setElderTestResult(`Error: ${err.response?.data?.error || err.message}`);
    } finally {
      setElderTesting(false);
    }
  };

  const pushToElder = async () => {
    setElderPushing(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await elderApi.push();
      setSuccess(`Successfully pushed ${result.findings_pushed} findings to Elder`);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(`Failed to push to Elder: ${err.response?.data?.error || err.message}`);
    } finally {
      setElderPushing(false);
    }
  };

  const updateConfigValue = (path: string, value: any) => {
    const pathParts = path.split('.');
    const newConfig = JSON.parse(JSON.stringify(config));
    let current = newConfig;
    for (let i = 0; i < pathParts.length - 1; i++) {
      current = current[pathParts[i]];
    }
    current[pathParts[pathParts.length - 1]] = value;
    setConfig(newConfig);
  };

  if (isLoading) {
    return (
      <div>
        <h1 className="text-2xl font-bold text-gold-400 mb-6">Settings</h1>
        <div className="animate-pulse">
          <div className="h-64 bg-dark-800 rounded-lg"></div>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Settings</h1>
        <p className="text-dark-400 mt-1">Configure Darwin AI PR Reviewer</p>
      </div>

      {/* Alerts */}
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

      {/* Tab Navigation */}
      <TabNavigation tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'ai' && config && (
          <div className="space-y-6">
            {/* AI Enabled */}
            <Card title="AI Features">
              <div className="space-y-4">
                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">AI-Powered Reviews</span>
                    <span className="text-sm text-dark-400">Enable AI code review features</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.ai?.enabled || false}
                    onChange={(e) => updateConfigValue('ai.enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>

                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Default AI Provider</span>
                    <select
                      className="input"
                      value={config.ai?.default_provider || 'ollama'}
                      onChange={(e) => updateConfigValue('ai.default_provider', e.target.value)}
                    >
                      <option value="ollama">Ollama (Local)</option>
                      <option value="anthropic">Anthropic Claude</option>
                      <option value="openai">OpenAI</option>
                    </select>
                  </label>
                </div>
              </div>
            </Card>

            {/* Ollama Configuration */}
            <Card title="Ollama Provider">
              <div className="space-y-4">
                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Ollama Base URL</span>
                    <input
                      type="text"
                      className="input"
                      value={config.providers?.ollama?.base_url || ''}
                      onChange={(e) => updateConfigValue('providers.ollama.base_url', e.target.value)}
                      placeholder="http://ollama:11434"
                    />
                  </label>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block">
                      <span className="text-gold-400 block mb-2">Security Model</span>
                      <input
                        type="text"
                        className="input"
                        value={config.providers?.ollama?.models?.security || ''}
                        onChange={(e) => updateConfigValue('providers.ollama.models.security', e.target.value)}
                        placeholder="granite-code:34b"
                      />
                    </label>
                  </div>

                  <div>
                    <label className="block">
                      <span className="text-gold-400 block mb-2">Best Practices Model</span>
                      <input
                        type="text"
                        className="input"
                        value={config.providers?.ollama?.models?.best_practices || ''}
                        onChange={(e) => updateConfigValue('providers.ollama.models.best_practices', e.target.value)}
                        placeholder="llama3.3:70b"
                      />
                    </label>
                  </div>

                  <div>
                    <label className="block">
                      <span className="text-gold-400 block mb-2">Framework Model</span>
                      <input
                        type="text"
                        className="input"
                        value={config.providers?.ollama?.models?.framework || ''}
                        onChange={(e) => updateConfigValue('providers.ollama.models.framework', e.target.value)}
                        placeholder="codestral:22b"
                      />
                    </label>
                  </div>

                  <div>
                    <label className="block">
                      <span className="text-gold-400 block mb-2">IAC Model</span>
                      <input
                        type="text"
                        className="input"
                        value={config.providers?.ollama?.models?.iac || ''}
                        onChange={(e) => updateConfigValue('providers.ollama.models.iac', e.target.value)}
                        placeholder="granite-code:20b"
                      />
                    </label>
                  </div>
                </div>
              </div>
            </Card>

            {/* Review Categories */}
            <Card title="Review Categories">
              <div className="space-y-4">
                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">Security Reviews</span>
                    <span className="text-sm text-dark-400">Scan for security vulnerabilities</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.review_categories?.security_enabled || false}
                    onChange={(e) => updateConfigValue('review_categories.security_enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>

                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">Best Practices Reviews</span>
                    <span className="text-sm text-dark-400">Check code quality and best practices</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.review_categories?.best_practices_enabled || false}
                    onChange={(e) => updateConfigValue('review_categories.best_practices_enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>

                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">Framework Reviews</span>
                    <span className="text-sm text-dark-400">Framework-specific patterns and conventions</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.review_categories?.framework_enabled || false}
                    onChange={(e) => updateConfigValue('review_categories.framework_enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>

                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">IAC Reviews</span>
                    <span className="text-sm text-dark-400">Infrastructure as Code best practices</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.review_categories?.iac_enabled || false}
                    onChange={(e) => updateConfigValue('review_categories.iac_enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>
              </div>
            </Card>

            {/* Review Limits */}
            <Card title="Review Limits">
              <div className="space-y-4">
                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Max Files Per Review</span>
                    <input
                      type="number"
                      className="input"
                      value={config.review_limits?.max_files_per_review || 50}
                      onChange={(e) => updateConfigValue('review_limits.max_files_per_review', parseInt(e.target.value))}
                      min="1"
                      max="1000"
                    />
                  </label>
                </div>

                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Max Lines Per File</span>
                    <input
                      type="number"
                      className="input"
                      value={config.review_limits?.max_lines_per_file || 1000}
                      onChange={(e) => updateConfigValue('review_limits.max_lines_per_file', parseInt(e.target.value))}
                      min="100"
                      max="10000"
                    />
                  </label>
                </div>

                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Review Timeout (seconds)</span>
                    <input
                      type="number"
                      className="input"
                      value={config.review_limits?.review_timeout_seconds || 300}
                      onChange={(e) => updateConfigValue('review_limits.review_timeout_seconds', parseInt(e.target.value))}
                      min="60"
                      max="3600"
                    />
                  </label>
                </div>
              </div>
            </Card>

            {/* Save Button */}
            <div className="flex justify-end">
              <button
                onClick={saveConfig}
                disabled={isSaving}
                className="btn btn-primary"
              >
                {isSaving ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'integrations' && config && (
          <div className="space-y-6">
            {/* Elder Integration */}
            <Card title="Elder Security Platform Integration">
              <div className="space-y-4">
                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">Enable Elder Integration</span>
                    <span className="text-sm text-dark-400">Push security findings to Elder SIEM</span>
                  </div>
                  <input
                    type="checkbox"
                    checked={config.integrations?.elder?.enabled || false}
                    onChange={(e) => updateConfigValue('integrations.elder.enabled', e.target.checked)}
                    className="w-5 h-5"
                  />
                </label>

                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Elder URL</span>
                    <input
                      type="text"
                      className="input"
                      value={config.integrations?.elder?.url || ''}
                      onChange={(e) => updateConfigValue('integrations.elder.url', e.target.value)}
                      placeholder="https://elder.penguintech.io"
                    />
                  </label>
                </div>

                <div>
                  <label className="block">
                    <span className="text-gold-400 block mb-2">Elder API Key</span>
                    <input
                      type="password"
                      className="input"
                      value={config.integrations?.elder?.api_key || ''}
                      onChange={(e) => updateConfigValue('integrations.elder.api_key', e.target.value)}
                      placeholder="Enter API key"
                    />
                  </label>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={testElderConnection}
                    disabled={elderTesting || !config.integrations?.elder?.enabled}
                    className="btn btn-secondary"
                  >
                    {elderTesting ? 'Testing...' : 'Test Connection'}
                  </button>

                  <button
                    onClick={pushToElder}
                    disabled={elderPushing || !config.integrations?.elder?.enabled}
                    className="btn btn-primary"
                  >
                    {elderPushing ? 'Pushing...' : 'Push Findings to Elder'}
                  </button>
                </div>

                {elderTestResult && (
                  <div className={`p-3 rounded-lg border ${
                    elderTestResult.startsWith('Success')
                      ? 'bg-green-900/30 border-green-700 text-green-400'
                      : 'bg-red-900/30 border-red-700 text-red-400'
                  }`}>
                    {elderTestResult}
                  </div>
                )}

                {elderStats && (
                  <div className="mt-4 p-4 bg-dark-800 rounded-lg">
                    <h3 className="text-gold-400 mb-3">Available Findings</h3>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-dark-400">Total Findings:</span>
                        <span className="ml-2 text-gold-400 font-semibold">{elderStats.total_findings}</span>
                      </div>
                      <div>
                        <span className="text-dark-400">Critical:</span>
                        <span className="ml-2 text-red-400 font-semibold">{elderStats.by_severity.critical}</span>
                      </div>
                      <div>
                        <span className="text-dark-400">Major:</span>
                        <span className="ml-2 text-orange-400 font-semibold">{elderStats.by_severity.major}</span>
                      </div>
                      <div>
                        <span className="text-dark-400">Minor:</span>
                        <span className="ml-2 text-yellow-400 font-semibold">{elderStats.by_severity.minor}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {/* Save Button */}
            <div className="flex justify-end">
              <button
                onClick={saveConfig}
                disabled={isSaving}
                className="btn btn-primary"
              >
                {isSaving ? 'Saving...' : 'Save Configuration'}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'general' && (
          <Card title="General Settings">
            <div className="space-y-6">
              <div>
                <label className="flex items-center justify-between">
                  <div>
                    <span className="text-gold-400 block">Dark Mode</span>
                    <span className="text-sm text-dark-400">Use dark theme (default)</span>
                  </div>
                  <input type="checkbox" defaultChecked className="w-5 h-5" />
                </label>
              </div>

              <div>
                <label className="block">
                  <span className="text-gold-400 block mb-2">Timezone</span>
                  <select className="input">
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">Eastern Time</option>
                    <option value="America/Chicago">Central Time</option>
                    <option value="America/Denver">Mountain Time</option>
                    <option value="America/Los_Angeles">Pacific Time</option>
                  </select>
                </label>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
