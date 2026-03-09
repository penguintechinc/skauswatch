import { useState, useEffect } from 'react';
import { researchApi } from '../../hooks/useResearch';
import { ResearchLookupResponse, ResearchConfig } from '../../types/research';
import ResearchInput from './ResearchInput';
import ResearchResults from './ResearchResults';
import Card from '../Card';

export default function ResearchTab() {
  const [results, setResults] = useState<ResearchLookupResponse | null>(null);
  const [config, setConfig] = useState<ResearchConfig | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Load config on mount
    researchApi.getConfig().then(setConfig).catch(console.error);
  }, []);

  const handleSearch = async (query: string, indicatorType?: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await researchApi.lookup({
        query,
        indicator_type: indicatorType as any,
        include_threat_intel: true,
        include_shodan: config?.shodan_enabled ?? false,
        include_maltego: config?.maltego_enabled ?? false,
      });
      setResults(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Research lookup failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card title="Indicator Research">
        <ResearchInput onSearch={handleSearch} isLoading={isLoading} />
        {error && <div className="mt-4 text-red-400">{error}</div>}
      </Card>

      {results && config && (
        <ResearchResults results={results} config={config} />
      )}
    </div>
  );
}
