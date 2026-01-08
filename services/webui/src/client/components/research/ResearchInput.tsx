import { useState, useMemo } from 'react';

interface ResearchInputProps {
  onSearch: (query: string, indicatorType?: string) => void;
  isLoading: boolean;
}

type IndicatorType = 'IP' | 'Domain' | 'Hash' | 'URL' | 'Email' | 'Unknown';

// Regex patterns for indicator type detection
const INDICATOR_PATTERNS = {
  IP: /^(\d{1,3}\.){3}\d{1,3}$/,
  Domain: /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  Hash: /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/,
  URL: /^https?:\/\/.+/i,
  Email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

function detectIndicatorType(query: string): IndicatorType {
  if (!query.trim()) return 'Unknown';

  if (INDICATOR_PATTERNS.IP.test(query)) return 'IP';
  if (INDICATOR_PATTERNS.Hash.test(query)) return 'Hash';
  if (INDICATOR_PATTERNS.URL.test(query)) return 'URL';
  if (INDICATOR_PATTERNS.Email.test(query)) return 'Email';
  if (INDICATOR_PATTERNS.Domain.test(query)) return 'Domain';

  return 'Unknown';
}

function getBadgeColor(type: IndicatorType): string {
  const colors: Record<IndicatorType, string> = {
    IP: 'bg-blue-900/50 text-blue-400',
    Domain: 'bg-purple-900/50 text-purple-400',
    Hash: 'bg-pink-900/50 text-pink-400',
    URL: 'bg-cyan-900/50 text-cyan-400',
    Email: 'bg-orange-900/50 text-orange-400',
    Unknown: 'bg-dark-700 text-dark-400',
  };
  return colors[type];
}

export default function ResearchInput({
  onSearch,
  isLoading,
}: ResearchInputProps) {
  const [query, setQuery] = useState('');
  const indicatorType = useMemo(() => detectIndicatorType(query), [query]);

  const handleSearch = () => {
    if (query.trim()) {
      onSearch(
        query,
        indicatorType !== 'Unknown' ? indicatorType : undefined
      );
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isLoading) {
      handleSearch();
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Search IP, domain, hash, URL, or email..."
          className="input flex-1"
          disabled={isLoading}
        />
        <button
          onClick={handleSearch}
          disabled={isLoading || !query.trim()}
          className="px-4 py-2 bg-gold-500 text-dark-900 rounded-lg font-medium
                     hover:bg-gold-400 disabled:opacity-50 disabled:cursor-not-allowed
                     transition-colors duration-200"
        >
          {isLoading ? (
            <span className="flex items-center justify-center">
              <span className="animate-spin mr-2">⟳</span>
            </span>
          ) : (
            '🔍'
          )}
        </button>
      </div>

      {query.trim() && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-dark-400">Detected:</span>
          <span className={`badge ${getBadgeColor(indicatorType)}`}>
            {indicatorType}
          </span>
        </div>
      )}
    </div>
  );
}
