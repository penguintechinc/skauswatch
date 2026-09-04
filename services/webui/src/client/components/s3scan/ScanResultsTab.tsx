import { useState, useEffect } from 'react';
import Card from '../Card';
import Button from '../Button';
import { getCsrfToken, CSRF_HEADER_NAME } from '../../utils/csrf';

interface BucketConfig {
  id: number;
  bucket_name: string;
  aws_region: string;
  enabled: boolean;
}

interface ScanResult {
  id: number;
  bucket_name: string;
  object_key: string;
  object_size: number;
  file_type: string;
  status: 'clean' | 'infected' | 'pup' | 'error' | 'skipped';
  threat_names: string[];
  scanned_at: string;
  scan_duration_ms: number;
  md5_hash?: string;
  sha1_hash?: string;
  sha256_hash?: string;
  clamav_result?: any;
  yara_matches?: any[];
  threat_intel_enrichment?: any;
  sandbox_submission_id?: string;
  error_message?: string;
}

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

interface Statistics {
  total_scanned: number;
  infected: number;
  pup: number;
  clean: number;
  errors: number;
}

interface Filters {
  bucket_id?: number;
  status?: string[];
  threat_filter?: 'malware' | 'pup' | 'any';
  file_type?: string;
  date_from?: string;
  date_to?: string;
}

export default function ScanResultsTab() {
  const [buckets, setBuckets] = useState<BucketConfig[]>([]);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [statistics, setStatistics] = useState<Statistics>({
    total_scanned: 0,
    infected: 0,
    pup: 0,
    clean: 0,
    errors: 0,
  });
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [perPage] = useState(20);

  // Filter state
  const [filters, setFilters] = useState<Filters>({});
  const [selectedBucket, setSelectedBucket] = useState<string>('');
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
  const [threatFilter, setThreatFilter] = useState<string>('');
  const [fileType, setFileType] = useState<string>('');
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');

  // Load buckets on mount
  useEffect(() => {
    loadBuckets();
  }, []);

  // Load results when page or filters change
  useEffect(() => {
    loadResults();
    loadStatistics();
  }, [currentPage, filters]);

  const loadBuckets = async () => {
    try {
      const response = await fetch('/api/v1/s3-scan/buckets', { credentials: 'include' });
      if (!response.ok) throw new Error('Failed to load buckets');
      const data = await response.json();
      setBuckets(data.items || []);
    } catch (err) {
      console.error('Error loading buckets:', err);
    }
  };

  const loadResults = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: currentPage.toString(),
        per_page: perPage.toString(),
      });

      if (filters.bucket_id) params.append('bucket_id', filters.bucket_id.toString());
      if (filters.status && filters.status.length > 0) {
        filters.status.forEach(s => params.append('status', s));
      }
      if (filters.threat_filter) params.append('threat_filter', filters.threat_filter);
      if (filters.file_type) params.append('file_type', filters.file_type);
      if (filters.date_from) params.append('date_from', filters.date_from);
      if (filters.date_to) params.append('date_to', filters.date_to);

      const response = await fetch(`/api/v1/s3-scan/results?${params.toString()}`, {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to load scan results');

      const data: PaginatedResponse<ScanResult> = await response.json();
      setResults(data.items);
      setTotalPages(data.pages);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load results');
    } finally {
      setIsLoading(false);
    }
  };

  const loadStatistics = async () => {
    try {
      const params = new URLSearchParams();
      if (filters.bucket_id) params.append('bucket_id', filters.bucket_id.toString());
      if (filters.date_from) params.append('date_from', filters.date_from);
      if (filters.date_to) params.append('date_to', filters.date_to);

      const response = await fetch(`/api/v1/s3-scan/statistics?${params.toString()}`, {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to load statistics');

      const data = await response.json();
      setStatistics(data);
    } catch (err) {
      console.error('Error loading statistics:', err);
    }
  };

  const applyFilters = () => {
    const newFilters: Filters = {};

    if (selectedBucket) {
      const bucket = buckets.find(b => b.bucket_name === selectedBucket);
      if (bucket) newFilters.bucket_id = bucket.id;
    }
    if (selectedStatuses.length > 0) newFilters.status = selectedStatuses;
    if (threatFilter) newFilters.threat_filter = threatFilter as any;
    if (fileType) newFilters.file_type = fileType;
    if (dateFrom) newFilters.date_from = dateFrom;
    if (dateTo) newFilters.date_to = dateTo;

    setFilters(newFilters);
    setCurrentPage(1);
  };

  const clearFilters = () => {
    setSelectedBucket('');
    setSelectedStatuses([]);
    setThreatFilter('');
    setFileType('');
    setDateFrom('');
    setDateTo('');
    setFilters({});
    setCurrentPage(1);
  };

  const handleStatusToggle = (status: string) => {
    setSelectedStatuses(prev =>
      prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status]
    );
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getStatusBadge = (status: string) => {
    const statusClasses = {
      clean: 'bg-green-500/20 text-green-400 border-green-500/30',
      infected: 'bg-red-500/20 text-red-400 border-red-500/30',
      pup: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      error: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
      skipped: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    };

    return (
      <span className={`px-2 py-1 rounded text-xs font-medium border ${statusClasses[status as keyof typeof statusClasses]}`}>
        {status.toUpperCase()}
      </span>
    );
  };

  const createIndicator = async (result: ScanResult) => {
    try {
      const iocData = {
        type: 'file_hash',
        value: result.sha256_hash || result.md5_hash,
        threat_level: result.status === 'infected' ? 'high' : 'medium',
        source: 's3-scan',
        tags: ['s3-scan', result.bucket_name, ...result.threat_names],
        context: {
          bucket: result.bucket_name,
          object_key: result.object_key,
          file_type: result.file_type,
          scan_result_id: result.id,
        },
      };

      const csrfToken = getCsrfToken();
      const response = await fetch('/api/v1/threat-intel/iocs', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : {}),
        },
        body: JSON.stringify(iocData),
      });

      if (!response.ok) throw new Error('Failed to create indicator');
      alert('Indicator created successfully');
    } catch (err) {
      alert(`Error creating indicator: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  const submitToSandbox = async (result: ScanResult) => {
    try {
      const csrfToken = getCsrfToken();
      const response = await fetch('/api/v1/s3-scan/submit-sandbox', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : {}),
        },
        body: JSON.stringify({
          scan_result_id: result.id,
          bucket_name: result.bucket_name,
          object_key: result.object_key,
        }),
      });

      if (!response.ok) throw new Error('Failed to submit to sandbox');
      const data = await response.json();
      alert(`Submitted to sandbox: ${data.submission_id}`);
      loadResults();
    } catch (err) {
      alert(`Error submitting to sandbox: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Filter Panel */}
      <Card title="Filters" className="bg-dark-800">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Bucket Selector */}
            <div>
              <label className="block text-sm font-medium text-white mb-2">Bucket</label>
              <select
                value={selectedBucket}
                onChange={(e) => setSelectedBucket(e.target.value)}
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded text-white focus:outline-none focus:border-gold-400"
              >
                <option value="">All Buckets</option>
                {buckets.map(bucket => (
                  <option key={bucket.id} value={bucket.bucket_name}>
                    {bucket.bucket_name}
                  </option>
                ))}
              </select>
            </div>

            {/* File Type Filter */}
            <div>
              <label className="block text-sm font-medium text-white mb-2">File Type</label>
              <input
                type="text"
                value={fileType}
                onChange={(e) => setFileType(e.target.value)}
                placeholder="e.g., pdf, exe, zip"
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded text-white focus:outline-none focus:border-gold-400"
              />
            </div>

            {/* Threat Filter */}
            <div>
              <label className="block text-sm font-medium text-white mb-2">Threat Type</label>
              <select
                value={threatFilter}
                onChange={(e) => setThreatFilter(e.target.value)}
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded text-white focus:outline-none focus:border-gold-400"
              >
                <option value="">All Threats</option>
                <option value="malware">Malware Only</option>
                <option value="pup">PUP Only</option>
                <option value="any">Any Threat</option>
              </select>
            </div>

            {/* Date From */}
            <div>
              <label className="block text-sm font-medium text-white mb-2">Date From</label>
              <input
                type="datetime-local"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded text-white focus:outline-none focus:border-gold-400"
              />
            </div>

            {/* Date To */}
            <div>
              <label className="block text-sm font-medium text-white mb-2">Date To</label>
              <input
                type="datetime-local"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded text-white focus:outline-none focus:border-gold-400"
              />
            </div>
          </div>

          {/* Status Checkboxes */}
          <div>
            <label className="block text-sm font-medium text-white mb-2">Status</label>
            <div className="flex flex-wrap gap-4">
              {['clean', 'infected', 'pup', 'error', 'skipped'].map(status => (
                <label key={status} className="flex items-center space-x-2 text-white">
                  <input
                    type="checkbox"
                    checked={selectedStatuses.includes(status)}
                    onChange={() => handleStatusToggle(status)}
                    className="w-4 h-4 bg-dark-900 border-dark-600 rounded focus:ring-gold-400"
                  />
                  <span className="capitalize">{status}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Filter Buttons */}
          <div className="flex gap-3">
            <Button onClick={applyFilters} variant="primary">
              Apply Filters
            </Button>
            <Button onClick={clearFilters} variant="secondary">
              Clear Filters
            </Button>
          </div>
        </div>
      </Card>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-dark-800">
          <div className="text-center">
            <div className="text-3xl font-bold text-white">{statistics.total_scanned.toLocaleString()}</div>
            <div className="text-sm text-gray-400 mt-1">Total Scanned</div>
          </div>
        </Card>
        <Card className="bg-dark-800">
          <div className="text-center">
            <div className="text-3xl font-bold text-red-400">{statistics.infected.toLocaleString()}</div>
            <div className="text-sm text-gray-400 mt-1">Infected</div>
          </div>
        </Card>
        <Card className="bg-dark-800">
          <div className="text-center">
            <div className="text-3xl font-bold text-orange-400">{statistics.pup.toLocaleString()}</div>
            <div className="text-sm text-gray-400 mt-1">PUP</div>
          </div>
        </Card>
        <Card className="bg-dark-800">
          <div className="text-center">
            <div className="text-3xl font-bold text-green-400">{statistics.clean.toLocaleString()}</div>
            <div className="text-sm text-gray-400 mt-1">Clean</div>
          </div>
        </Card>
        <Card className="bg-dark-800">
          <div className="text-center">
            <div className="text-3xl font-bold text-gray-400">{statistics.errors.toLocaleString()}</div>
            <div className="text-sm text-gray-400 mt-1">Errors</div>
          </div>
        </Card>
      </div>

      {/* Results Table */}
      <Card title="Scan Results" className="bg-dark-800">
        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500/30 rounded text-red-400">
            {error}
          </div>
        )}

        {isLoading ? (
          <div className="text-center py-8">
            <div className="inline-block animate-spin text-4xl text-gold-400">⟳</div>
            <div className="mt-2 text-white">Loading results...</div>
          </div>
        ) : results.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No scan results found. Adjust your filters or scan some buckets.
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-dark-600">
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Object Key</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Size</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">File Type</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Status</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Threat Names</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Scanned At</th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gold-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(result => (
                    <tr
                      key={result.id}
                      className="border-b border-dark-600 hover:bg-dark-700 cursor-pointer"
                      onClick={() => setSelectedResult(result)}
                    >
                      <td className="px-4 py-3 text-sm text-white">
                        <div className="max-w-xs truncate" title={result.object_key}>
                          {result.object_key}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-white">{formatBytes(result.object_size)}</td>
                      <td className="px-4 py-3 text-sm text-white">{result.file_type}</td>
                      <td className="px-4 py-3 text-sm">{getStatusBadge(result.status)}</td>
                      <td className="px-4 py-3 text-sm text-white">
                        {result.threat_names.length > 0 ? (
                          <div className="max-w-xs truncate" title={result.threat_names.join(', ')}>
                            {result.threat_names.join(', ')}
                          </div>
                        ) : (
                          <span className="text-gray-400">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-white">{formatDate(result.scanned_at)}</td>
                      <td className="px-4 py-3 text-sm">
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedResult(result);
                          }}
                        >
                          View Details
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="mt-4 flex items-center justify-between">
              <div className="text-sm text-gray-400">
                Page {currentPage} of {totalPages}
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>

      {/* Detail Modal */}
      {selectedResult && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-dark-800 border-b border-dark-600 p-6 flex items-center justify-between">
              <h2 className="text-2xl font-bold text-gold-400">Scan Result Details</h2>
              <button
                onClick={() => setSelectedResult(null)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>

            <div className="p-6 space-y-6">
              {/* Basic Information */}
              <div>
                <h3 className="text-lg font-semibold text-gold-400 mb-3">Basic Information</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Bucket:</span>
                    <span className="ml-2 text-white">{selectedResult.bucket_name}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Status:</span>
                    <span className="ml-2">{getStatusBadge(selectedResult.status)}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-gray-400">Object Key:</span>
                    <span className="ml-2 text-white break-all">{selectedResult.object_key}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Size:</span>
                    <span className="ml-2 text-white">{formatBytes(selectedResult.object_size)}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">File Type:</span>
                    <span className="ml-2 text-white">{selectedResult.file_type}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Scanned At:</span>
                    <span className="ml-2 text-white">{formatDate(selectedResult.scanned_at)}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Scan Duration:</span>
                    <span className="ml-2 text-white">{selectedResult.scan_duration_ms}ms</span>
                  </div>
                </div>
              </div>

              {/* File Hashes */}
              {(selectedResult.md5_hash || selectedResult.sha1_hash || selectedResult.sha256_hash) && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">File Hashes</h3>
                  <div className="space-y-2 text-sm">
                    {selectedResult.md5_hash && (
                      <div className="flex">
                        <span className="text-gray-400 w-24">MD5:</span>
                        <span className="text-white font-mono">{selectedResult.md5_hash}</span>
                      </div>
                    )}
                    {selectedResult.sha1_hash && (
                      <div className="flex">
                        <span className="text-gray-400 w-24">SHA1:</span>
                        <span className="text-white font-mono">{selectedResult.sha1_hash}</span>
                      </div>
                    )}
                    {selectedResult.sha256_hash && (
                      <div className="flex">
                        <span className="text-gray-400 w-24">SHA256:</span>
                        <span className="text-white font-mono">{selectedResult.sha256_hash}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Threat Information */}
              {selectedResult.threat_names.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">Threat Names</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedResult.threat_names.map((threat, idx) => (
                      <span
                        key={idx}
                        className="px-3 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-sm"
                      >
                        {threat}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ClamAV Results */}
              {selectedResult.clamav_result && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">ClamAV Results</h3>
                  <pre className="bg-dark-900 p-4 rounded text-sm text-white overflow-x-auto">
                    {JSON.stringify(selectedResult.clamav_result, null, 2)}
                  </pre>
                </div>
              )}

              {/* YARA Matches */}
              {selectedResult.yara_matches && selectedResult.yara_matches.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">YARA Matches</h3>
                  <pre className="bg-dark-900 p-4 rounded text-sm text-white overflow-x-auto">
                    {JSON.stringify(selectedResult.yara_matches, null, 2)}
                  </pre>
                </div>
              )}

              {/* Threat Intel Enrichment */}
              {selectedResult.threat_intel_enrichment && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">Threat Intel Enrichment</h3>
                  <pre className="bg-dark-900 p-4 rounded text-sm text-white overflow-x-auto">
                    {JSON.stringify(selectedResult.threat_intel_enrichment, null, 2)}
                  </pre>
                </div>
              )}

              {/* Error Message */}
              {selectedResult.error_message && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">Error Details</h3>
                  <div className="bg-red-500/20 border border-red-500/30 rounded p-4 text-red-400 text-sm">
                    {selectedResult.error_message}
                  </div>
                </div>
              )}

              {/* Sandbox Submission */}
              {selectedResult.sandbox_submission_id && (
                <div>
                  <h3 className="text-lg font-semibold text-gold-400 mb-3">Sandbox Analysis</h3>
                  <div className="text-sm text-white">
                    <span className="text-gray-400">Submission ID:</span>
                    <span className="ml-2 font-mono">{selectedResult.sandbox_submission_id}</span>
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-3 pt-4 border-t border-dark-600">
                <Button
                  variant="primary"
                  onClick={() => createIndicator(selectedResult)}
                >
                  Create Indicator
                </Button>
                {!selectedResult.sandbox_submission_id && (
                  <Button
                    variant="secondary"
                    onClick={() => submitToSandbox(selectedResult)}
                  >
                    Submit to Sandbox
                  </Button>
                )}
                <Button
                  variant="secondary"
                  onClick={() => setSelectedResult(null)}
                >
                  Close
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
