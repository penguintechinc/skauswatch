import React, { useState, useEffect } from 'react';
import { s3ScanApi, BucketConfig } from '../../hooks/useS3Scan';

interface BucketConfigFormData {
  name: string;
  endpoint_url: string;
  bucket_name: string;
  access_key_id: string;
  secret_access_key: string;
  region: string;
  use_ssl: boolean;
  path_style: boolean;
  prefix_filter: string;
  max_file_size_mb: number;
  scan_enabled: boolean;
  yara_enabled: boolean;
  schedule?: string;
  schedule_timezone?: string;
}

const initialFormData: BucketConfigFormData = {
  name: '',
  endpoint_url: '',
  bucket_name: '',
  access_key_id: '',
  secret_access_key: '',
  region: 'us-east-1',
  use_ssl: true,
  path_style: true,
  prefix_filter: '',
  max_file_size_mb: 100,
  scan_enabled: true,
  yara_enabled: false,
  schedule: '',
  schedule_timezone: 'UTC',
};

const timezones = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Dubai',
  'Australia/Sydney',
];

const BucketConfigTab: React.FC = () => {
  const [buckets, setBuckets] = useState<BucketConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingBucket, setEditingBucket] = useState<BucketConfig | null>(null);
  const [formData, setFormData] = useState<BucketConfigFormData>(initialFormData);
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [showTestModal, setShowTestModal] = useState(false);
  const [scanningBucketId, setScanningBucketId] = useState<string | null>(null);
  const [showScanConfirmation, setShowScanConfirmation] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [deletingBucketId, setDeletingBucketId] = useState<string | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [bucketToDelete, setBucketToDelete] = useState<BucketConfig | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    loadBuckets();
  }, []);

  useEffect(() => {
    if (successMessage) {
      const timer = setTimeout(() => {
        setSuccessMessage(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [successMessage]);

  const loadBuckets = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await s3ScanApi.listBuckets();
      // Extract items array if data is a paginated response
      setBuckets(Array.isArray(data) ? data : (data as unknown as { items: BucketConfig[] }).items || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load buckets');
    } finally {
      setLoading(false);
    }
  };

  const openAddModal = () => {
    setEditingBucket(null);
    setFormData(initialFormData);
    setFormErrors({});
    setTestResult(null);
    setShowModal(true);
  };

  const openEditModal = (bucket: BucketConfig) => {
    setEditingBucket(bucket);
    const bucketWithSchedule = bucket as unknown as BucketConfigFormData;
    setFormData({
      name: bucket.name,
      endpoint_url: bucket.endpoint_url,
      bucket_name: bucket.bucket_name,
      access_key_id: bucket.access_key_id,
      secret_access_key: '',
      region: bucket.region || 'us-east-1',
      use_ssl: bucket.use_ssl !== false,
      path_style: bucket.path_style !== false,
      prefix_filter: bucket.prefix_filter || '',
      max_file_size_mb: bucket.max_file_size_mb || 100,
      scan_enabled: bucket.scan_enabled !== false,
      yara_enabled: bucket.yara_enabled || false,
      schedule: bucketWithSchedule.schedule || '',
      schedule_timezone: bucketWithSchedule.schedule_timezone || 'UTC',
    });
    setFormErrors({});
    setTestResult(null);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setEditingBucket(null);
    setFormData(initialFormData);
    setFormErrors({});
    setTestResult(null);
  };

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    if (!formData.name.trim()) {
      errors.name = 'Name is required';
    }
    if (!formData.endpoint_url.trim()) {
      errors.endpoint_url = 'Endpoint URL is required';
    } else if (!/^https?:\/\/.+/.test(formData.endpoint_url)) {
      errors.endpoint_url = 'Endpoint URL must start with http:// or https://';
    }
    if (!formData.bucket_name.trim()) {
      errors.bucket_name = 'Bucket name is required';
    }
    if (!formData.access_key_id.trim()) {
      errors.access_key_id = 'Access Key ID is required';
    }
    if (!editingBucket && !formData.secret_access_key.trim()) {
      errors.secret_access_key = 'Secret Access Key is required';
    }
    if (!formData.region.trim()) {
      errors.region = 'Region is required';
    }
    if (formData.max_file_size_mb <= 0) {
      errors.max_file_size_mb = 'Max file size must be greater than 0';
    }
    if (formData.schedule && formData.schedule.trim()) {
      const cronRegex = /^(\*|([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])|\*\/([0-9]+))\s+(\*|([0-9]|1[0-9]|2[0-3])|\*\/([0-9]+))\s+(\*|([1-9]|1[0-9]|2[0-9]|3[0-1])|\*\/([0-9]+))\s+(\*|([1-9]|1[0-2])|\*\/([0-9]+))\s+(\*|([0-6])|\*\/([0-9]+))$/;
      if (!cronRegex.test(formData.schedule.trim())) {
        errors.schedule = 'Invalid cron expression (format: minute hour day month weekday)';
      }
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleInputChange = (field: keyof BucketConfigFormData, value: string | boolean | number) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (formErrors[field]) {
      setFormErrors(prev => {
        const updated = { ...prev };
        delete updated[field];
        return updated;
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setSubmitting(true);
    try {
      const submitData: any = { ...formData };

      if (editingBucket && !submitData.secret_access_key) {
        delete submitData.secret_access_key;
      }

      if (!submitData.schedule || !submitData.schedule.trim()) {
        delete submitData.schedule;
        delete submitData.schedule_timezone;
      }

      if (editingBucket) {
        await s3ScanApi.updateBucket(editingBucket.id, submitData);
        setSuccessMessage(`Bucket "${formData.name}" updated successfully`);
      } else {
        await s3ScanApi.createBucket(submitData);
        setSuccessMessage(`Bucket "${formData.name}" created successfully`);
      }

      await loadBuckets();
      closeModal();
    } catch (err) {
      setFormErrors({ submit: err instanceof Error ? err.message : 'Failed to save bucket configuration' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestConnection = async () => {
    if (!validateForm()) {
      return;
    }

    setTestingConnection(true);
    setTestResult(null);

    try {
      const testData: any = { ...formData };
      if (editingBucket && !testData.secret_access_key) {
        delete testData.secret_access_key;
      }

      const result = await s3ScanApi.testConnection(testData);
      setTestResult({
        success: result.success,
        message: result.message || (result.success ? 'Connection successful' : 'Connection failed'),
      });
      setShowTestModal(true);
    } catch (err) {
      setTestResult({
        success: false,
        message: err instanceof Error ? err.message : 'Connection test failed',
      });
      setShowTestModal(true);
    } finally {
      setTestingConnection(false);
    }
  };

  const handleToggleScanEnabled = async (bucket: BucketConfig) => {
    try {
      await s3ScanApi.updateBucket(bucket.id, {
        scan_enabled: !bucket.scan_enabled,
      });
      await loadBuckets();
      setSuccessMessage(`Bucket "${bucket.name}" ${!bucket.scan_enabled ? 'enabled' : 'disabled'}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle scan enabled');
    }
  };

  const handleTriggerScan = async (bucket: BucketConfig) => {
    setScanningBucketId(String(bucket.id));
    try {
      const result = await s3ScanApi.triggerScan(bucket.id);
      setScanJobId(result.job_id);
      setShowScanConfirmation(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger scan');
    } finally {
      setScanningBucketId(null);
    }
  };

  const handleDeleteClick = (bucket: BucketConfig) => {
    setBucketToDelete(bucket);
    setShowDeleteConfirm(true);
  };

  const handleDeleteConfirm = async () => {
    if (!bucketToDelete) return;

    setDeletingBucketId(String(bucketToDelete.id));
    try {
      await s3ScanApi.deleteBucket(bucketToDelete.id);
      setSuccessMessage(`Bucket "${bucketToDelete.name}" deleted successfully`);
      await loadBuckets();
      setShowDeleteConfirm(false);
      setBucketToDelete(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete bucket');
    } finally {
      setDeletingBucketId(null);
    }
  };

  const handleDeleteCancel = () => {
    setShowDeleteConfirm(false);
    setBucketToDelete(null);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-dark-300">Loading bucket configurations...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-900/20 border border-red-700 text-red-400 px-4 py-3 rounded-lg flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="text-red-400 hover:text-red-300"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {successMessage && (
        <div className="bg-green-900/20 border border-green-700 text-green-400 px-4 py-3 rounded-lg flex items-center justify-between">
          <span>{successMessage}</span>
          <button
            onClick={() => setSuccessMessage(null)}
            className="text-green-400 hover:text-green-300"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">S3 Bucket Configurations</h2>
        <button
          onClick={openAddModal}
          className="bg-gold-500 hover:bg-gold-600 text-dark-900 px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Bucket
        </button>
      </div>

      {buckets.length === 0 ? (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-8 text-center">
          <div className="text-dark-300 mb-4">No bucket configurations found</div>
          <button
            onClick={openAddModal}
            className="bg-gold-500 hover:bg-gold-600 text-dark-900 px-4 py-2 rounded-lg font-medium transition-colors inline-flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Your First Bucket
          </button>
        </div>
      ) : (
        <div className="bg-dark-800 border border-dark-600 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-dark-700 border-b border-dark-600">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Endpoint URL
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Bucket Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Scan Enabled
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Schedule
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gold-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {buckets.map((bucket) => (
                  <tr key={bucket.id} className="hover:bg-dark-700 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-white font-medium">{bucket.name}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-dark-300 text-sm">{bucket.endpoint_url}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-dark-300 text-sm">{bucket.bucket_name}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleScanEnabled(bucket)}
                        className="focus:outline-none"
                        title={bucket.scan_enabled ? 'Disable scanning' : 'Enable scanning'}
                      >
                        {bucket.scan_enabled ? (
                          <svg className="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        ) : (
                          <svg className="w-6 h-6 text-dark-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        )}
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {(bucket as unknown as BucketConfigFormData).schedule ? (
                        <div className="text-dark-300 text-sm">
                          <div className="font-mono">{(bucket as unknown as BucketConfigFormData).schedule}</div>
                          <div className="text-xs text-dark-400">{(bucket as unknown as BucketConfigFormData).schedule_timezone || 'UTC'}</div>
                        </div>
                      ) : (
                        <span className="text-dark-500 text-sm">Not scheduled</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEditModal(bucket)}
                          className="text-gold-400 hover:text-gold-300 transition-colors"
                          title="Edit configuration"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleTestConnection()}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                          title="Test connection"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleTriggerScan(bucket)}
                          disabled={scanningBucketId === String(bucket.id)}
                          className="text-green-400 hover:text-green-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Trigger manual scan"
                        >
                          {scanningBucketId === String(bucket.id) ? (
                            <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                          ) : (
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                            </svg>
                          )}
                        </button>
                        <button
                          onClick={() => handleDeleteClick(bucket)}
                          disabled={deletingBucketId === String(bucket.id)}
                          className="text-red-400 hover:text-red-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Delete configuration"
                        >
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-dark-800 border-b border-dark-600 px-6 py-4 flex items-center justify-between">
              <h3 className="text-xl font-bold text-white">
                {editingBucket ? 'Edit Bucket Configuration' : 'Add Bucket Configuration'}
              </h3>
              <button
                onClick={closeModal}
                className="text-dark-400 hover:text-white transition-colors"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              {formErrors.submit && (
                <div className="bg-red-900/20 border border-red-700 text-red-400 px-4 py-3 rounded-lg">
                  {formErrors.submit}
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => handleInputChange('name', e.target.value)}
                  className={`w-full bg-dark-800 border ${formErrors.name ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                  placeholder="My S3 Bucket"
                />
                {formErrors.name && <p className="text-red-500 text-sm mt-1">{formErrors.name}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Endpoint URL <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.endpoint_url}
                  onChange={(e) => handleInputChange('endpoint_url', e.target.value)}
                  className={`w-full bg-dark-800 border ${formErrors.endpoint_url ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                  placeholder="https://s3.amazonaws.com or https://minio.example.com:9000"
                />
                {formErrors.endpoint_url && <p className="text-red-500 text-sm mt-1">{formErrors.endpoint_url}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Bucket Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.bucket_name}
                  onChange={(e) => handleInputChange('bucket_name', e.target.value)}
                  className={`w-full bg-dark-800 border ${formErrors.bucket_name ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                  placeholder="my-bucket-name"
                />
                {formErrors.bucket_name && <p className="text-red-500 text-sm mt-1">{formErrors.bucket_name}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Access Key ID <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={formData.access_key_id}
                  onChange={(e) => handleInputChange('access_key_id', e.target.value)}
                  className={`w-full bg-dark-800 border ${formErrors.access_key_id ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                />
                {formErrors.access_key_id && <p className="text-red-500 text-sm mt-1">{formErrors.access_key_id}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Secret Access Key {!editingBucket && <span className="text-red-500">*</span>}
                  {editingBucket && <span className="text-dark-400 text-xs ml-2">(leave blank to keep existing)</span>}
                </label>
                <input
                  type="password"
                  value={formData.secret_access_key}
                  onChange={(e) => handleInputChange('secret_access_key', e.target.value)}
                  className={`w-full bg-dark-800 border ${formErrors.secret_access_key ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                />
                {formErrors.secret_access_key && <p className="text-red-500 text-sm mt-1">{formErrors.secret_access_key}</p>}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">
                    Region <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={formData.region}
                    onChange={(e) => handleInputChange('region', e.target.value)}
                    className={`w-full bg-dark-800 border ${formErrors.region ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                    placeholder="us-east-1"
                  />
                  {formErrors.region && <p className="text-red-500 text-sm mt-1">{formErrors.region}</p>}
                </div>

                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">
                    Max File Size (MB) <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="number"
                    value={formData.max_file_size_mb}
                    onChange={(e) => handleInputChange('max_file_size_mb', parseInt(e.target.value) || 0)}
                    className={`w-full bg-dark-800 border ${formErrors.max_file_size_mb ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500`}
                    min="1"
                  />
                  {formErrors.max_file_size_mb && <p className="text-red-500 text-sm mt-1">{formErrors.max_file_size_mb}</p>}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Prefix Filter (Optional)
                </label>
                <input
                  type="text"
                  value={formData.prefix_filter}
                  onChange={(e) => handleInputChange('prefix_filter', e.target.value)}
                  className="w-full bg-dark-800 border border-dark-600 rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500"
                  placeholder="uploads/ or documents/"
                />
                <p className="text-dark-400 text-xs mt-1">Only scan objects with this prefix</p>
              </div>

              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.use_ssl}
                    onChange={(e) => handleInputChange('use_ssl', e.target.checked)}
                    className="w-4 h-4 text-gold-500 bg-dark-700 border-dark-600 rounded focus:ring-gold-500"
                  />
                  <span className="text-sm text-dark-300">Use SSL</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.path_style}
                    onChange={(e) => handleInputChange('path_style', e.target.checked)}
                    className="w-4 h-4 text-gold-500 bg-dark-700 border-dark-600 rounded focus:ring-gold-500"
                  />
                  <span className="text-sm text-dark-300">Path Style (for MinIO)</span>
                </label>
              </div>

              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.scan_enabled}
                    onChange={(e) => handleInputChange('scan_enabled', e.target.checked)}
                    className="w-4 h-4 text-gold-500 bg-dark-700 border-dark-600 rounded focus:ring-gold-500"
                  />
                  <span className="text-sm text-dark-300">Scan Enabled</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.yara_enabled}
                    onChange={(e) => handleInputChange('yara_enabled', e.target.checked)}
                    className="w-4 h-4 text-gold-500 bg-dark-700 border-dark-600 rounded focus:ring-gold-500"
                  />
                  <span className="text-sm text-dark-300">YARA Enabled</span>
                </label>
              </div>

              <div className="border-t border-dark-600 pt-4 mt-4">
                <h4 className="text-lg font-semibold text-white mb-3">Schedule Configuration (Optional)</h4>

                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-2">
                    Cron Expression
                  </label>
                  <input
                    type="text"
                    value={formData.schedule}
                    onChange={(e) => handleInputChange('schedule', e.target.value)}
                    className={`w-full bg-dark-800 border ${formErrors.schedule ? 'border-red-500' : 'border-dark-600'} rounded px-3 py-2 text-white font-mono focus:outline-none focus:border-gold-500`}
                    placeholder="0 2 * * * (daily at 2am)"
                  />
                  {formErrors.schedule && <p className="text-red-500 text-sm mt-1">{formErrors.schedule}</p>}
                  <p className="text-dark-400 text-xs mt-1">Format: minute hour day month weekday</p>
                  <p className="text-dark-400 text-xs">Examples: "0 2 * * *" (daily at 2am), "*/30 * * * *" (every 30 min)</p>
                </div>

                <div className="mt-3">
                  <label className="block text-sm font-medium text-dark-300 mb-2">
                    Timezone
                  </label>
                  <select
                    value={formData.schedule_timezone}
                    onChange={(e) => handleInputChange('schedule_timezone', e.target.value)}
                    className="w-full bg-dark-800 border border-dark-600 rounded px-3 py-2 text-white focus:outline-none focus:border-gold-500"
                  >
                    {timezones.map((tz) => (
                      <option key={tz} value={tz}>{tz}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-between pt-4 border-t border-dark-600">
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testingConnection || submitting}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {testingConnection ? (
                    <>
                      <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Testing...
                    </>
                  ) : (
                    <>
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                      </svg>
                      Test Connection
                    </>
                  )}
                </button>

                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={closeModal}
                    disabled={submitting}
                    className="px-4 py-2 text-dark-300 hover:text-white transition-colors disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting || testingConnection}
                    className="bg-gold-500 hover:bg-gold-600 text-dark-900 px-6 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                  >
                    {submitting ? (
                      <>
                        <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        {editingBucket ? 'Updating...' : 'Creating...'}
                      </>
                    ) : (
                      <>{editingBucket ? 'Update' : 'Create'} Bucket</>
                    )}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {showTestModal && testResult && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg max-w-md w-full">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                {testResult.success ? (
                  <svg className="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                ) : (
                  <svg className="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                )}
                <div>
                  <h3 className="text-xl font-bold text-white">
                    {testResult.success ? 'Connection Successful' : 'Connection Failed'}
                  </h3>
                  <p className={`text-sm ${testResult.success ? 'text-green-400' : 'text-red-400'} mt-1`}>
                    {testResult.message}
                  </p>
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  onClick={() => setShowTestModal(false)}
                  className="bg-gold-500 hover:bg-gold-600 text-dark-900 px-6 py-2 rounded-lg font-medium transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showScanConfirmation && scanJobId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg max-w-md w-full">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-12 h-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <h3 className="text-xl font-bold text-white">Scan Started</h3>
                  <p className="text-sm text-green-400 mt-1">
                    Scan job has been queued successfully
                  </p>
                </div>
              </div>
              <div className="bg-dark-700 rounded-lg p-3 mb-4">
                <p className="text-dark-300 text-sm mb-1">Job ID:</p>
                <p className="text-white font-mono text-sm">{scanJobId}</p>
              </div>
              <p className="text-dark-400 text-sm mb-4">
                You can monitor the scan progress in the Scan History tab.
              </p>
              <div className="flex justify-end">
                <button
                  onClick={() => {
                    setShowScanConfirmation(false);
                    setScanJobId(null);
                  }}
                  className="bg-gold-500 hover:bg-gold-600 text-dark-900 px-6 py-2 rounded-lg font-medium transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showDeleteConfirm && bucketToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg max-w-md w-full">
            <div className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <svg className="w-12 h-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <h3 className="text-xl font-bold text-white">Confirm Deletion</h3>
                  <p className="text-sm text-dark-300 mt-1">
                    This action cannot be undone
                  </p>
                </div>
              </div>
              <p className="text-dark-300 mb-4">
                Are you sure you want to delete bucket configuration <span className="font-semibold text-white">"{bucketToDelete.name}"</span>?
              </p>
              <p className="text-dark-400 text-sm mb-4">
                This will only remove the configuration from SkausWatch. The actual S3 bucket and its contents will not be affected.
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={handleDeleteCancel}
                  disabled={deletingBucketId !== null}
                  className="px-4 py-2 text-dark-300 hover:text-white transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteConfirm}
                  disabled={deletingBucketId !== null}
                  className="bg-red-600 hover:bg-red-700 text-white px-6 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {deletingBucketId ? (
                    <>
                      <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Deleting...
                    </>
                  ) : (
                    'Delete'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BucketConfigTab;
