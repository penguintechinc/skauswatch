import api from '../lib/api';
import type {
  AdhocScanResult,
  BucketConfig,
  BucketConfigCreateRequest,
  BucketConfigUpdateRequest,
  ConnectionTestResult,
  IndicatorCreateResponse,
  PaginatedResponse,
  S3ScanStatus,
  ScanJob,
  ScanResult,
  ScanResultsQuery,
  ScanSchedule,
  ScanStatistics,
  TIEnrichment,
} from '../types/s3scan';

// S3 Scan API
export const s3ScanApi = {
  // ============= Bucket Configurations =============

  /**
   * List all bucket configurations with pagination
   */
  listBuckets: async (
    page = 1,
    perPage = 20
  ): Promise<PaginatedResponse<BucketConfig>> => {
    const response = await api.get('/s3scan/buckets', {
      params: { page, per_page: perPage },
    });
    return response.data;
  },

  /**
   * Get a specific bucket configuration
   */
  getBucket: async (id: number): Promise<BucketConfig> => {
    const response = await api.get(`/s3scan/buckets/${id}`);
    return response.data;
  },

  /**
   * Create a new bucket configuration
   */
  createBucket: async (
    data: BucketConfigCreateRequest
  ): Promise<BucketConfig> => {
    const response = await api.post('/s3scan/buckets', data);
    return response.data;
  },

  /**
   * Update an existing bucket configuration
   */
  updateBucket: async (
    id: number,
    data: BucketConfigUpdateRequest
  ): Promise<BucketConfig> => {
    const response = await api.put(`/s3scan/buckets/${id}`, data);
    return response.data;
  },

  /**
   * Delete a bucket configuration
   */
  deleteBucket: async (id: number): Promise<void> => {
    await api.delete(`/s3scan/buckets/${id}`);
  },

  /**
   * Test connection to a bucket
   */
  testConnection: async (id: number): Promise<ConnectionTestResult> => {
    const response = await api.post(`/s3scan/buckets/${id}/test-connection`);
    return response.data;
  },

  // ============= Scan Jobs =============

  /**
   * Trigger a new scan on a bucket
   */
  triggerScan: async (
    bucketId: number,
    prefixFilter?: string,
    forceRescan?: boolean
  ): Promise<ScanJob> => {
    const response = await api.post(
      `/s3scan/buckets/${bucketId}/scan`,
      {
        prefix_filter: prefixFilter,
        force_rescan: forceRescan,
      }
    );
    return response.data;
  },

  /**
   * List scan jobs with optional filtering
   */
  listJobs: async (params?: {
    bucket_config_id?: number;
    status?: string;
    page?: number;
    per_page?: number;
  }): Promise<PaginatedResponse<ScanJob>> => {
    const response = await api.get('/s3scan/jobs', { params });
    return response.data;
  },

  /**
   * Get a specific scan job by ID
   */
  getJob: async (jobId: string): Promise<ScanJob> => {
    const response = await api.get(`/s3scan/jobs/${jobId}`);
    return response.data;
  },

  /**
   * Cancel a running scan job
   */
  cancelJob: async (jobId: string): Promise<void> => {
    await api.post(`/s3scan/jobs/${jobId}/cancel`);
  },

  // ============= Scan Results =============

  /**
   * Query scan results with filters and pagination
   */
  queryResults: async (
    query: ScanResultsQuery
  ): Promise<PaginatedResponse<ScanResult>> => {
    const response = await api.get('/s3scan/results', { params: query });
    return response.data;
  },

  /**
   * Get a specific scan result
   */
  getResult: async (id: number): Promise<ScanResult> => {
    const response = await api.get(`/s3scan/results/${id}`);
    return response.data;
  },

  /**
   * Get scan statistics for a bucket or overall
   */
  getStatistics: async (
    bucketConfigId?: number
  ): Promise<ScanStatistics> => {
    const params = bucketConfigId
      ? { bucket_config_id: bucketConfigId }
      : {};
    const response = await api.get('/s3scan/statistics', { params });
    return response.data;
  },

  // ============= Schedules =============

  /**
   * Get schedule for a bucket
   */
  getSchedule: async (bucketId: number): Promise<ScanSchedule | null> => {
    const response = await api.get(`/s3scan/buckets/${bucketId}/schedule`);
    return response.data;
  },

  /**
   * Set or update a scan schedule for a bucket
   */
  setSchedule: async (
    bucketId: number,
    cronExpression: string,
    timezone?: string,
    enabled?: boolean
  ): Promise<ScanSchedule> => {
    const response = await api.post(
      `/s3scan/buckets/${bucketId}/schedule`,
      {
        cron_expression: cronExpression,
        timezone: timezone || 'UTC',
        enabled: enabled !== undefined ? enabled : true,
      }
    );
    return response.data;
  },

  /**
   * Delete a scan schedule
   */
  deleteSchedule: async (bucketId: number): Promise<void> => {
    await api.delete(`/s3scan/buckets/${bucketId}/schedule`);
  },

  // ============= Ad-hoc File Upload =============

  /**
   * Upload a file for ad-hoc scanning
   */
  uploadFile: async (file: File): Promise<AdhocScanResult> => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await api.post('/s3scan/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  /**
   * Get results of an uploaded file scan
   */
  getUploadResult: async (scanId: string): Promise<AdhocScanResult> => {
    const response = await api.get(`/s3scan/upload/${scanId}`);
    return response.data;
  },

  /**
   * List upload history with pagination
   */
  listUploadHistory: async (
    page?: number,
    perPage?: number
  ): Promise<PaginatedResponse<AdhocScanResult>> => {
    const response = await api.get('/s3scan/upload', {
      params: { page: page || 1, per_page: perPage || 20 },
    });
    return response.data;
  },

  /**
   * Delete an uploaded file scan result
   */
  deleteUpload: async (scanId: string): Promise<void> => {
    await api.delete(`/s3scan/upload/${scanId}`);
  },

  // ============= Threat Intelligence =============

  /**
   * Create a TI indicator from a scan result
   */
  createIndicator: async (
    resultId: number
  ): Promise<IndicatorCreateResponse> => {
    const response = await api.post(`/s3scan/results/${resultId}/create-indicator`);
    return response.data;
  },

  /**
   * Get TI enrichment for a scan result
   */
  getTIEnrichment: async (resultId: number): Promise<TIEnrichment> => {
    const response = await api.get(`/s3scan/results/${resultId}/ti-enrichment`);
    return response.data;
  },

  /**
   * Look up hash value in threat intelligence databases
   */
  lookupHash: async (hashValue: string): Promise<TIEnrichment> => {
    const response = await api.get('/s3scan/ti/lookup-hash', {
      params: { hash: hashValue },
    });
    return response.data;
  },
};
