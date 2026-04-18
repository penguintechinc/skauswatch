/**
 * S3 Scan API client tests.
 *
 * Tests the s3ScanApi module by mocking the underlying
 * axios instance to verify correct endpoint calls and
 * request parameter formatting.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the api module (axios instance used by hooks/useS3Scan)
const mockApi = {
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
};

vi.mock('@/lib/api', () => ({
  default: mockApi,
}));

// Import after mocking — uses the axios-based client
import { s3ScanApi } from '@/hooks/useS3Scan';

describe('s3ScanApi', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('bucket operations', () => {
    it('listBuckets calls correct endpoint with pagination', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { items: [], total: 0 } });
      await s3ScanApi.listBuckets(2, 10);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/buckets', {
        params: { page: 2, per_page: 10 },
      });
    });

    it('listBuckets uses default pagination', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { items: [], total: 0 } });
      await s3ScanApi.listBuckets();
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/buckets', {
        params: { page: 1, per_page: 20 },
      });
    });

    it('getBucket calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { id: 1, name: 'test' } });
      await s3ScanApi.getBucket(1);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/buckets/1');
    });

    it('createBucket posts data', async () => {
      const data = { name: 'new-bucket', endpoint_url: 'http://minio:9000' };
      mockApi.post.mockResolvedValueOnce({ data: { id: 1, ...data } });
      await s3ScanApi.createBucket(data as any);
      expect(mockApi.post).toHaveBeenCalledWith('/s3scan/buckets', data);
    });

    it('updateBucket puts data', async () => {
      const data = { name: 'updated-bucket' };
      mockApi.put.mockResolvedValueOnce({ data: { id: 1, ...data } });
      await s3ScanApi.updateBucket(1, data as any);
      expect(mockApi.put).toHaveBeenCalledWith('/s3scan/buckets/1', data);
    });

    it('deleteBucket calls correct endpoint', async () => {
      mockApi.delete.mockResolvedValueOnce({});
      await s3ScanApi.deleteBucket(1);
      expect(mockApi.delete).toHaveBeenCalledWith('/s3scan/buckets/1');
    });

    it('testConnection posts to correct endpoint', async () => {
      mockApi.post.mockResolvedValueOnce({
        data: { success: true },
      });
      await s3ScanApi.testConnection(5);
      expect(mockApi.post).toHaveBeenCalledWith(
        '/s3scan/buckets/5/test-connection'
      );
    });
  });

  describe('scan jobs', () => {
    it('triggerScan posts with correct params', async () => {
      mockApi.post.mockResolvedValueOnce({
        data: { id: 'job-1', status: 'pending' },
      });
      await s3ScanApi.triggerScan(1, 'uploads/', true);
      expect(mockApi.post).toHaveBeenCalledWith('/s3scan/buckets/1/scan', {
        prefix_filter: 'uploads/',
        force_rescan: true,
      });
    });

    it('listJobs calls with filter params', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { items: [] } });
      await s3ScanApi.listJobs({ bucket_config_id: 1, status: 'completed' });
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/jobs', {
        params: { bucket_config_id: 1, status: 'completed' },
      });
    });

    it('getJob calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { id: 'job-1' } });
      await s3ScanApi.getJob('job-1');
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/jobs/job-1');
    });

    it('cancelJob posts to correct endpoint', async () => {
      mockApi.post.mockResolvedValueOnce({});
      await s3ScanApi.cancelJob('job-1');
      expect(mockApi.post).toHaveBeenCalledWith('/s3scan/jobs/job-1/cancel');
    });
  });

  describe('scan results', () => {
    it('queryResults passes query params', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { items: [] } });
      const query = { bucket_config_id: 1, status: 'infected' as any };
      await s3ScanApi.queryResults(query);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/results', {
        params: query,
      });
    });

    it('getResult calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { id: 1 } });
      await s3ScanApi.getResult(42);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/results/42');
    });

    it('getStatistics calls with optional bucket_config_id', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { total: 100 } });
      await s3ScanApi.getStatistics(3);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/statistics', {
        params: { bucket_config_id: 3 },
      });
    });

    it('getStatistics calls without params for overall', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { total: 100 } });
      await s3ScanApi.getStatistics();
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/statistics', {
        params: {},
      });
    });
  });

  describe('schedules', () => {
    it('getSchedule calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: null });
      await s3ScanApi.getSchedule(1);
      expect(mockApi.get).toHaveBeenCalledWith(
        '/s3scan/buckets/1/schedule'
      );
    });

    it('setSchedule posts with cron expression', async () => {
      mockApi.post.mockResolvedValueOnce({
        data: { cron_expression: '0 * * * *' },
      });
      await s3ScanApi.setSchedule(1, '0 * * * *', 'US/Eastern', true);
      expect(mockApi.post).toHaveBeenCalledWith(
        '/s3scan/buckets/1/schedule',
        {
          cron_expression: '0 * * * *',
          timezone: 'US/Eastern',
          enabled: true,
        }
      );
    });

    it('deleteSchedule calls correct endpoint', async () => {
      mockApi.delete.mockResolvedValueOnce({});
      await s3ScanApi.deleteSchedule(1);
      expect(mockApi.delete).toHaveBeenCalledWith(
        '/s3scan/buckets/1/schedule'
      );
    });
  });

  describe('file upload', () => {
    it('uploadFile sends FormData', async () => {
      mockApi.post.mockResolvedValueOnce({
        data: { scan_id: 'scan-1' },
      });
      const file = new File(['content'], 'test.exe', {
        type: 'application/octet-stream',
      });
      await s3ScanApi.uploadFile(file);
      expect(mockApi.post).toHaveBeenCalledWith(
        '/s3scan/upload',
        expect.any(FormData),
        { headers: { 'Content-Type': 'multipart/form-data' } }
      );
    });

    it('getUploadResult calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { scan_id: 'scan-1' } });
      await s3ScanApi.getUploadResult('scan-1');
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/upload/scan-1');
    });

    it('listUploadHistory calls with pagination', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { items: [] } });
      await s3ScanApi.listUploadHistory(2, 10);
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/upload', {
        params: { page: 2, per_page: 10 },
      });
    });

    it('deleteUpload calls correct endpoint', async () => {
      mockApi.delete.mockResolvedValueOnce({});
      await s3ScanApi.deleteUpload('scan-1');
      expect(mockApi.delete).toHaveBeenCalledWith('/s3scan/upload/scan-1');
    });
  });

  describe('threat intelligence', () => {
    it('createIndicator posts to correct endpoint', async () => {
      mockApi.post.mockResolvedValueOnce({ data: { indicator_id: 10 } });
      await s3ScanApi.createIndicator(42);
      expect(mockApi.post).toHaveBeenCalledWith(
        '/s3scan/results/42/create-indicator'
      );
    });

    it('getTIEnrichment calls correct endpoint', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { sources: [] } });
      await s3ScanApi.getTIEnrichment(42);
      expect(mockApi.get).toHaveBeenCalledWith(
        '/s3scan/results/42/ti-enrichment'
      );
    });

    it('lookupHash calls with hash param', async () => {
      mockApi.get.mockResolvedValueOnce({ data: { found: false } });
      await s3ScanApi.lookupHash('abc123');
      expect(mockApi.get).toHaveBeenCalledWith('/s3scan/ti/lookup-hash', {
        params: { hash: 'abc123' },
      });
    });
  });
});
