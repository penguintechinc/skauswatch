import { getCsrfToken, isMutatingMethod, CSRF_HEADER_NAME } from '../utils/csrf';

const API_BASE = '/api/v1/s3-scan';

async function handleResponse(response: Response) {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${response.status}`);
  }
  return response;
}

// Auth is cookie-based (H2 audit fix): the manager sets HttpOnly
// sw_access/sw_refresh cookies, sent automatically via `credentials:
// 'include'`. Mutating requests also echo the JS-readable `sw_csrf` cookie
// back as the X-CSRF-Token header.
function csrfHeaders(method: string): HeadersInit | undefined {
  if (!isMutatingMethod(method)) return undefined;
  const csrfToken = getCsrfToken();
  return csrfToken ? { [CSRF_HEADER_NAME]: csrfToken } : undefined;
}

export const s3ScanApi = {
  async uploadFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await handleResponse(
      await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders('POST'),
        body: formData,
      })
    );
    return res.json();
  },

  async getScanResult(scanId: string) {
    const res = await handleResponse(
      await fetch(`${API_BASE}/results/${scanId}`, { credentials: 'include' })
    );
    return res.json();
  },

  async getUploadHistory() {
    const res = await handleResponse(
      await fetch(`${API_BASE}/history`, { credentials: 'include' })
    );
    return res.json();
  },

  async deleteUpload(id: string) {
    await handleResponse(
      await fetch(`${API_BASE}/uploads/${id}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: csrfHeaders('DELETE'),
      })
    );
  },

  async submitToSandbox(scanId: string) {
    const res = await handleResponse(
      await fetch(`${API_BASE}/sandbox/${scanId}`, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders('POST'),
      })
    );
    return res.json();
  },

  async downloadReport(scanId: string) {
    const res = await handleResponse(
      await fetch(`${API_BASE}/reports/${scanId}`, { credentials: 'include' })
    );
    return res.blob();
  },
};
