const API_BASE = '/api/v1/s3-scan';

async function handleResponse(response: Response) {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${response.status}`);
  }
  return response;
}

export const s3ScanApi = {
  async uploadFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await handleResponse(
      await fetch(`${API_BASE}/upload`, { method: 'POST', body: formData })
    );
    return res.json();
  },

  async getScanResult(scanId: string) {
    const res = await handleResponse(await fetch(`${API_BASE}/results/${scanId}`));
    return res.json();
  },

  async getUploadHistory() {
    const res = await handleResponse(await fetch(`${API_BASE}/history`));
    return res.json();
  },

  async deleteUpload(id: string) {
    await handleResponse(
      await fetch(`${API_BASE}/uploads/${id}`, { method: 'DELETE' })
    );
  },

  async submitToSandbox(scanId: string) {
    const res = await handleResponse(
      await fetch(`${API_BASE}/sandbox/${scanId}`, { method: 'POST' })
    );
    return res.json();
  },

  async downloadReport(scanId: string) {
    const res = await handleResponse(await fetch(`${API_BASE}/reports/${scanId}`));
    return res.blob();
  },
};
