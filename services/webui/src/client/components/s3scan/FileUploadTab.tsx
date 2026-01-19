import React, { useState, useRef, useEffect } from 'react';
import { s3ScanApi } from '../../api/s3scan';

interface UploadedFile {
  id: string;
  filename: string;
  size: number;
  status: 'pending' | 'scanning' | 'clean' | 'infected' | 'pup' | 'error';
  uploadedAt: string;
  md5?: string;
  sha256?: string;
  threats?: string[];
  tiSummary?: string;
}

interface ScanResult {
  scanId: string;
  filename: string;
  size: number;
  status: 'pending' | 'scanning' | 'clean' | 'infected' | 'pup' | 'error';
  md5?: string;
  sha256?: string;
  threats?: string[];
  tiSummary?: string;
  uploadedAt: string;
}

const FileUploadTab: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [uploadHistory, setUploadHistory] = useState<UploadedFile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const itemsPerPage = 10;
  const maxFileSize = 100 * 1024 * 1024; // 100MB

  useEffect(() => {
    loadUploadHistory();
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (currentResult && (currentResult.status === 'pending' || currentResult.status === 'scanning')) {
      pollIntervalRef.current = setInterval(async () => {
        try {
          const result = await s3ScanApi.getScanResult(currentResult.scanId);
          setCurrentResult(result);

          if (result.status !== 'pending' && result.status !== 'scanning') {
            if (pollIntervalRef.current) {
              clearInterval(pollIntervalRef.current);
              pollIntervalRef.current = null;
            }
            setScanning(false);
            loadUploadHistory();
          }
        } catch (err) {
          console.error('Error polling scan result:', err);
        }
      }, 2000);

      return () => {
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current);
        }
      };
    }
  }, [currentResult]);

  const loadUploadHistory = async () => {
    try {
      const history = await s3ScanApi.getUploadHistory();
      setUploadHistory(history);
    } catch (err) {
      console.error('Error loading upload history:', err);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (file: File) => {
    setError(null);

    if (file.size > maxFileSize) {
      setError(`File size exceeds maximum limit of ${formatFileSize(maxFileSize)}`);
      return;
    }

    setSelectedFile(file);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    setScanning(false);
    setError(null);
    setCurrentResult(null);

    try {
      const result = await s3ScanApi.uploadFile(selectedFile);
      setCurrentResult(result);
      setUploading(false);
      setScanning(true);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (err: any) {
      setError(err.message || 'Failed to upload file. Please try again.');
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await s3ScanApi.deleteUpload(id);
      loadUploadHistory();
      if (currentResult?.scanId === id) {
        setCurrentResult(null);
      }
    } catch (err) {
      console.error('Error deleting upload:', err);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
  };

  const handleSubmitToSandbox = async (scanId: string) => {
    try {
      await s3ScanApi.submitToSandbox(scanId);
      alert('File submitted to sandbox for deeper analysis');
    } catch (err: any) {
      alert(err.message || 'Failed to submit to sandbox');
    }
  };

  const handleDownloadReport = async (scanId: string) => {
    try {
      const blob = await s3ScanApi.downloadReport(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-report-${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      alert(err.message || 'Failed to download report');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const getStatusBadge = (status: string, threats?: string[]) => {
    switch (status) {
      case 'clean':
        return <span className="px-3 py-1 rounded-full text-sm font-medium bg-green-900 text-green-300">CLEAN</span>;
      case 'infected':
        return (
          <div className="flex flex-col gap-1">
            <span className="px-3 py-1 rounded-full text-sm font-medium bg-red-900 text-red-300">INFECTED</span>
            {threats && threats.length > 0 && (
              <span className="text-xs text-red-400">{threats.join(', ')}</span>
            )}
          </div>
        );
      case 'pup':
        return (
          <div className="flex flex-col gap-1">
            <span className="px-3 py-1 rounded-full text-sm font-medium bg-orange-900 text-orange-300">PUP</span>
            {threats && threats.length > 0 && (
              <span className="text-xs text-orange-400">{threats.join(', ')}</span>
            )}
          </div>
        );
      case 'scanning':
        return <span className="px-3 py-1 rounded-full text-sm font-medium bg-blue-900 text-blue-300">SCANNING</span>;
      case 'pending':
        return <span className="px-3 py-1 rounded-full text-sm font-medium bg-yellow-900 text-yellow-300">PENDING</span>;
      case 'error':
        return <span className="px-3 py-1 rounded-full text-sm font-medium bg-gray-900 text-gray-300">ERROR</span>;
      default:
        return <span className="px-3 py-1 rounded-full text-sm font-medium bg-gray-900 text-gray-300">{status.toUpperCase()}</span>;
    }
  };

  const paginatedHistory = uploadHistory.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(uploadHistory.length / itemsPerPage);

  return (
    <div className="space-y-6">
      {/* Upload Zone */}
      <div className="bg-dark-800 rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gold-400 mb-4">Quick File Scan</h2>

        <div
          className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
            dragActive
              ? 'border-gold-400 bg-dark-700'
              : 'border-dark-600 bg-dark-900'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={handleFileInputChange}
            accept=".exe,.dll,.pdf,.doc,.docx,.xls,.xlsx,.zip,.rar,.7z,.tar,.gz,.js,.jar,.apk,.elf,.so,.dylib"
          />

          <div className="space-y-4">
            <svg
              className="mx-auto h-16 w-16 text-dark-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
              />
            </svg>

            <div>
              <p className="text-lg text-white mb-2">
                Drag and drop files here or click to browse
              </p>
              <p className="text-sm text-dark-400">
                Max file size: {formatFileSize(maxFileSize)}
              </p>
              <p className="text-xs text-dark-500 mt-2">
                Supported: Executables, PDFs, Office docs, Archives
              </p>
            </div>
          </div>
        </div>

        {selectedFile && (
          <div className="mt-4 p-4 bg-dark-700 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white font-medium">{selectedFile.name}</p>
                <p className="text-sm text-dark-400">{formatFileSize(selectedFile.size)}</p>
              </div>
              <button
                onClick={handleUpload}
                disabled={uploading}
                className="px-6 py-2 bg-gold-500 text-dark-900 rounded-lg hover:bg-gold-400 disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                {uploading ? 'Uploading...' : 'Upload & Scan'}
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-4 bg-red-900 bg-opacity-20 border border-red-800 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}
      </div>

      {/* Upload Progress */}
      {(uploading || scanning) && (
        <div className="bg-dark-800 rounded-lg p-6">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-white font-medium">
                {uploading ? 'Uploading...' : 'Scanning...'}
              </span>
              <span className="text-gold-400">{uploading ? '50%' : '75%'}</span>
            </div>
            <div className="w-full bg-dark-700 rounded-full h-2">
              <div
                className="bg-gold-500 h-2 rounded-full transition-all duration-300"
                style={{ width: uploading ? '50%' : '75%' }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Scan Result */}
      {currentResult && !uploading && (
        <div className="bg-dark-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-gold-400 mb-4">Scan Result</h3>

          <div className="space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-white font-medium">{currentResult.filename}</p>
                <p className="text-sm text-dark-400">{formatFileSize(currentResult.size)}</p>
              </div>
              {getStatusBadge(currentResult.status, currentResult.threats)}
            </div>

            {currentResult.md5 && currentResult.sha256 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between bg-dark-900 p-3 rounded">
                  <div>
                    <p className="text-xs text-dark-400 mb-1">MD5</p>
                    <p className="text-sm text-white font-mono">{currentResult.md5}</p>
                  </div>
                  <button
                    onClick={() => handleCopyHash(currentResult.md5!)}
                    className="px-3 py-1 text-xs bg-dark-700 text-gold-400 rounded hover:bg-dark-600"
                  >
                    Copy
                  </button>
                </div>

                <div className="flex items-center justify-between bg-dark-900 p-3 rounded">
                  <div>
                    <p className="text-xs text-dark-400 mb-1">SHA256</p>
                    <p className="text-sm text-white font-mono break-all">{currentResult.sha256}</p>
                  </div>
                  <button
                    onClick={() => handleCopyHash(currentResult.sha256!)}
                    className="px-3 py-1 text-xs bg-dark-700 text-gold-400 rounded hover:bg-dark-600"
                  >
                    Copy
                  </button>
                </div>
              </div>
            )}

            {currentResult.tiSummary && (
              <div className="bg-dark-900 p-4 rounded">
                <p className="text-xs text-dark-400 mb-2">Threat Intelligence Summary</p>
                <p className="text-sm text-white">{currentResult.tiSummary}</p>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={() => handleSubmitToSandbox(currentResult.scanId)}
                className="px-4 py-2 bg-dark-700 text-gold-400 rounded-lg hover:bg-dark-600 font-medium"
              >
                Submit to Sandbox
              </button>
              <button
                onClick={() => handleDownloadReport(currentResult.scanId)}
                className="px-4 py-2 bg-dark-700 text-white rounded-lg hover:bg-dark-600 font-medium"
              >
                Download Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Upload History */}
      <div className="bg-dark-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gold-400 mb-4">Upload History</h3>

        {uploadHistory.length === 0 ? (
          <p className="text-dark-400 text-center py-8">No uploads yet</p>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-dark-700">
                    <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Filename</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Size</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Status</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-dark-400">Uploaded At</th>
                    <th className="text-right py-3 px-4 text-sm font-medium text-dark-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedHistory.map((item) => (
                    <tr key={item.id} className="border-b border-dark-700 hover:bg-dark-750">
                      <td className="py-3 px-4 text-sm text-white">{item.filename}</td>
                      <td className="py-3 px-4 text-sm text-dark-400">{formatFileSize(item.size)}</td>
                      <td className="py-3 px-4">{getStatusBadge(item.status, item.threats)}</td>
                      <td className="py-3 px-4 text-sm text-dark-400">
                        {new Date(item.uploadedAt).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleDelete(item.id)}
                          className="px-3 py-1 text-xs bg-red-900 text-red-300 rounded hover:bg-red-800"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4">
                <p className="text-sm text-dark-400">
                  Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
                  {Math.min(currentPage * itemsPerPage, uploadHistory.length)} of{' '}
                  {uploadHistory.length} results
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="px-3 py-1 bg-dark-700 text-white rounded hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    className="px-3 py-1 bg-dark-700 text-white rounded hover:bg-dark-600 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default FileUploadTab;
