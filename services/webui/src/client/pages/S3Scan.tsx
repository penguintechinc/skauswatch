import { useState } from 'react';
import TabNavigation from '../components/TabNavigation';
import BucketConfigTab from '../components/s3scan/BucketConfigTab';
import ScanResultsTab from '../components/s3scan/ScanResultsTab';
import FileUploadTab from '../components/s3scan/FileUploadTab';

export default function S3Scan() {
  const [activeTab, setActiveTab] = useState('buckets');

  const tabs = [
    { id: 'buckets', label: 'Bucket Management' },
    { id: 'results', label: 'Scan Results' },
    { id: 'upload', label: 'File Upload' },
  ];

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">S3 Malware Scanning</h1>
        <p className="text-dark-400 mt-1">
          Scan S3-compatible storage for malware and threats
        </p>
      </div>

      {/* Tab Navigation */}
      <TabNavigation tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'buckets' && <BucketConfigTab />}
        {activeTab === 'results' && <ScanResultsTab />}
        {activeTab === 'upload' && <FileUploadTab />}
      </div>
    </div>
  );
}
