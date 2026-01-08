import { useState } from 'react';
import TabNavigation from '../components/TabNavigation';
import ResearchTab from '../components/research/ResearchTab';
import Card from '../components/Card';

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState('research');

  const tabs = [
    { id: 'iocs', label: 'IOCs' },
    { id: 'feeds', label: 'Feeds' },
    { id: 'statistics', label: 'Statistics' },
    { id: 'research', label: 'Research' },
  ];

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Threat Intelligence</h1>
        <p className="text-dark-400 mt-1">Monitor and research threat indicators</p>
      </div>

      {/* Tab Navigation */}
      <TabNavigation tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'iocs' && (
          <Card title="Indicators of Compromise">
            <p className="text-dark-400">IOC management coming soon...</p>
          </Card>
        )}
        {activeTab === 'feeds' && (
          <Card title="Threat Feeds">
            <p className="text-dark-400">Threat feed management coming soon...</p>
          </Card>
        )}
        {activeTab === 'statistics' && (
          <Card title="Statistics">
            <p className="text-dark-400">Threat intel statistics coming soon...</p>
          </Card>
        )}
        {activeTab === 'research' && <ResearchTab />}
      </div>
    </div>
  );
}
