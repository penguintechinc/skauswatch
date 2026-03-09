import { useState } from 'react';
import TabNavigation from '../components/TabNavigation';
import ReposTab from './darwin/ReposTab';
import ReviewsTab from './darwin/ReviewsTab';
import PlansTab from './darwin/PlansTab';

export default function Darwin() {
  const [activeTab, setActiveTab] = useState('repos');

  const tabs = [
    { id: 'repos', label: 'Repositories' },
    { id: 'reviews', label: 'Code Reviews' },
    { id: 'plans', label: 'Issue Plans' },
  ];

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Darwin AI Review</h1>
        <p className="text-dark-400 mt-1">
          AI-powered code review and issue planning for GitHub and GitLab
        </p>
      </div>

      {/* Tab Navigation */}
      <TabNavigation tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'repos' && <ReposTab />}
        {activeTab === 'reviews' && <ReviewsTab />}
        {activeTab === 'plans' && <PlansTab />}
      </div>
    </div>
  );
}
