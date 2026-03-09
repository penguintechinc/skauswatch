import { useState, useEffect } from 'react';
import { analyticsApi } from '../api/client';
import type { ReviewMetrics } from '../types';
import Card from '../components/Card';
import TabNavigation from '../components/TabNavigation';

export default function Analytics() {
  const [metrics, setMetrics] = useState<ReviewMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'activity', label: 'Activity' },
    { id: 'performance', label: 'Performance' },
  ];

  useEffect(() => {
    const fetchMetrics = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await analyticsApi.metrics();
        setMetrics(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
      } finally {
        setIsLoading(false);
      }
    };

    fetchMetrics();
  }, []);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-32 bg-dark-800 rounded animate-pulse"></div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-20 bg-dark-800 rounded animate-pulse"></div>
          ))}
        </div>
      </div>
    );
  }

  if (error || !metrics) {
    return (
      <Card className="border border-red-900">
        <p className="text-red-400">{error || 'Failed to load analytics'}</p>
      </Card>
    );
  }

  const approvalRate = metrics.total_reviews > 0
    ? Math.round((metrics.approved / metrics.total_reviews) * 100)
    : 0;

  const changesRate = metrics.total_reviews > 0
    ? Math.round((metrics.changes_requested / metrics.total_reviews) * 100)
    : 0;

  const criticalPercentage = metrics.total_issues > 0
    ? Math.round((metrics.critical_issues / metrics.total_issues) * 100)
    : 0;

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Analytics</h1>
        <p className="text-dark-400 mt-1">Review metrics and usage statistics</p>
      </div>

      {/* Tab Navigation */}
      <TabNavigation tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'overview' && (
          <>
            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {/* Total Reviews */}
              <Card title="Total Reviews">
                <div className="flex items-end justify-between">
                  <div>
                    <div className="text-3xl font-bold text-gold-400">
                      {metrics.total_reviews}
                    </div>
                    <p className="text-sm text-dark-400 mt-2">All time</p>
                  </div>
                  <div className="text-right">
                    <div className="text-green-400 text-sm font-medium">+12%</div>
                    <p className="text-xs text-dark-400">vs last month</p>
                  </div>
                </div>
              </Card>

              {/* Approved */}
              <Card title="Approved">
                <div className="flex items-end justify-between">
                  <div>
                    <div className="text-3xl font-bold text-green-400">
                      {metrics.approved}
                    </div>
                    <p className="text-sm text-dark-400 mt-2">{approvalRate}%</p>
                  </div>
                  <div className="w-12 h-12 rounded-full bg-green-900 flex items-center justify-center">
                    <span className="text-green-400 text-sm font-bold">
                      {approvalRate}%
                    </span>
                  </div>
                </div>
              </Card>

              {/* Changes Requested */}
              <Card title="Changes Requested">
                <div className="flex items-end justify-between">
                  <div>
                    <div className="text-3xl font-bold text-orange-400">
                      {metrics.changes_requested}
                    </div>
                    <p className="text-sm text-dark-400 mt-2">{changesRate}%</p>
                  </div>
                  <div className="w-12 h-12 rounded-full bg-orange-900 flex items-center justify-center">
                    <span className="text-orange-400 text-sm font-bold">
                      {changesRate}%
                    </span>
                  </div>
                </div>
              </Card>

              {/* Pending */}
              <Card title="Pending Reviews">
                <div className="flex items-end justify-between">
                  <div>
                    <div className="text-3xl font-bold text-yellow-400">
                      {metrics.pending}
                    </div>
                    <p className="text-sm text-dark-400 mt-2">Awaiting action</p>
                  </div>
                  <div className="w-12 h-12 rounded-full bg-yellow-900 flex items-center justify-center">
                    <span className="text-yellow-400 text-sm font-bold">!</span>
                  </div>
                </div>
              </Card>
            </div>

            {/* Issues Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Total Issues */}
              <Card title="Total Issues">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-dark-400">Total</span>
                    <span className="text-2xl font-bold text-gold-400">
                      {metrics.total_issues}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-dark-400">Critical</span>
                    <span className="text-lg font-bold text-red-400">
                      {metrics.critical_issues} ({criticalPercentage}%)
                    </span>
                  </div>
                  <div className="pt-4 border-t border-dark-700">
                    <div className="w-full bg-dark-800 rounded-full h-2">
                      <div
                        className="bg-red-500 h-2 rounded-full"
                        style={{ width: `${criticalPercentage}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              </Card>

              {/* Average Review Time */}
              <Card title="Average Review Time">
                <div className="space-y-4">
                  <div className="text-4xl font-bold text-gold-400">
                    {metrics.avg_review_time}
                  </div>
                  <p className="text-dark-400">Hours</p>
                  <div className="pt-4 border-t border-dark-700">
                    <p className="text-xs text-dark-400">
                      Time from PR creation to review completion
                    </p>
                  </div>
                </div>
              </Card>
            </div>
          </>
        )}

        {activeTab === 'activity' && (
          <Card title="Activity Over Time">
            {metrics.recent_activity && metrics.recent_activity.length > 0 ? (
              <div className="space-y-4">
                {metrics.recent_activity.map((activity, index) => (
                  <div key={index} className="flex items-center gap-4">
                    <div className="w-24 text-sm text-dark-400">
                      {new Date(activity.date).toLocaleDateString()}
                    </div>
                    <div className="flex-1">
                      <div className="w-full bg-dark-800 rounded-full h-2">
                        <div
                          className="bg-gold-400 h-2 rounded-full"
                          style={{
                            width: `${Math.min(
                              (activity.count /
                                Math.max(
                                  ...metrics.recent_activity.map((a) => a.count)
                                )) *
                                100,
                              100
                            )}%`,
                          }}
                        ></div>
                      </div>
                    </div>
                    <div className="w-12 text-right font-bold text-gold-400">
                      {activity.count}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-dark-400">No activity data available</p>
            )}
          </Card>
        )}

        {activeTab === 'performance' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Review Completion Rate */}
            <Card title="Review Completion Rate">
              <div className="space-y-4">
                <div className="text-4xl font-bold text-green-400">
                  {metrics.total_reviews > 0
                    ? Math.round(
                        ((metrics.approved + metrics.changes_requested) /
                          metrics.total_reviews) *
                          100
                      )
                    : 0}
                  %
                </div>
                <p className="text-dark-400">Of reviews have been completed</p>
                <div className="pt-4 border-t border-dark-700">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-dark-400">
                      {metrics.approved + metrics.changes_requested} of{' '}
                      {metrics.total_reviews} reviews
                    </span>
                  </div>
                </div>
              </div>
            </Card>

            {/* Quality Metrics */}
            <Card title="Quality Metrics">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-dark-400">Avg Review Time</span>
                  <span className="text-xl font-bold text-gold-400">
                    {metrics.avg_review_time}h
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-dark-400">Approval Rate</span>
                  <span className="text-xl font-bold text-green-400">
                    {approvalRate}%
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-dark-400">Issues Rate</span>
                  <span className="text-xl font-bold text-orange-400">
                    {changesRate}%
                  </span>
                </div>
                <div className="pt-4 border-t border-dark-700">
                  <p className="text-xs text-dark-400">
                    Based on all reviews and issues in system
                  </p>
                </div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
