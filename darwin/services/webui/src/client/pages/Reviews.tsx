import { useState, useEffect } from 'react';
import { reviewsApi } from '../api/client';
import type { Review, ReviewStatus } from '../types';
import Card from '../components/Card';
import Button from '../components/Button';

const statusColors: Record<ReviewStatus, string> = {
  pending: 'bg-yellow-900 text-yellow-200',
  approved: 'bg-green-900 text-green-200',
  changes_requested: 'bg-red-900 text-red-200',
  commented: 'bg-blue-900 text-blue-200',
};

export default function Reviews() {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);

  // Filters
  const [statusFilter, setStatusFilter] = useState<ReviewStatus | ''>('');
  const [repoFilter, setRepoFilter] = useState('');
  const [dateFilter, setDateFilter] = useState<'week' | 'month' | 'all'>('month');

  useEffect(() => {
    const fetchReviews = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await reviewsApi.list(page, 20, {
          status: statusFilter || undefined,
          repo: repoFilter || undefined,
        });

        setReviews(result.items);
        setTotalPages(result.pages);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch reviews');
      } finally {
        setIsLoading(false);
      }
    };

    fetchReviews();
  }, [page, statusFilter, repoFilter]);

  const handleStatusFilter = (status: ReviewStatus | '') => {
    setStatusFilter(status);
    setPage(1);
  };

  const handleRepoFilter = (repo: string) => {
    setRepoFilter(repo);
    setPage(1);
  };

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gold-400">Reviews</h1>
        <p className="text-dark-400 mt-1">Manage and track pull request reviews</p>
      </div>

      {/* Filters */}
      <Card title="Filters" className="mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Status Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Status</label>
            <select
              value={statusFilter}
              onChange={(e) => handleStatusFilter(e.target.value as ReviewStatus | '')}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 focus:outline-none focus:border-gold-400"
            >
              <option value="">All Statuses</option>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="changes_requested">Changes Requested</option>
              <option value="commented">Commented</option>
            </select>
          </div>

          {/* Repository Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Repository</label>
            <input
              type="text"
              value={repoFilter}
              onChange={(e) => handleRepoFilter(e.target.value)}
              placeholder="Filter by repo name..."
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
            />
          </div>

          {/* Date Filter */}
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">Date Range</label>
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value as 'week' | 'month' | 'all')}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 focus:outline-none focus:border-gold-400"
            >
              <option value="week">Last Week</option>
              <option value="month">Last Month</option>
              <option value="all">All Time</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Reviews List */}
      {isLoading ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-dark-800 rounded animate-pulse"></div>
          ))}
        </div>
      ) : error ? (
        <Card className="border border-red-900">
          <p className="text-red-400">{error}</p>
        </Card>
      ) : reviews.length === 0 ? (
        <Card>
          <p className="text-dark-400 text-center py-8">No reviews found</p>
        </Card>
      ) : (
        <div className="space-y-4">
          {reviews.map((review) => (
            <Card key={review.id} className="hover:border-gold-500 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <h3 className="text-lg font-semibold text-gold-400">
                      {review.pull_request.title}
                    </h3>
                    <span
                      className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                        statusColors[review.status]
                      }`}
                    >
                      {review.status.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-dark-400">Repository</span>
                      <p className="text-dark-200">{review.pull_request.repository}</p>
                    </div>
                    <div>
                      <span className="text-dark-400">Author</span>
                      <p className="text-dark-200">{review.pull_request.author}</p>
                    </div>
                    <div>
                      <span className="text-dark-400">Reviewer</span>
                      <p className="text-dark-200">{review.reviewer}</p>
                    </div>
                    <div>
                      <span className="text-dark-400">Comments</span>
                      <p className="text-dark-200">{review.comments.length}</p>
                    </div>
                  </div>

                  <p className="text-xs text-dark-400 mt-3">
                    Updated {new Date(review.updated_at).toLocaleDateString()}
                  </p>
                </div>

                <div className="ml-4">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      // Navigate to review detail
                      window.location.href = `/reviews/${review.id}`;
                    }}
                  >
                    View
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-8">
          <Button
            variant="secondary"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            Previous
          </Button>
          <span className="flex items-center px-4 text-dark-300">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="secondary"
            disabled={page === totalPages}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
