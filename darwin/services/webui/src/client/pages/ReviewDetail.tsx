import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { reviewsApi } from '../api/client';
import type { Review, ReviewComment } from '../types';
import Card from '../components/Card';
import Button from '../components/Button';

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-900 text-yellow-200',
  approved: 'bg-green-900 text-green-200',
  changes_requested: 'bg-red-900 text-red-200',
  commented: 'bg-blue-900 text-blue-200',
};

export default function ReviewDetail() {
  const { id } = useParams<{ id: string }>();
  const [review, setReview] = useState<Review | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [commentText, setCommentText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    const fetchReview = async () => {
      if (!id) return;
      setIsLoading(true);
      setError(null);
      try {
        const data = await reviewsApi.get(parseInt(id, 10));
        setReview(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch review');
      } finally {
        setIsLoading(false);
      }
    };

    fetchReview();
  }, [id]);

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!review || !commentText.trim()) return;

    setIsSubmitting(true);
    try {
      const newComment = await reviewsApi.addComment(review.id, {
        content: commentText,
      });

      setReview({
        ...review,
        comments: [...review.comments, newComment],
      });
      setCommentText('');
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to add comment');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-32 bg-dark-800 rounded animate-pulse"></div>
        <div className="h-64 bg-dark-800 rounded animate-pulse"></div>
      </div>
    );
  }

  if (error || !review) {
    return (
      <Card className="border border-red-900">
        <p className="text-red-400">{error || 'Review not found'}</p>
      </Card>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gold-400">
            {review.pull_request.title}
          </h1>
          <p className="text-dark-400 mt-1">PR #{review.pull_request.number}</p>
        </div>
        <span
          className={`inline-block px-3 py-1 rounded text-sm font-medium ${
            statusColors[review.status]
          }`}
        >
          {review.status.replace('_', ' ')}
        </span>
      </div>

      {/* PR Details */}
      <Card title="Pull Request Details" className="mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h3 className="text-sm font-medium text-dark-300 mb-2">Description</h3>
            <p className="text-dark-200">{review.pull_request.description}</p>
          </div>

          <div className="space-y-4">
            <div>
              <span className="text-sm text-dark-400">Repository</span>
              <p className="text-dark-200">{review.pull_request.repository}</p>
            </div>
            <div>
              <span className="text-sm text-dark-400">Author</span>
              <p className="text-dark-200">{review.pull_request.author}</p>
            </div>
            <div>
              <span className="text-sm text-dark-400">Status</span>
              <p className="text-dark-200">{review.pull_request.status}</p>
            </div>
            <div>
              <span className="text-sm text-dark-400">Created</span>
              <p className="text-dark-200">
                {new Date(review.pull_request.created_at).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>

        <div className="mt-6 pt-6 border-t border-dark-700">
          <a
            href={review.pull_request.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-gold-400 hover:text-gold-300"
          >
            View on GitHub
            <span className="text-sm">→</span>
          </a>
        </div>
      </Card>

      {/* Review Info */}
      <Card title="Review Information" className="mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <span className="text-sm text-dark-400">Reviewer</span>
            <p className="text-dark-200">{review.reviewer}</p>
          </div>
          <div>
            <span className="text-sm text-dark-400">Status</span>
            <p>
              <span
                className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                  statusColors[review.status]
                }`}
              >
                {review.status.replace('_', ' ')}
              </span>
            </p>
          </div>
          <div>
            <span className="text-sm text-dark-400">Total Comments</span>
            <p className="text-dark-200">{review.comments.length}</p>
          </div>
        </div>
      </Card>

      {/* Comments Section */}
      <Card title={`Comments (${review.comments.length})`} className="mb-6">
        {review.comments.length === 0 ? (
          <p className="text-dark-400 py-4">No comments yet</p>
        ) : (
          <div className="space-y-4">
            {review.comments.map((comment) => (
              <div key={comment.id} className="pb-4 border-b border-dark-700 last:border-0">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <p className="font-medium text-dark-200">{comment.author}</p>
                    {comment.file && (
                      <p className="text-xs text-dark-400">
                        {comment.file}
                        {comment.line && `:${comment.line}`}
                      </p>
                    )}
                  </div>
                  <span className="text-xs text-dark-400">
                    {new Date(comment.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-dark-300">{comment.content}</p>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Add Comment Form */}
      <Card title="Add Comment" className="mb-6">
        <form onSubmit={handleAddComment} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-2">
              Your Comment
            </label>
            <textarea
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Enter your comment..."
              rows={4}
              className="w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded text-dark-100 placeholder-dark-500 focus:outline-none focus:border-gold-400"
            />
          </div>

          <div className="flex gap-2">
            <Button
              type="submit"
              disabled={isSubmitting || !commentText.trim()}
            >
              {isSubmitting ? 'Posting...' : 'Post Comment'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => window.history.back()}
            >
              Back
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
