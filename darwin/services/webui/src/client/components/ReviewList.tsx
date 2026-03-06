import React, { useState, useEffect } from 'react';
import ReviewCard from './ReviewCard';
import { useState as useStateLocal } from 'react';

interface Review {
  id: string;
  prNumber: number;
  repository: string;
  author: string;
  status: 'completed' | 'in_progress' | 'pending' | 'failed';
  createdAt: string;
  summary: string;
  issueCount: number;
}

interface ReviewListProps {
  filter?: 'all' | 'completed' | 'in_progress' | 'pending' | 'failed';
  onSelectReview?: (review: Review) => void;
}

export default function ReviewList({ filter = 'all', onSelectReview }: ReviewListProps) {
  const [reviews, setReviews] = useState<Review[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReviews();
  }, [filter]);

  const fetchReviews = async () => {
    try {
      setLoading(true);
      const endpoint = filter === 'all' ? '/api/v1/reviews' : `/api/v1/reviews?status=${filter}`;
      const response = await fetch(endpoint);
      if (response.ok) {
        const data = await response.json();
        setReviews(data.reviews || []);
      }
    } catch (error) {
      console.error('Failed to fetch reviews:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-4 text-center text-elder-text-light">Loading reviews...</div>;
  }

  if (reviews.length === 0) {
    return <div className="p-4 text-center text-elder-text-light">No reviews found</div>;
  }

  return (
    <div className="space-y-4">
      {reviews.map((review) => (
        <div key={review.id} onClick={() => onSelectReview?.(review)}>
          <ReviewCard review={review} />
        </div>
      ))}
    </div>
  );
}
