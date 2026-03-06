import React, { useState } from 'react';

interface Comment {
  id: string;
  author: string;
  content: string;
  timestamp: string;
  replies?: Comment[];
}

interface CommentThreadProps {
  issueId: string;
  comments: Comment[];
  onAddComment?: (content: string) => Promise<void>;
  isReadOnly?: boolean;
}

export default function CommentThread({
  issueId,
  comments,
  onAddComment,
  isReadOnly = false,
}: CommentThreadProps) {
  const [replyContent, setReplyContent] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!replyContent.trim() || !onAddComment) return;

    try {
      setSubmitting(true);
      await onAddComment(replyContent);
      setReplyContent('');
    } catch (error) {
      console.error('Failed to add comment:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString();
  };

  const renderComments = (items: Comment[], depth = 0) => {
    return items.map((comment) => (
      <div key={comment.id} className={`mb-4 ${depth > 0 ? 'ml-4' : ''}`}>
        <div className="card p-3">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-sm font-semibold text-gold-400">{comment.author}</p>
              <p className="text-xs text-elder-text-light">{formatTime(comment.timestamp)}</p>
            </div>
          </div>
          <p className="text-sm text-elder-text-base whitespace-pre-wrap">{comment.content}</p>
        </div>
        {comment.replies && comment.replies.length > 0 && (
          <div className="mt-3">{renderComments(comment.replies, depth + 1)}</div>
        )}
      </div>
    ));
  };

  return (
    <div className="space-y-4">
      {comments.length > 0 ? (
        <div>{renderComments(comments)}</div>
      ) : (
        <p className="text-center text-elder-text-light py-4">No comments yet</p>
      )}

      {!isReadOnly && onAddComment && (
        <div className="card p-4">
          <label className="block text-sm font-medium text-gold-400 mb-2">Add Comment</label>
          <textarea
            value={replyContent}
            onChange={(e) => setReplyContent(e.target.value)}
            placeholder="Enter your comment..."
            className="w-full px-3 py-2 rounded bg-elder-bg-darker text-elder-text-base border border-elder-border focus:border-gold-500 focus:outline-none resize-none mb-3"
            rows={4}
            disabled={submitting}
          />
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setReplyContent('')}
              className="px-3 py-1 rounded text-sm bg-elder-bg-darker text-elder-text-base hover:bg-elder-bg-light transition-colors"
              disabled={submitting}
            >
              Clear
            </button>
            <button
              onClick={handleSubmit}
              disabled={!replyContent.trim() || submitting}
              className="px-3 py-1 rounded text-sm bg-gold-600 text-elder-bg-darkest hover:bg-gold-500 disabled:opacity-50 transition-colors"
            >
              {submitting ? 'Posting...' : 'Post'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
