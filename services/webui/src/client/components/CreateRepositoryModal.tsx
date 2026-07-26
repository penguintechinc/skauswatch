// Stub component for batch 2 - TODO: Implement
import { ReactNode } from 'react';

interface CreateRepositoryModalProps {
  isOpen?: boolean;
  onClose?: () => void;
  onSubmit?: (data: any) => void;
  children?: ReactNode;
}

export default function CreateRepositoryModal({ isOpen, onClose, onSubmit }: CreateRepositoryModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center">
      <div className="bg-slate-800 rounded-lg p-6 max-w-md w-full">
        <h2 className="text-xl font-bold text-amber-400 mb-4">Create Repository</h2>
        <p className="text-slate-400 mb-4">Modal implementation coming soon</p>
        <button
          onClick={onClose}
          className="px-4 py-2 bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
        >
          Close
        </button>
      </div>
    </div>
  );
}
