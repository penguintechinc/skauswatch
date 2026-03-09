import { useState } from 'react';

interface CollapsibleSectionProps {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

export default function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
}: CollapsibleSectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="mb-4">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3
                   bg-dark-800 border border-dark-700 rounded-lg
                   text-gold-400 hover:bg-dark-700
                   transition-colors duration-200"
      >
        <span className="font-semibold text-sm uppercase tracking-wider">
          {title}
        </span>
        <span
          className={`text-lg transition-transform duration-200 ${
            isOpen ? 'rotate-90' : ''
          }`}
        >
          ›
        </span>
      </button>

      {isOpen && (
        <div className="mt-2 px-4 py-3 bg-dark-800/50 border border-dark-700
                        border-t-0 rounded-b-lg animate-in fade-in duration-200">
          {children}
        </div>
      )}
    </div>
  );
}
