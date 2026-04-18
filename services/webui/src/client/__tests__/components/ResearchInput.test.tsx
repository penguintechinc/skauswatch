/**
 * ResearchInput component tests.
 *
 * Tests indicator auto-detection for IPs, domains, hashes,
 * URLs, and emails, plus search submission behavior.
 */
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ResearchInput from '@/components/research/ResearchInput';

describe('ResearchInput', () => {
  const defaultProps = {
    onSearch: vi.fn(),
    isLoading: false,
  };

  it('renders input field and search button', () => {
    render(<ResearchInput {...defaultProps} />);
    expect(
      screen.getByPlaceholderText(/Search IP, domain, hash/i)
    ).toBeInTheDocument();
  });

  describe('indicator auto-detection', () => {
    it('detects IPv4 addresses', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: '192.168.1.1' },
      });
      expect(screen.getByText('IP')).toBeInTheDocument();
    });

    it('detects domain names', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'example.com' },
      });
      expect(screen.getByText('Domain')).toBeInTheDocument();
    });

    it('detects MD5 hashes (32 chars)', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'd41d8cd98f00b204e9800998ecf8427e' },
      });
      expect(screen.getByText('Hash')).toBeInTheDocument();
    });

    it('detects SHA1 hashes (40 chars)', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'da39a3ee5e6b4b0d3255bfef95601890afd80709' },
      });
      expect(screen.getByText('Hash')).toBeInTheDocument();
    });

    it('detects SHA256 hashes (64 chars)', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: {
          value:
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      });
      expect(screen.getByText('Hash')).toBeInTheDocument();
    });

    it('detects URLs', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'https://malicious.example.com/payload' },
      });
      expect(screen.getByText('URL')).toBeInTheDocument();
    });

    it('detects email addresses', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'threat@malware.com' },
      });
      expect(screen.getByText('Email')).toBeInTheDocument();
    });

    it('shows Unknown for unrecognized input', () => {
      render(<ResearchInput {...defaultProps} />);
      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'random search query' },
      });
      expect(screen.getByText('Unknown')).toBeInTheDocument();
    });

    it('does not show badge when input is empty', () => {
      render(<ResearchInput {...defaultProps} />);
      expect(screen.queryByText('Detected:')).not.toBeInTheDocument();
    });
  });

  describe('search behavior', () => {
    it('calls onSearch with query and detected type on button click', () => {
      const onSearch = vi.fn();
      render(<ResearchInput onSearch={onSearch} isLoading={false} />);

      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: '192.168.1.1' },
      });
      fireEvent.click(screen.getByRole('button'));

      expect(onSearch).toHaveBeenCalledWith('192.168.1.1', 'IP');
    });

    it('calls onSearch on Enter key press', () => {
      const onSearch = vi.fn();
      render(<ResearchInput onSearch={onSearch} isLoading={false} />);

      const input = screen.getByPlaceholderText(/Search/);
      fireEvent.change(input, { target: { value: 'example.com' } });
      fireEvent.keyPress(input, { key: 'Enter', charCode: 13 });

      expect(onSearch).toHaveBeenCalledWith('example.com', 'Domain');
    });

    it('passes undefined type for Unknown indicators', () => {
      const onSearch = vi.fn();
      render(<ResearchInput onSearch={onSearch} isLoading={false} />);

      fireEvent.change(screen.getByPlaceholderText(/Search/), {
        target: { value: 'something' },
      });
      fireEvent.click(screen.getByRole('button'));

      expect(onSearch).toHaveBeenCalledWith('something', undefined);
    });

    it('does not call onSearch with empty input', () => {
      const onSearch = vi.fn();
      render(<ResearchInput onSearch={onSearch} isLoading={false} />);

      fireEvent.click(screen.getByRole('button'));
      expect(onSearch).not.toHaveBeenCalled();
    });
  });

  describe('loading state', () => {
    it('disables input when loading', () => {
      render(<ResearchInput onSearch={vi.fn()} isLoading={true} />);
      expect(screen.getByPlaceholderText(/Search/)).toBeDisabled();
    });

    it('disables button when loading', () => {
      render(<ResearchInput onSearch={vi.fn()} isLoading={true} />);
      expect(screen.getByRole('button')).toBeDisabled();
    });
  });
});
