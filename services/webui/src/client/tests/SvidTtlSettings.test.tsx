import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import SvidTtlSettings from '../components/SvidTtlSettings';
import { svidTtlApi } from '../api/svidTtl';
import { formatTtl } from '../utils/svidTtl';

vi.mock('../api/svidTtl', () => ({
  svidTtlApi: {
    get: vi.fn(),
    update: vi.fn(),
  },
}));

const mockIsSuperAdmin = vi.fn();
vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({
    isSuperAdmin: mockIsSuperAdmin,
  }),
}));

const baseSettings = {
  x509_ttl_seconds: 300,
  jwt_ttl_seconds: 300,
  default_seconds: 300,
  min_seconds: 60,
  max_seconds: 86400,
};

describe('formatTtl', () => {
  it('formats whole hours', () => {
    expect(formatTtl(3600)).toBe('1h');
    expect(formatTtl(7200)).toBe('2h');
  });

  it('formats whole minutes', () => {
    expect(formatTtl(300)).toBe('5m');
    expect(formatTtl(60)).toBe('1m');
  });

  it('formats raw seconds when not a whole minute/hour', () => {
    expect(formatTtl(90)).toBe('90s');
    expect(formatTtl(0)).toBe('0s');
  });

  it('formats non-finite input as an em dash', () => {
    expect(formatTtl(NaN)).toBe('—');
  });
});

describe('SvidTtlSettings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing for non-super-admin roles', () => {
    mockIsSuperAdmin.mockReturnValue(false);
    const { container } = render(<SvidTtlSettings />);
    expect(container).toBeEmptyDOMElement();
    expect(svidTtlApi.get).not.toHaveBeenCalled();
  });

  it('loads and displays current TTL values for super-admin', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);

    render(<SvidTtlSettings />);

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300);
    });
    expect(screen.getByTestId('svid-ttl-jwt-input')).toHaveValue(300);
    expect(screen.getAllByText('Current: 5m')).toHaveLength(2);
    expect(screen.getByTestId('svid-ttl-save-button')).not.toBeDisabled();
  });

  it('shows a load error when the GET request fails', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockRejectedValue(new Error('network down'));

    render(<SvidTtlSettings />);

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-load-error')).toHaveTextContent('network down');
    });
  });

  it('validates the 60-86400s bound client-side and disables save', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.change(screen.getByTestId('svid-ttl-x509-input'), { target: { value: '10' } });

    expect(screen.getByTestId('svid-ttl-x509-error')).toHaveTextContent(
      'Must be between 1m and 24h (60-86400s)'
    );
    expect(screen.getByTestId('svid-ttl-save-button')).toBeDisabled();
  });

  it('rejects a value above the max bound', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-jwt-input')).toHaveValue(300));

    fireEvent.change(screen.getByTestId('svid-ttl-jwt-input'), { target: { value: '999999' } });

    expect(screen.getByTestId('svid-ttl-jwt-error')).toBeInTheDocument();
    expect(screen.getByTestId('svid-ttl-save-button')).toBeDisabled();
  });

  it('rejects a non-integer value', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    // A number input accepts decimals syntactically; our validator rejects
    // non-integer seconds semantically — this exercises that branch
    // (an alpha string like "abc" never reaches onChange on type="number").
    fireEvent.change(screen.getByTestId('svid-ttl-x509-input'), { target: { value: '120.5' } });

    expect(screen.getByTestId('svid-ttl-x509-error')).toHaveTextContent('whole number');
  });

  it('rejects an empty value', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.change(screen.getByTestId('svid-ttl-x509-input'), { target: { value: '' } });

    expect(screen.getByTestId('svid-ttl-x509-error')).toHaveTextContent('Required');
  });

  it('submits the PUT with the correct payload and shows success', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);
    vi.mocked(svidTtlApi.update).mockResolvedValue(undefined);

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.change(screen.getByTestId('svid-ttl-x509-input'), { target: { value: '600' } });
    fireEvent.change(screen.getByTestId('svid-ttl-jwt-input'), { target: { value: '120' } });
    fireEvent.click(screen.getByTestId('svid-ttl-save-button'));

    await waitFor(() => {
      expect(svidTtlApi.update).toHaveBeenCalledWith({
        x509_ttl_seconds: 600,
        jwt_ttl_seconds: 120,
      });
    });
    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-save-success')).toBeInTheDocument();
    });
    // Refetches after a successful save.
    expect(svidTtlApi.get).toHaveBeenCalledTimes(2);
  });

  it('shows a 403-specific error when the backend rejects a non-super-admin PUT', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);
    vi.mocked(svidTtlApi.update).mockRejectedValue({ response: { status: 403 } });

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.click(screen.getByTestId('svid-ttl-save-button'));

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-save-error')).toHaveTextContent(
        'super-admin required'
      );
    });
  });

  it('shows a 400-specific error when the backend rejects an out-of-range PUT', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);
    vi.mocked(svidTtlApi.update).mockRejectedValue({ response: { status: 400 } });

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.click(screen.getByTestId('svid-ttl-save-button'));

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-save-error')).toHaveTextContent('out of range');
    });
  });

  it('shows the Error message for an unrecognized Error failure', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);
    vi.mocked(svidTtlApi.update).mockRejectedValue(new Error('boom'));

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.click(screen.getByTestId('svid-ttl-save-button'));

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-save-error')).toHaveTextContent('boom');
    });
  });

  it('falls back to a generic message for a non-Error, non-HTTP rejection', async () => {
    mockIsSuperAdmin.mockReturnValue(true);
    vi.mocked(svidTtlApi.get).mockResolvedValue(baseSettings);
    vi.mocked(svidTtlApi.update).mockRejectedValue('unexpected rejection');

    render(<SvidTtlSettings />);
    await waitFor(() => expect(screen.getByTestId('svid-ttl-x509-input')).toHaveValue(300));

    fireEvent.click(screen.getByTestId('svid-ttl-save-button'));

    await waitFor(() => {
      expect(screen.getByTestId('svid-ttl-save-error')).toHaveTextContent(
        'Failed to update SVID TTL settings'
      );
    });
  });
});
