/**
 * Pure helpers for the SVID TTL settings panel — formatting and client-side
 * bound validation, split out from the component so the component module
 * only exports the default component (react-refresh requirement) and so
 * these are independently unit-testable.
 */

export interface FieldValidation {
  error: string | null;
  value: number;
}

/** Formats a whole number of seconds as a compact human string (e.g. "5m", "1h", "90s"). */
export function formatTtl(seconds: number): string {
  if (!Number.isFinite(seconds)) return '—';
  if (seconds > 0 && seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds > 0 && seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Validates a raw TTL input string against the [min, max] second bound. */
export function validateTtlInput(raw: string, min: number, max: number): FieldValidation {
  const trimmed = raw.trim();
  if (trimmed === '') {
    return { error: 'Required', value: NaN };
  }
  const value = Number(trimmed);
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    return { error: 'Must be a whole number of seconds', value: NaN };
  }
  if (value < min || value > max) {
    return {
      error: `Must be between ${formatTtl(min)} and ${formatTtl(max)} (${min}-${max}s)`,
      value,
    };
  }
  return { error: null, value };
}

/** Extracts an axios-style HTTP status code from a caught error, if present. */
export function extractStatus(err: unknown): number | undefined {
  if (typeof err === 'object' && err !== null && 'response' in err) {
    const response = (err as { response?: { status?: number } }).response;
    return response?.status;
  }
  return undefined;
}
