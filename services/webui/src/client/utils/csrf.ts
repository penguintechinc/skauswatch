/**
 * Cookie-based CSRF helper (H2 audit fix). The manager backend issues a
 * non-HttpOnly `sw_csrf` cookie alongside the HttpOnly `sw_access`/
 * `sw_refresh` session cookies on login/register/refresh. Every mutating
 * request (POST/PUT/PATCH/DELETE) authenticated via those cookies must echo
 * the `sw_csrf` value back as the `X-CSRF-Token` header; GET/HEAD are exempt.
 */

export const CSRF_COOKIE_NAME = 'sw_csrf';
export const CSRF_HEADER_NAME = 'X-CSRF-Token';

const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete']);

/** Reads a single cookie value by name from `document.cookie`. */
export function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const prefix = `${name}=`;
  const match = document.cookie.split('; ').find((row) => row.startsWith(prefix));
  if (!match) return null;
  return decodeURIComponent(match.slice(prefix.length));
}

/** Current CSRF token value from the JS-readable `sw_csrf` cookie, or null before login. */
export function getCsrfToken(): string | null {
  return getCookie(CSRF_COOKIE_NAME);
}

/** Whether an HTTP method requires a CSRF header (GET/HEAD are exempt). */
export function isMutatingMethod(method?: string): boolean {
  return !!method && MUTATING_METHODS.has(method.toLowerCase());
}
