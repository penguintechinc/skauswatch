//! HttpOnly session cookies + the `sw_csrf` double-submit token (H2 audit
//! fix: storing the JWT in webui `localStorage` means an XSS bug is a full
//! account takeover — the token must never be reachable from JS). Bearer
//! clients (CLI, mobile, the golden parity harness) are entirely unaffected:
//! every handler here keeps returning the unchanged response-body token
//! alongside these cookies, never instead of it.
//!
//! Cookie contract (matched byte-for-byte by the webui frontend agent):
//!
//! | Cookie      | HttpOnly | SameSite | Path             |
//! |-------------|----------|----------|------------------|
//! | `sw_access`  | yes      | Lax      | `/`              |
//! | `sw_refresh` | yes      | Strict   | `/api/v1/auth`   |
//! | `sw_csrf`    | no       | Lax      | `/`              |
//!
//! All three are always `Secure` — this workspace enforces TLS 1.2+ on
//! every external endpoint (`security.md`), so there is no local-http dev
//! exception to carve out here.

use axum::http::{HeaderMap, HeaderValue, header::SET_COOKIE};
use cookie::{Cookie, SameSite};
use rand_core::{OsRng, RngCore};

use crate::error::ApiError;

/// Name of the HttpOnly access-token cookie.
pub(crate) const ACCESS_COOKIE: &str = "sw_access";
/// Name of the HttpOnly refresh-token cookie.
pub(crate) const REFRESH_COOKIE: &str = "sw_refresh";
/// Name of the non-HttpOnly CSRF double-submit cookie — the frontend must
/// be able to read this one to echo it back in `X-CSRF-Token`.
pub(crate) const CSRF_COOKIE: &str = "sw_csrf";
/// `sw_refresh` is scoped to the refresh route only — no reason for it to
/// travel on every request the way `sw_access` does.
const REFRESH_COOKIE_PATH: &str = "/api/v1/auth";
/// Double-submit header the frontend must echo the `sw_csrf` cookie value
/// into on every cookie-authenticated mutating request. Matched
/// case-insensitively by `HeaderMap::get` regardless of the literal casing
/// used here.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

/// Generates a fresh CSRF token from the OS CSPRNG: 32 random bytes (256
/// bits of entropy) hex-encoded. `rand_core::OsRng` — not the `uuid` crate's
/// v4 generator already used elsewhere in this module — because the task
/// contract calls for an explicit CSPRNG for this specific value; `OsRng`
/// is already a pinned workspace dependency (`crates/skauswatch-auth`'s
/// dev-key generation), so this adds no new supply-chain surface.
pub(crate) fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write as _;
        // `write!` into a `String` is infallible — documented invariant,
        // not a suppressed error.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Builds one `Set-Cookie` header value. `Secure` is unconditional (see
/// module docs); the caller controls `http_only`/`same_site`/`path`/
/// lifetime per the cookie contract table above.
fn build_cookie(
    name: &str,
    value: &str,
    path: &str,
    max_age_secs: i64,
    http_only: bool,
    same_site: SameSite,
) -> Result<HeaderValue, ApiError> {
    let rendered = Cookie::build((name.to_owned(), value.to_owned()))
        .path(path.to_owned())
        .max_age(cookie::time::Duration::seconds(max_age_secs))
        .secure(true)
        .http_only(http_only)
        .same_site(same_site)
        .build()
        .to_string();
    HeaderValue::from_str(&rendered).map_err(|e| ApiError::internal("build set-cookie header", e))
}

/// The three `Set-Cookie` headers issued on a successful login/refresh:
/// `sw_access` + `sw_refresh` (HttpOnly) and `sw_csrf` (not HttpOnly — see
/// module docs). Ages both token cookies to match the JWTs they carry, and
/// the CSRF cookie to the (shorter-lived) access token's lifetime, since a
/// fresh CSRF token is minted every time `sw_access` is.
pub(crate) fn auth_cookies(
    access_token: &str,
    refresh_token: &str,
    csrf_token: &str,
    access_max_age_secs: i64,
    refresh_max_age_secs: i64,
) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.append(
        SET_COOKIE,
        build_cookie(
            ACCESS_COOKIE,
            access_token,
            "/",
            access_max_age_secs,
            true,
            SameSite::Lax,
        )?,
    );
    headers.append(
        SET_COOKIE,
        build_cookie(
            REFRESH_COOKIE,
            refresh_token,
            REFRESH_COOKIE_PATH,
            refresh_max_age_secs,
            true,
            SameSite::Strict,
        )?,
    );
    headers.append(
        SET_COOKIE,
        build_cookie(
            CSRF_COOKIE,
            csrf_token,
            "/",
            access_max_age_secs,
            false,
            SameSite::Lax,
        )?,
    );
    Ok(headers)
}

/// Expires all three cookies on logout — same name/path/attributes used at
/// set-time (browsers key cookie deletion on name+path+domain; a mismatched
/// path would silently fail to clear it).
pub(crate) fn clear_auth_cookies() -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    headers.append(
        SET_COOKIE,
        build_cookie(ACCESS_COOKIE, "", "/", 0, true, SameSite::Lax)?,
    );
    headers.append(
        SET_COOKIE,
        build_cookie(
            REFRESH_COOKIE,
            "",
            REFRESH_COOKIE_PATH,
            0,
            true,
            SameSite::Strict,
        )?,
    );
    headers.append(
        SET_COOKIE,
        build_cookie(CSRF_COOKIE, "", "/", 0, false, SameSite::Lax)?,
    );
    Ok(headers)
}

/// Reads a single cookie's value out of the request's `Cookie` header(s).
/// A real browser always sends exactly one `Cookie` header with all pairs
/// semicolon-joined, but scans every occurrence via `get_all` rather than
/// `get` regardless — some test harnesses (`axum-test`'s `add_cookie`) and
/// intermediary proxies emit one `Cookie:` header per cookie instead of
/// joining them, and `get` alone would silently see only the first.
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .find_map(|part| {
            let (k, v) = part.trim().split_once('=')?;
            (k == name).then(|| v.to_owned())
        })
}

/// Constant-time byte comparison — avoids a timing oracle on the CSRF
/// token compare, same rationale as the login-timing-equalizer in
/// `routes/auth.rs` (finding #8).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Whether `method` is a CSRF-relevant mutation. Safe methods (GET/HEAD/
/// OPTIONS) are exempt per the double-submit contract.
pub(crate) fn is_mutating(method: &axum::http::Method) -> bool {
    matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    )
}

/// Double-submit CSRF validation: the `X-CSRF-Token` header must be present
/// and equal the `sw_csrf` cookie value. Only called for requests that
/// authenticated via the `sw_access` cookie — a `Bearer` header bypasses
/// this entirely (see `crate::auth::CurrentUser`'s docs: browsers never
/// auto-attach `Authorization`, so it isn't a CSRF vector).
pub(crate) fn verify_csrf(headers: &HeaderMap) -> Result<(), ApiError> {
    let header_token = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok());
    let cookie_token = cookie_value(headers, CSRF_COOKIE);
    let valid = matches!(
        (header_token, cookie_token),
        (Some(h), Some(c)) if !h.is_empty() && ct_eq(h.as_bytes(), c.as_bytes())
    );
    if valid {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "CSRF token missing or invalid".to_owned(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderMap as HttpHeaderMap;

    fn headers_with(cookie: Option<&str>, csrf_header: Option<&str>) -> HttpHeaderMap {
        let mut h = HttpHeaderMap::new();
        if let Some(c) = cookie {
            h.insert(
                axum::http::header::COOKIE,
                HeaderValue::from_str(c).unwrap_or_else(|e| panic!("cookie header: {e}")),
            );
        }
        if let Some(x) = csrf_header {
            h.insert(
                CSRF_HEADER,
                HeaderValue::from_str(x).unwrap_or_else(|e| panic!("csrf header: {e}")),
            );
        }
        h
    }

    #[test]
    fn generate_csrf_token_has_sufficient_entropy_and_is_hex() {
        let a = generate_csrf_token();
        let b = generate_csrf_token();
        assert_eq!(a.len(), 64); // 32 bytes hex-encoded
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two draws from a CSPRNG must not collide");
    }

    #[test]
    fn auth_cookies_sets_expected_attributes_per_cookie() {
        let headers = match auth_cookies("access-tok", "refresh-tok", "csrf-tok", 1800, 604_800) {
            Ok(h) => h,
            Err(e) => panic!("auth_cookies: {e:?}"),
        };
        let rendered: Vec<String> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(rendered.len(), 3);

        let access = rendered
            .iter()
            .find(|c| c.starts_with("sw_access="))
            .unwrap_or_else(|| panic!("missing sw_access cookie in {rendered:?}"));
        assert!(access.contains("HttpOnly"));
        assert!(access.contains("Secure"));
        assert!(access.contains("SameSite=Lax"));
        assert!(access.contains("Path=/;") || access.ends_with("Path=/"));

        let refresh = rendered
            .iter()
            .find(|c| c.starts_with("sw_refresh="))
            .unwrap_or_else(|| panic!("missing sw_refresh cookie in {rendered:?}"));
        assert!(refresh.contains("HttpOnly"));
        assert!(refresh.contains("Secure"));
        assert!(refresh.contains("SameSite=Strict"));
        assert!(refresh.contains("Path=/api/v1/auth"));

        let csrf = rendered
            .iter()
            .find(|c| c.starts_with("sw_csrf="))
            .unwrap_or_else(|| panic!("missing sw_csrf cookie in {rendered:?}"));
        assert!(!csrf.contains("HttpOnly"), "sw_csrf must be JS-readable");
        assert!(csrf.contains("Secure"));
        assert!(csrf.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_auth_cookies_zeroes_max_age_on_all_three() {
        let headers = match clear_auth_cookies() {
            Ok(h) => h,
            Err(e) => panic!("clear_auth_cookies: {e:?}"),
        };
        let rendered: Vec<String> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(rendered.len(), 3);
        for c in &rendered {
            assert!(c.contains("Max-Age=0"), "expected Max-Age=0 in {c}");
        }
    }

    #[test]
    fn cookie_value_parses_a_multi_cookie_header() {
        let headers = headers_with(Some("sw_access=tok1; sw_csrf=tok2"), None);
        assert_eq!(
            cookie_value(&headers, ACCESS_COOKIE),
            Some("tok1".to_owned())
        );
        assert_eq!(cookie_value(&headers, CSRF_COOKIE), Some("tok2".to_owned()));
        assert_eq!(cookie_value(&headers, REFRESH_COOKIE), None);
    }

    /// Regression: some HTTP clients/test harnesses (`axum-test`'s
    /// `add_cookie`, called once per cookie) emit one `Cookie:` header per
    /// cookie rather than a single semicolon-joined header. `HeaderMap::get`
    /// only sees the first occurrence and previously made every cookie but
    /// the first invisible to this function — must use `get_all`.
    #[test]
    fn cookie_value_finds_a_cookie_in_any_of_several_separate_cookie_headers() {
        let mut headers = HttpHeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("sw_csrf=first-header-value"),
        );
        headers.append(
            axum::http::header::COOKIE,
            HeaderValue::from_static("sw_access=second-header-value"),
        );
        assert_eq!(
            cookie_value(&headers, ACCESS_COOKIE),
            Some("second-header-value".to_owned())
        );
        assert_eq!(
            cookie_value(&headers, CSRF_COOKIE),
            Some("first-header-value".to_owned())
        );
    }

    #[test]
    fn verify_csrf_requires_matching_header_and_cookie() {
        let matching = headers_with(Some("sw_csrf=same-token"), Some("same-token"));
        assert!(verify_csrf(&matching).is_ok());

        let mismatched = headers_with(Some("sw_csrf=one"), Some("other"));
        assert!(verify_csrf(&mismatched).is_err());

        let missing_header = headers_with(Some("sw_csrf=one"), None);
        assert!(verify_csrf(&missing_header).is_err());

        let missing_cookie = headers_with(None, Some("one"));
        assert!(verify_csrf(&missing_cookie).is_err());
    }

    #[test]
    fn is_mutating_matches_write_verbs_only() {
        assert!(is_mutating(&axum::http::Method::POST));
        assert!(is_mutating(&axum::http::Method::PUT));
        assert!(is_mutating(&axum::http::Method::PATCH));
        assert!(is_mutating(&axum::http::Method::DELETE));
        assert!(!is_mutating(&axum::http::Method::GET));
        assert!(!is_mutating(&axum::http::Method::HEAD));
        assert!(!is_mutating(&axum::http::Method::OPTIONS));
    }
}
