//! Test-only helper shared across unit test modules — this crate's lints
//! deny `clippy::unwrap_used` and warn-as-error (`-D warnings`) on
//! `clippy::expect_used`/`clippy::panic` everywhere, including tests, so
//! every "this must succeed" assertion in test code goes through here
//! instead of `.unwrap()`/`.expect()`.

/// Unwraps a `Result` in test code, panicking with `ctx` and the error on
/// failure. The one sanctioned `panic!` call site for test setup —
/// `#[allow(clippy::panic)]` is scoped to this function only.
#[allow(clippy::panic)]
pub(crate) fn must<T, E: std::fmt::Display>(result: Result<T, E>, ctx: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: {e}"),
    }
}

/// Unwraps the `Err` side of a `Result` in test code, panicking with `ctx`
/// if it was unexpectedly `Ok`.
#[allow(clippy::panic)]
pub(crate) fn must_err<T: std::fmt::Debug, E>(result: Result<T, E>, ctx: &str) -> E {
    match result {
        Err(e) => e,
        Ok(v) => panic!("{ctx}: expected Err, got Ok({v:?})"),
    }
}
