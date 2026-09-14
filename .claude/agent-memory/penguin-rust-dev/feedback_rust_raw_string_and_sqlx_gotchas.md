---
name: feedback-rust-raw-string-and-sqlx-gotchas
description: Three Rust compile-error traps hit building DepGate P3 heuristics/policy/bundle code — raw string embedded quotes, sqlx 0.9 SqlSafeStr, static+LazyLock aggregates
metadata:
  type: feedback
---

Three non-obvious Rust traps, hit in one session building DepGate P3 (`services/depgate/src/heuristics.rs`, `db.rs`):

1. **Raw string literals cannot contain a literal `"` even via `\"`.** `r"...['\"]+..."` silently terminates the raw string at that `"` (backslash is NOT an escape inside `r"..."`), then cascades into dozens of unrelated "unknown start of token"/"prefix X is unknown" parse errors much later in the file — the real bug is invisible from the error locations. Fix: use `r#"..."#` fencing whenever the pattern needs an embedded double-quote (e.g. a regex char class like `[^'"]`).
2. **sqlx 0.9's `SqlSafeStr` trait requires `&'static str`** for `query`/`query_as` — `sqlx::query_as(&format!("SELECT {COLS} FROM ..."))` fails to compile even when the format args are compile-time constants (`const COLS: &str = "..."`). Must inline the literal column list into each query string, or use `QueryBuilder`; the "shared column-list const + format!()" shortcut other services' code doesn't need (they don't format! their SQL) simply doesn't work anymore.
3. **`static` items cannot embed `LazyLock<T>` fields inside an aggregate literal** — `static X: &[SomeStruct(&str, LazyLock<Regex>)] = &[SomeStruct("a", LazyLock::new(...)), ...]` fails with E0492 "interior mutable shared borrows of temporaries". Fix: one top-level `static X: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| vec![("a", regex_or_panic(...)), ...])` instead of a static array of per-entry-LazyLock structs.

**Why:** all three cost real debugging time because the compiler error pointed far from the actual cause (raw string) or gave a plausible-but-wrong fix suggestion (sqlx's error message suggests `AssertSqlSafe` as a bypass, which is the wrong move for injection-audited SQL).

**How to apply:** when writing new regex patterns with embedded quotes, default to `r#"..."#`. When adding any new sqlx query with a shared/formatted column list, inline it as a literal instead. When building a static table of pre-compiled regexes/patterns, use `LazyLock<Vec<_>>`, never a static array of structs each holding their own `LazyLock` field.
