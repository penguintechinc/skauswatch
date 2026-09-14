//! Serde adapter for `Option<chrono::DateTime<chrono::Utc>>` fields decoded
//! from this service's Postgres `TIMESTAMPTZ` columns.
//!
//! Every timestamp column in `migrations/0001_codescan_schema.sql` is
//! `TIMESTAMPTZ`. sqlx maps `chrono::NaiveDateTime` to the SQL `TIMESTAMP`
//! type ([`Type<Postgres>::type_info`] returns `PgTypeInfo::TIMESTAMP`) —
//! binding a `NaiveDateTime` into a `TIMESTAMPTZ` column succeeds silently
//! (Postgres has an implicit `timestamp -> timestamptz` assignment cast),
//! but *decoding* a `TIMESTAMPTZ` column's value back into a `NaiveDateTime`
//! fails at runtime with a `mismatched types` `sqlx::Error` — there is no
//! equivalent implicit cast on the client decode path, and sqlx's own
//! `Type::compatible` guard rejects it before `Decode::decode` ever runs.
//! Every `#[derive(sqlx::FromRow)]` struct field bound to a `TIMESTAMPTZ`
//! column must therefore use `DateTime<Utc>`, not `NaiveDateTime` — this
//! was undetected before real-Postgres handler tests existed (`for_tests`
//! previously only ever used a lazy, unconnected pool).
//!
//! Renders identically to `skauswatch_streams::serde_py_isoformat_opt`
//! (Python `datetime.isoformat()` parity, six-zero-padded microseconds or
//! no fraction at all) by delegating to the same
//! [`skauswatch_streams::py_isoformat`] after dropping to naive UTC —
//! `DateTime<Utc>` and `NaiveDateTime` carry the same wall-clock value here
//! since Postgres stores `TIMESTAMPTZ` internally as UTC.

use chrono::{DateTime, Utc};

/// Serde `serialize_with` adapter for `Option<DateTime<Utc>>` struct fields.
pub fn serde_py_isoformat_opt<S: serde::Serializer>(
    t: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match t {
        Some(v) => serializer.serialize_str(&skauswatch_streams::py_isoformat(v.naive_utc())),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Row {
        #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
        at: Option<DateTime<Utc>>,
    }

    #[test]
    fn some_renders_python_isoformat() {
        let dt = match DateTime::parse_from_rfc3339("2026-07-22T10:03:07.123456Z") {
            Ok(d) => d.with_timezone(&Utc),
            Err(e) => panic!("parse: {e}"),
        };
        let value = match serde_json::to_value(Row { at: Some(dt) }) {
            Ok(v) => v,
            Err(e) => panic!("serialize: {e}"),
        };
        assert_eq!(
            value,
            serde_json::json!({"at": "2026-07-22T10:03:07.123456"})
        );
    }

    #[test]
    fn none_renders_null() {
        let value = match serde_json::to_value(Row { at: None }) {
            Ok(v) => v,
            Err(e) => panic!("serialize: {e}"),
        };
        assert_eq!(value, serde_json::json!({"at": null}));
    }
}
