//! Order-preserving JSON used to reproduce v1's byte-exact OpenSearch documents.
//!
//! serde_json's default `Value` sorts object keys (its `Map` is a `BTreeMap`);
//! the Python log-receiver (aiohttp `json_response` + opensearch-py's
//! `JSONSerializer`) preserves dict insertion order and never sorts. Turning on
//! serde_json's `preserve_order` feature would flip key ordering globally across
//! the workspace (Cargo unifies features) and silently change the manager's
//! already parity-verified responses. This self-contained value type keeps
//! insertion order, emits compact `(",", ":")` separators, and renders scalars
//! the way Python's `json.dumps(..., ensure_ascii=False)` / `str()` do — all
//! without touching serde_json's feature set.

use std::fmt::Write as _;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A JSON value that preserves object key insertion order.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonVal {
    /// JSON `null`.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON number, held as serde_json's `Number` so int/float rendering matches.
    Num(serde_json::Number),
    /// JSON string.
    Str(String),
    /// JSON array.
    Arr(Vec<JsonVal>),
    /// JSON object; entries stay in insertion order (mirrors Python dict order).
    Obj(Vec<(String, JsonVal)>),
}

impl JsonVal {
    /// Borrows the value for `key` if this is an object containing it (first
    /// match wins, mirroring `dict.get`).
    pub fn get(&self, key: &str) -> Option<&JsonVal> {
        match self {
            JsonVal::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Borrows the inner string when this value is a JSON string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonVal::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Whether this value is a JSON object.
    pub fn is_object(&self) -> bool {
        matches!(self, JsonVal::Obj(_))
    }

    /// Python truthiness of the value: `None`, `False`, `0`, `""`, `[]`, `{}`
    /// are falsy; everything else is truthy.
    pub fn py_truthy(&self) -> bool {
        match self {
            JsonVal::Null => false,
            JsonVal::Bool(b) => *b,
            JsonVal::Num(n) => {
                if let Some(i) = n.as_i64() {
                    i != 0
                } else if let Some(u) = n.as_u64() {
                    u != 0
                } else {
                    n.as_f64().is_some_and(|f| f != 0.0)
                }
            }
            JsonVal::Str(s) => !s.is_empty(),
            JsonVal::Arr(a) => !a.is_empty(),
            JsonVal::Obj(o) => !o.is_empty(),
        }
    }

    /// Python `str(value).lower()` — used by v1 severity/status detection. Only
    /// the string form ever matches a mapping key/substring; other types render
    /// to a value that intentionally matches nothing.
    pub fn py_str_lower(&self) -> String {
        match self {
            JsonVal::Str(s) => s.to_lowercase(),
            JsonVal::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
            JsonVal::Num(n) => n.to_string(),
            JsonVal::Null => "none".to_owned(),
            JsonVal::Arr(_) | JsonVal::Obj(_) => self.py_repr().to_lowercase(),
        }
    }

    /// Python `repr(value)` — reproduces `str(dict)[:500]` for the message
    /// fallback (`str(dict) == repr(dict)`). Strings use Python's quote rules;
    /// `True`/`False`/`None` are capitalized; containers use `, ` / `: `.
    pub fn py_repr(&self) -> String {
        let mut out = String::new();
        self.write_py_repr(&mut out);
        out
    }

    fn write_py_repr(&self, out: &mut String) {
        match self {
            JsonVal::Null => out.push_str("None"),
            JsonVal::Bool(b) => out.push_str(if *b { "True" } else { "False" }),
            JsonVal::Num(n) => out.push_str(&n.to_string()),
            JsonVal::Str(s) => out.push_str(&python_str_repr(s)),
            JsonVal::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    item.write_py_repr(out);
                }
                out.push(']');
            }
            JsonVal::Obj(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&python_str_repr(k));
                    out.push_str(": ");
                    v.write_py_repr(out);
                }
                out.push('}');
            }
        }
    }

    /// Appends the compact JSON encoding (no spaces, insertion order) to `out`,
    /// matching Python `json.dumps(x, separators=(",", ":"), ensure_ascii=False)`
    /// and opensearch-py's serializer.
    pub fn write_compact(&self, out: &mut String) {
        match self {
            JsonVal::Null => out.push_str("null"),
            JsonVal::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonVal::Num(n) => out.push_str(&n.to_string()),
            JsonVal::Str(s) => write_json_string(s, out),
            JsonVal::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_compact(out);
                }
                out.push(']');
            }
            JsonVal::Obj(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_compact(out);
                }
                out.push('}');
            }
        }
    }

    /// Convenience: the full compact JSON encoding as a `String`.
    pub fn to_compact_string(&self) -> String {
        let mut out = String::new();
        self.write_compact(&mut out);
        out
    }
}

/// Writes a JSON string literal using the same escape set as serde_json and
/// Python's `json.dumps` (escapes `"`, `\`, and C0 control chars; leaves `/`
/// and non-ASCII bytes raw — i.e. `ensure_ascii=False`).
fn write_json_string(s: &str, out: &mut String) {
    match serde_json::to_string(s) {
        Ok(encoded) => out.push_str(&encoded),
        // Serializing a `&str` is infallible; keep a lint-clean fallback anyway.
        Err(_) => {
            out.push('"');
            out.push('"');
        }
    }
}

/// Python `repr(str)`: prefers single quotes, switches to double quotes when the
/// string contains a single quote but no double quote, and backslash-escapes the
/// active quote, backslash, and C0/DEL control characters.
fn python_str_repr(s: &str) -> String {
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let quote = if has_single && !has_double { '"' } else { '\'' };

    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

impl<'de> Deserialize<'de> for JsonVal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonValVisitor)
    }
}

/// serde visitor that materializes any self-describing input into [`JsonVal`],
/// preserving object key order as delivered by the parser.
struct JsonValVisitor;

impl<'de> Visitor<'de> for JsonValVisitor {
    type Value = JsonVal;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_unit<E>(self) -> Result<JsonVal, E> {
        Ok(JsonVal::Null)
    }

    fn visit_none<E>(self) -> Result<JsonVal, E> {
        Ok(JsonVal::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<JsonVal, E> {
        Ok(JsonVal::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<JsonVal, E> {
        Ok(JsonVal::Num(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<JsonVal, E> {
        Ok(JsonVal::Num(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<JsonVal, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(JsonVal::Num)
            .ok_or_else(|| E::custom("non-finite float"))
    }

    fn visit_str<E>(self, v: &str) -> Result<JsonVal, E> {
        Ok(JsonVal::Str(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<JsonVal, E> {
        Ok(JsonVal::Str(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonVal, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(JsonVal::Arr(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonVal, A::Error> {
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value()?;
            entries.push((key, value));
        }
        Ok(JsonVal::Obj(entries))
    }
}

/// Parses raw bytes into an order-preserving [`JsonVal`], rejecting trailing
/// data exactly like `serde_json::from_slice`.
///
/// # Errors
/// Returns the serde_json error when the bytes are not valid JSON.
pub fn from_slice(bytes: &[u8]) -> Result<JsonVal, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Truncates to the first `n` Unicode scalar values, matching Python `s[:n]`.
pub fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(s: &str) -> JsonVal {
        from_slice(s.as_bytes()).unwrap()
    }

    #[test]
    fn object_key_order_is_preserved() {
        let v = parse(r#"{"src_ip":"10.0.0.1","dst_port":443,"level":"warning"}"#);
        assert_eq!(
            v.to_compact_string(),
            r#"{"src_ip":"10.0.0.1","dst_port":443,"level":"warning"}"#
        );
    }

    #[test]
    fn compact_output_drops_input_whitespace() {
        let v = parse(r#"{ "a" : 1 , "b" : [ 1 , 2 ] }"#);
        assert_eq!(v.to_compact_string(), r#"{"a":1,"b":[1,2]}"#);
    }

    #[test]
    fn int_and_float_render_like_python_json() {
        assert_eq!(parse("1705312200").to_compact_string(), "1705312200");
        assert_eq!(parse("1705312200.5").to_compact_string(), "1705312200.5");
        assert_eq!(parse("1705312200.0").to_compact_string(), "1705312200.0");
        assert_eq!(parse("0.1").to_compact_string(), "0.1");
    }

    #[test]
    fn forward_slash_and_unicode_are_not_escaped() {
        let v = parse(r#"{"p":"/etc/passwd","u":"café"}"#);
        assert_eq!(v.to_compact_string(), r#"{"p":"/etc/passwd","u":"café"}"#);
    }

    #[test]
    fn py_truthy_matches_python() {
        assert!(!parse("null").py_truthy());
        assert!(!parse("false").py_truthy());
        assert!(parse("true").py_truthy());
        assert!(!parse("0").py_truthy());
        assert!(parse("3").py_truthy());
        assert!(!parse(r#""""#).py_truthy());
        assert!(parse(r#""x""#).py_truthy());
        assert!(!parse("[]").py_truthy());
        assert!(!parse("{}").py_truthy());
    }

    #[test]
    fn py_str_lower_lowercases_strings_and_ignores_others() {
        assert_eq!(parse(r#""HIGH""#).py_str_lower(), "high");
        assert_eq!(parse("3").py_str_lower(), "3");
        assert_eq!(parse("true").py_str_lower(), "true");
    }

    #[test]
    fn py_repr_matches_python_str_dict() {
        // Captured from Python str(dict) — see tests/fixtures/pyrepr_cases.json.
        let r4 = parse(r#"{"endpoint":"/api/v1/users","method":"GET","time":1705312200}"#);
        assert_eq!(
            r4.py_repr(),
            "{'endpoint': '/api/v1/users', 'method': 'GET', 'time': 1705312200}"
        );

        let nested = parse(r#"{"a":1,"b":[1,2,{"c":true}],"d":null,"e":"x'y"}"#);
        assert_eq!(
            nested.py_repr(),
            r#"{'a': 1, 'b': [1, 2, {'c': True}], 'd': None, 'e': "x'y"}"#
        );

        let floaty = parse(r#"{"n":1705312200.0,"m":0.1}"#);
        assert_eq!(floaty.py_repr(), "{'n': 1705312200.0, 'm': 0.1}");
    }

    #[test]
    fn python_str_repr_switches_quotes_like_cpython() {
        assert_eq!(python_str_repr("plain"), "'plain'");
        assert_eq!(python_str_repr("x'y"), "\"x'y\""); // single present, no double
        assert_eq!(python_str_repr("a\"b"), "'a\"b'"); // double present
        assert_eq!(python_str_repr("a'\"b"), "'a\\'\"b'"); // both → single, escape '
        assert_eq!(python_str_repr("tab\tend"), "'tab\\tend'");
    }

    #[test]
    fn truncate_counts_code_points() {
        assert_eq!(truncate_chars("abcdef", 3), "abc");
        assert_eq!(truncate_chars("abc", 10), "abc");
    }
}
