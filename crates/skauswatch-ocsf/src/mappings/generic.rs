//! Generic webhook/JSON → OCSF field mapping. Task 1.3 implements the
//! pass-through path: generic JSON records are normalized directly by
//! [`crate::normalize`] without pre-mapping (same as v1 behavior). Future
//! tasks may add native OCSF detection and validation here.

use crate::JsonVal;

/// Returns the generic JSON record unchanged — the `normalize` function
/// handles all transformation to OCSF, same as v1's path for generic JSON.
pub fn transform(_record: JsonVal) -> JsonVal {
    _record
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::jsonord::from_slice;

    #[test]
    fn generic_transform_is_identity() {
        let input = from_slice(br#"{"message":"test","level":"info"}"#).unwrap();
        let output = transform(input.clone());
        assert_eq!(input, output);
    }
}
