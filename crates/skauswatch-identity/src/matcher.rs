//! Allowlist for the SPIFFE ID a mTLS peer's certificate must carry.
//!
//! A [`SpiffeIdMatcher`] is deliberately not scoped to a single trust
//! domain: SPIFFE federation means a peer's trust anchor can legitimately
//! live outside `penguintech.io`, so the matcher lets a caller combine
//! rules across any number of trust domains (e.g.
//! `spiffe://penguintech.io/*` and `spiffe://customer.example/*` in the
//! same matcher). Chain-of-trust validation (is the peer's certificate
//! signed by a bundle we hold) is a separate, prior step performed by
//! [`crate::IdentityProvider::server_tls_config`] /
//! [`crate::IdentityProvider::client_tls_config`]; the matcher only decides
//! whether an already-trusted identity is *permitted*.

use spiffe::{SpiffeId, TrustDomain};

/// One allow-rule inside a [`SpiffeIdMatcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// Matches any SPIFFE ID in this trust domain, regardless of path.
    AnyPath(TrustDomain),
    /// Matches SPIFFE IDs in this trust domain whose path starts with a
    /// given `/`-delimited prefix.
    PathPrefix(TrustDomain, String),
    /// Matches exactly one SPIFFE ID.
    Exact(SpiffeId),
}

impl Rule {
    /// Whether `id` satisfies this rule.
    fn matches(&self, id: &SpiffeId) -> bool {
        match self {
            Self::AnyPath(trust_domain) => id.is_member_of(trust_domain),
            Self::PathPrefix(trust_domain, prefix) => {
                id.is_member_of(trust_domain) && path_has_prefix(id.path(), prefix)
            }
            Self::Exact(exact) => id == exact,
        }
    }
}

/// Segment-boundary prefix match: a `/beta` prefix matches `/beta` and
/// `/beta/manager`, but never `/betainator` — matching is on whole
/// `/`-delimited path segments, not a raw byte prefix.
fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// An allowlist of SPIFFE IDs a mTLS peer's certificate may present.
///
/// Built with [`SpiffeIdMatcher::allow_trust_domain`],
/// [`SpiffeIdMatcher::allow_path_prefix`], and
/// [`SpiffeIdMatcher::allow_exact`]; a peer's SPIFFE ID matches if it
/// satisfies *any* configured rule. An empty matcher (the [`Default`])
/// matches nothing, so a mTLS config built with it rejects every peer —
/// there is no implicit "trust everyone in the bundle set" fallback.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpiffeIdMatcher {
    rules: Vec<Rule>,
}

impl SpiffeIdMatcher {
    /// An empty matcher that rejects every peer until rules are added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allows any SPIFFE ID in `trust_domain`, regardless of path.
    ///
    /// This is the mechanism for allowing a whole federated trust domain
    /// (e.g. a customer's own SPIRE deployment) rather than one specific
    /// workload within it — combine calls to admit multiple trust domains
    /// in the same matcher.
    #[must_use]
    pub fn allow_trust_domain(mut self, trust_domain: TrustDomain) -> Self {
        self.rules.push(Rule::AnyPath(trust_domain));
        self
    }

    /// Allows SPIFFE IDs in `trust_domain` whose path starts with `prefix`.
    ///
    /// `prefix` is normalized to start with `/` if the caller omits it, so
    /// both `"beta"` and `"/beta"` behave identically. Matching is on whole
    /// path segments: a `/beta` prefix matches `/beta/manager` but not
    /// `/betainator`.
    #[must_use]
    pub fn allow_path_prefix(
        mut self,
        trust_domain: TrustDomain,
        prefix: impl Into<String>,
    ) -> Self {
        let mut prefix = prefix.into();
        if !prefix.starts_with('/') {
            prefix.insert(0, '/');
        }
        self.rules.push(Rule::PathPrefix(trust_domain, prefix));
        self
    }

    /// Allows exactly this one SPIFFE ID.
    #[must_use]
    pub fn allow_exact(mut self, spiffe_id: SpiffeId) -> Self {
        self.rules.push(Rule::Exact(spiffe_id));
        self
    }

    /// Returns `true` if `id` satisfies at least one configured rule.
    #[must_use]
    pub fn matches(&self, id: &SpiffeId) -> bool {
        self.rules.iter().any(|rule| rule.matches(id))
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // test helpers fail loudly by design, matching skauswatch-auth's convention
mod tests {
    use super::*;

    fn td(name: &str) -> TrustDomain {
        match TrustDomain::new(name) {
            Ok(v) => v,
            Err(e) => panic!("trust domain {name}: {e}"),
        }
    }

    fn id(uri: &str) -> SpiffeId {
        match SpiffeId::new(uri) {
            Ok(v) => v,
            Err(e) => panic!("spiffe id {uri}: {e}"),
        }
    }

    #[test]
    fn empty_matcher_rejects_everything() {
        let matcher = SpiffeIdMatcher::new();
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
    }

    #[test]
    fn allow_trust_domain_matches_any_path_in_domain_only() {
        let matcher = SpiffeIdMatcher::new().allow_trust_domain(td("penguintech.io"));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/worker-vault-sync")));
        assert!(!matcher.matches(&id("spiffe://other.example/beta/manager")));
    }

    #[test]
    fn allow_path_prefix_matches_segment_boundary_only() {
        let matcher = SpiffeIdMatcher::new().allow_path_prefix(td("penguintech.io"), "/beta");
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta")));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(!matcher.matches(&id("spiffe://penguintech.io/betainator")));
        assert!(!matcher.matches(&id("spiffe://penguintech.io/prod/manager")));
    }

    #[test]
    fn allow_path_prefix_normalizes_missing_leading_slash() {
        let matcher = SpiffeIdMatcher::new().allow_path_prefix(td("penguintech.io"), "beta");
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
    }

    #[test]
    fn allow_exact_matches_only_that_id() {
        let matcher =
            SpiffeIdMatcher::new().allow_exact(id("spiffe://penguintech.io/beta/manager"));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/worker")));
    }

    #[test]
    fn matcher_spans_multiple_trust_domains_for_federation() {
        let matcher = SpiffeIdMatcher::new()
            .allow_trust_domain(td("penguintech.io"))
            .allow_trust_domain(td("customer.example"));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(matcher.matches(&id("spiffe://customer.example/agent/x")));
        assert!(!matcher.matches(&id("spiffe://unrelated.example/agent/x")));
    }
}
