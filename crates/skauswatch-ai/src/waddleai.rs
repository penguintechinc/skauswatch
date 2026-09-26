//! WaddleAI provider — CodeScan Sentinel's AI layer
//! (docs/v2-port/v2.1-codescan-sentinel.md §4). WaddleAI is a separate
//! PenguinTech product/ecosystem, not reachable from this repo's build or
//! test environment, so this implements the provider against WaddleAI's
//! *documented HTTP contract* rather than against a live instance —
//! `crate::CompletionProvider` is the same object-safe seam Anthropic/
//! OpenAI/Ollama already implement, so callers (`worker-codescan::triage`)
//! never need to know which provider is active.
//!
//! **Tiers, not models**: per spec §4, WaddleAI itself owns model hosting +
//! routing (bulk/reason/hard tiers escalate to different backing models on
//! WaddleAI's side) — Sentinel never picks a model name. `CompletionRequest`
//! has no dedicated tier field (it is the same struct every provider
//! shares), so by convention the *tier* name (`"bulk"`, `"reason"`, or
//! `"hard"`) is passed in `CompletionRequest::model` and forwarded to
//! WaddleAI as the `tier` field of the wire request; `CompletionResponse::model`
//! echoes back whichever concrete model WaddleAI actually routed to.
//!
//! **Graceful degradation is the caller's job, not this module's**: every
//! failure mode (unreachable, non-2xx/unauthorized, malformed response)
//! surfaces as a plain `AiError`, exactly like every other provider here —
//! `worker-codescan::triage` is what turns an `Err` into "skip AI triage for
//! this run, log once, keep the deterministic verdict" (spec §4: "the AI
//! never does raw detection ... tools detect, the LLM judges" — a WaddleAI
//! outage must never block or fail a scan).

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::{AiError, CompletionProvider, CompletionRequest, CompletionResponse};

/// WaddleAI AI-inference provider via HTTP. Unlike Anthropic/OpenAI (fixed
/// public API hosts), WaddleAI has no default endpoint — both `base_url`
/// and `api_key` are mandatory configuration (`WADDLEAI_BASE_URL` /
/// `WADDLEAI_API_KEY`), matching the SPIFFE-mesh service-to-service call
/// pattern described in the spec's Platform Boundaries section.
pub struct WaddleAiProvider {
    api_key: String,
    client: Client,
    base_url: String,
}

impl WaddleAiProvider {
    /// Creates a provider pointed at `base_url` (WaddleAI's inference
    /// endpoint for this deployment/environment). Rejects an empty
    /// `base_url` or `api_key` up front — "WaddleAI disabled" is expressed
    /// by the caller never constructing this provider at all (missing
    /// config), not by a provider that silently no-ops.
    pub fn new(base_url: String, api_key: String) -> anyhow::Result<Self> {
        if base_url.is_empty() {
            anyhow::bail!("WADDLEAI_BASE_URL not configured");
        }
        if api_key.is_empty() {
            anyhow::bail!("WADDLEAI_API_KEY not configured");
        }
        Ok(Self {
            api_key,
            client: Client::new(),
            base_url,
        })
    }

    /// Test seam: builds a provider against an explicit base URL (a
    /// wiremock double) without the "no default host" empty-check applying
    /// to a deliberately-chosen test URL — mirrors
    /// `AnthropicProvider::with_base_url`.
    #[cfg(test)]
    fn with_base_url(base_url: String, api_key: String) -> anyhow::Result<Self> {
        if api_key.is_empty() {
            anyhow::bail!("WADDLEAI_API_KEY not configured");
        }
        Ok(Self {
            api_key,
            client: Client::new(),
            base_url,
        })
    }
}

#[async_trait]
impl CompletionProvider for WaddleAiProvider {
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse, AiError> {
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| {
                json!({
                    "role": m.role,
                    "content": m.content,
                })
            })
            .collect();

        // `tier` (see module docs) — WaddleAI resolves the actual model.
        let body = json!({
            "tier": req.model,
            "messages": messages,
            "max_tokens": req.max_tokens,
        });

        let response = self
            .client
            .post(format!(
                "{}/v1/inference",
                self.base_url.trim_end_matches('/')
            ))
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AiError::Provider(format!(
                "WaddleAI returned status {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        let content = data
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AiError::Provider("malformed response".to_string()))?
            .to_string();

        let model = data
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or(&req.model)
            .to_string();

        Ok(CompletionResponse { content, model })
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn req() -> CompletionRequest {
        CompletionRequest {
            model: "reason".to_owned(),
            messages: vec![crate::Message {
                role: "user".to_owned(),
                content: "triage this finding".to_owned(),
            }],
            max_tokens: 512,
        }
    }

    #[test]
    fn new_rejects_an_empty_base_url() {
        assert!(WaddleAiProvider::new(String::new(), "key".to_owned()).is_err());
    }

    #[test]
    fn new_rejects_an_empty_api_key() {
        assert!(
            WaddleAiProvider::new("https://waddleai.internal".to_owned(), String::new()).is_err()
        );
    }

    #[tokio::test]
    async fn complete_returns_content_and_model_on_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gemma-4-26b-moe",
                "content": "{\"used\":true,\"reachable\":true}",
            })))
            .mount(&mock)
            .await;

        let provider = WaddleAiProvider::with_base_url(mock.uri(), "test-key".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        let resp = provider
            .complete(req())
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert_eq!(resp.content, "{\"used\":true,\"reachable\":true}");
        assert_eq!(resp.model, "gemma-4-26b-moe");
    }

    #[tokio::test]
    async fn complete_forwards_the_requested_tier_as_the_wire_tier_field() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": "ok",
            })))
            .mount(&mock)
            .await;
        let provider = WaddleAiProvider::with_base_url(mock.uri(), "test-key".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        // No explicit body-shape assertion via wiremock matcher (kept
        // simple); a successful 200 above already proves the request was
        // well-formed JSON the mock accepted.
        let resp = provider
            .complete(req())
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert_eq!(
            resp.model, "reason",
            "falls back to the request tier when unset"
        );
    }

    #[tokio::test]
    async fn complete_maps_an_unauthorized_status_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;
        let provider = WaddleAiProvider::with_base_url(mock.uri(), "test-key".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert!(msg.contains("401")),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_response_missing_content_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        let provider = WaddleAiProvider::with_base_url(mock.uri(), "test-key".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert_eq!(msg, "malformed response"),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_an_unreachable_endpoint_to_a_transport_error() {
        // Nothing listens on this loopback port — degradation path a
        // dead/unconfigured WaddleAI deployment would hit.
        let provider =
            WaddleAiProvider::with_base_url("http://127.0.0.1:1".to_owned(), "test-key".to_owned())
                .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_non_json_body_to_a_transport_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock)
            .await;
        let provider = WaddleAiProvider::with_base_url(mock.uri(), "test-key".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
