//! OpenAI provider implementation.

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::{AiError, CompletionProvider, CompletionRequest, CompletionResponse};

/// OpenAI API provider.
pub struct OpenaiProvider {
    api_key: String,
    client: Client,
    base_url: String,
}

impl OpenaiProvider {
    /// Create a new OpenAI provider with the given API key.
    pub fn new(api_key: String) -> anyhow::Result<Self> {
        Self::with_base_url(api_key, "https://api.openai.com".to_owned())
    }

    /// Builds a provider pointed at an explicit base URL — the real API by
    /// default via [`Self::new`], or a wiremock double in tests, mirroring
    /// `worker-codescan::license_scan::RegistryClient`'s base-URL-override
    /// pattern for the same reason: the wire endpoint is otherwise a literal
    /// with no test seam.
    pub fn with_base_url(api_key: String, base_url: String) -> anyhow::Result<Self> {
        if api_key.is_empty() {
            anyhow::bail!("OPENAI_API_KEY not configured");
        }
        Ok(Self {
            api_key,
            client: Client::new(),
            base_url,
        })
    }
}

#[async_trait]
impl CompletionProvider for OpenaiProvider {
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

        let body = json!({
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        });

        let response = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AiError::Provider(format!(
                "OpenAI returned status {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        let content = data
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|t| t.as_str())
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn req() -> CompletionRequest {
        CompletionRequest {
            model: "gpt-4o".to_owned(),
            messages: vec![crate::Message {
                role: "user".to_owned(),
                content: "hello".to_owned(),
            }],
            max_tokens: 128,
        }
    }

    #[test]
    fn new_rejects_an_empty_api_key() {
        assert!(OpenaiProvider::new(String::new()).is_err());
    }

    #[tokio::test]
    async fn complete_returns_content_and_model_on_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gpt-4o-2024-08-06",
                "choices": [{"message": {"content": "hi there"}}],
            })))
            .mount(&mock)
            .await;

        let provider = OpenaiProvider::with_base_url("sk-test".to_owned(), mock.uri())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        let resp = provider
            .complete(req())
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert_eq!(resp.content, "hi there");
        assert_eq!(resp.model, "gpt-4o-2024-08-06");
    }

    #[tokio::test]
    async fn complete_falls_back_to_the_request_model_when_response_omits_it() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "hi"}}],
            })))
            .mount(&mock)
            .await;

        let provider = OpenaiProvider::with_base_url("sk-test".to_owned(), mock.uri())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        let resp = provider
            .complete(req())
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert_eq!(
            resp.model, "gpt-4o",
            "must fall back to the request's model"
        );
    }

    #[tokio::test]
    async fn complete_maps_a_non_success_status_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let provider = OpenaiProvider::with_base_url("sk-test".to_owned(), mock.uri())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert!(msg.contains("500")),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_response_missing_message_content_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let provider = OpenaiProvider::with_base_url("sk-test".to_owned(), mock.uri())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert_eq!(msg, "malformed response"),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_non_json_body_to_a_transport_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock)
            .await;

        let provider = OpenaiProvider::with_base_url("sk-test".to_owned(), mock.uri())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_an_unreachable_endpoint_to_a_transport_error() {
        // Nothing listens on this loopback port — `.send()` itself fails
        // before a response is ever received.
        let provider =
            OpenaiProvider::with_base_url("sk-test".to_owned(), "http://127.0.0.1:1".to_owned())
                .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
