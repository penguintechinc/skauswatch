//! Ollama provider implementation.

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::{AiError, CompletionProvider, CompletionRequest, CompletionResponse};

/// Self-hosted Ollama provider.
pub struct OllamaProvider {
    base_url: String,
    client: Client,
}

impl OllamaProvider {
    /// Create a new Ollama provider (base_url: http://localhost:11434, default).
    pub fn new(base_url: String) -> anyhow::Result<Self> {
        if base_url.is_empty() {
            anyhow::bail!("OLLAMA_URL not configured");
        }
        Ok(Self {
            base_url,
            client: Client::new(),
        })
    }
}

#[async_trait]
impl CompletionProvider for OllamaProvider {
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
            "messages": messages,
        });

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(AiError::Provider(format!(
                "Ollama returned status {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AiError::Transport(e.to_string()))?;

        let content = data
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| AiError::Provider("malformed response".to_string()))?
            .to_string();

        Ok(CompletionResponse {
            content,
            model: req.model,
        })
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
            model: "llama3".to_owned(),
            messages: vec![crate::Message {
                role: "user".to_owned(),
                content: "hello".to_owned(),
            }],
            max_tokens: 128,
        }
    }

    #[test]
    fn new_rejects_an_empty_base_url() {
        assert!(OllamaProvider::new(String::new()).is_err());
    }

    #[tokio::test]
    async fn complete_returns_content_and_the_request_model_on_success() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "hi there"},
            })))
            .mount(&mock)
            .await;

        // Trailing slash on the configured base_url must not double up in
        // the request path.
        let provider = OllamaProvider::new(format!("{}/", mock.uri()))
            .unwrap_or_else(|e| panic!("provider: {e}"));
        let resp = provider
            .complete(req())
            .await
            .unwrap_or_else(|e| panic!("complete: {e}"));
        assert_eq!(resp.content, "hi there");
        // Ollama's response never carries its own `model` field — the
        // provider always echoes the request's.
        assert_eq!(resp.model, "llama3");
    }

    #[tokio::test]
    async fn complete_maps_a_non_success_status_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let provider = OllamaProvider::new(mock.uri()).unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert!(msg.contains("500")),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_response_missing_content_to_a_provider_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let provider = OllamaProvider::new(mock.uri()).unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Provider(msg)) => assert_eq!(msg, "malformed response"),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_a_non_json_body_to_a_transport_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock)
            .await;

        let provider = OllamaProvider::new(mock.uri()).unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn complete_maps_an_unreachable_endpoint_to_a_transport_error() {
        // Nothing listens on this loopback port — `.send()` itself fails
        // before a response is ever received.
        let provider = OllamaProvider::new("http://127.0.0.1:1".to_owned())
            .unwrap_or_else(|e| panic!("provider: {e}"));
        match provider.complete(req()).await {
            Err(AiError::Transport(_)) => {}
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
