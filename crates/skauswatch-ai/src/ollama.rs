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
