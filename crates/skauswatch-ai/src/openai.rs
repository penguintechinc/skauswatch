//! OpenAI provider implementation.

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::{AiError, CompletionProvider, CompletionRequest, CompletionResponse};

/// OpenAI API provider.
pub struct OpenaiProvider {
    api_key: String,
    client: Client,
}

impl OpenaiProvider {
    /// Create a new OpenAI provider with the given API key.
    pub fn new(api_key: String) -> anyhow::Result<Self> {
        if api_key.is_empty() {
            anyhow::bail!("OPENAI_API_KEY not configured");
        }
        Ok(Self {
            api_key,
            client: Client::new(),
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
            .post("https://api.openai.com/v1/chat/completions")
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
