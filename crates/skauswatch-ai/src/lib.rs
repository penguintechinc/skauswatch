//! Multi-provider AI abstraction ported from
//! `services/manager-new/services/ai/` — one `CompletionProvider` trait with
//! Anthropic, OpenAI, and Ollama implementations (Phase 2/7 fill in the HTTP
//! clients). Provider API keys come from env/secrets, never config files.

use serde::{Deserialize, Serialize};

/// Which upstream AI provider to use, from `AI_PROVIDER` env.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// Anthropic Claude models.
    Anthropic,
    /// OpenAI models.
    Openai,
    /// Self-hosted Ollama models.
    Ollama,
}

/// One chat message in a completion exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// `system`, `user`, or `assistant`.
    pub role: String,
    /// Message text content.
    pub content: String,
}

/// A provider-agnostic completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// Model identifier (pinned per deployment, never `latest`).
    pub model: String,
    /// Conversation so far.
    pub messages: Vec<Message>,
    /// Upper bound on generated tokens.
    pub max_tokens: u32,
}

/// A provider-agnostic completion response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// Generated text.
    pub content: String,
    /// Provider-reported model that served the request.
    pub model: String,
}

/// Errors from provider calls.
#[derive(Debug, thiserror::Error)]
pub enum AiError {
    /// Transport-level failure reaching the provider.
    #[error("provider transport error: {0}")]
    Transport(String),
    /// The provider returned a non-success or malformed response.
    #[error("provider response error: {0}")]
    Provider(String),
}

/// The completion interface every provider implements. Object-safe so the
/// active provider can be selected at runtime from `ProviderKind`.
#[async_trait::async_trait]
pub trait CompletionProvider: Send + Sync {
    /// Executes one completion request against the provider.
    async fn complete(&self, req: CompletionRequest) -> Result<CompletionResponse, AiError>;
}
