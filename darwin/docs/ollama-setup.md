# Ollama Setup Guide for AI PR Reviewer

This guide explains how to set up Ollama with the recommended open-source AI models for the PR Reviewer service.

## Quick Start

```bash
# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve

# Pull recommended models (in order of priority)
ollama pull granite-code:20b        # Default model (12GB)
ollama pull granite-code:34b        # Security reviews (18GB)
ollama pull llama3.3:70b            # Best practices (40GB)
ollama pull codestral:22b           # Framework reviews (13GB)
ollama pull starcoder2:15b          # Fallback (9GB)
```

## Recommended Models by Use Case

### Production Deployment (High-Resource)
**Total VRAM Required**: ~92 GB (quantized models)

```bash
# Security-focused reviews
ollama pull granite-code:34b        # 18GB - IBM Granite, security focus

# Design and best practices
ollama pull llama3.3:70b            # 40GB - Meta Llama, design reviews

# Framework-specific reviews
ollama pull codestral:22b           # 13GB - Mistral, 256K context

# IaC and compliance
ollama pull granite-code:20b        # 12GB - IBM Granite, balanced

# General fallback
ollama pull starcoder2:15b          # 9GB - BigCode, general purpose
```

### Medium Deployment (24-48 GB VRAM)
**Recommended for most users**

```bash
# Primary model for all categories
ollama pull granite-code:20b        # 12GB - Best balance

# Fallback for general tasks
ollama pull starcoder2:15b          # 9GB - Fallback
```

### Lightweight Deployment (8-24 GB VRAM)
**For resource-constrained environments**

```bash
# Lightweight security model
ollama pull granite-code:8b         # 5GB - Security basics

# Lightweight general model
ollama pull starcoder2:7b           # 4GB - General purpose
```

## Model Details

### 1. IBM Granite Code 34B (Security Reviews)
```bash
ollama pull granite-code:34b
```

**Specs**:
- Size: 34B parameters (~18GB quantized)
- License: Apache 2.0
- Context: 8K tokens
- Languages: 92 programming languages

**Best For**:
- Security vulnerability detection
- OWASP Top 10 detection
- Enterprise compliance checks
- Critical code paths

**Benchmarks**:
- Explicit vulnerability detection capability
- Trained on enterprise-grade data
- PII redaction and malware scanning

### 2. Meta Llama 3.3 70B (Design & Best Practices)
```bash
ollama pull llama3.3:70b
```

**Specs**:
- Size: 70B parameters (~40GB quantized)
- License: Llama 3 Community License
- Context: 128K tokens
- Languages: General programming

**Best For**:
- Programming design patterns
- Architectural feedback
- Best practices recommendations
- Multi-vulnerability detection

**Benchmarks**:
- C vulnerability detection: 94.4% recall
- JavaScript: 93.0% recall
- F1 Score: 0.90 (single vulnerability)

### 3. Mistral Codestral 22B (Framework Reviews)
```bash
ollama pull codestral:22b
```

**Specs**:
- Size: 22B parameters (~13GB quantized)
- License: Mistral AI Non-Production License
- Context: 256K tokens (LARGEST)
- Languages: 80+ programming languages

**Best For**:
- Framework-specific patterns
- Large codebase analysis
- IaC (Infrastructure as Code)
- Fill-in-the-middle completions

**Benchmarks**:
- HumanEval: 86.6%
- JavaScript HumanEvalFIM: 87.96%
- FIM pass@1: 95.3%

### 4. IBM Granite Code 20B (Balanced Default)
```bash
ollama pull granite-code:20b
```

**Specs**:
- Size: 20B parameters (~12GB quantized)
- License: Apache 2.0
- Context: 8K tokens
- Languages: 92 programming languages

**Best For**:
- Default model for all categories
- IaC reviews (Terraform, Ansible)
- Balanced performance and resource usage
- Production deployments

**Benchmarks**:
- HumanEvalPack: Strong performance
- Best performance at 7B-8B scale

### 5. StarCoder2 15B (Fallback)
```bash
ollama pull starcoder2:15b
```

**Specs**:
- Size: 15B parameters (~9GB quantized)
- License: Apache 2.0 / OpenRAIL-M
- Context: 16K tokens
- Languages: 619 programming languages

**Best For**:
- General code review
- Fallback when other models unavailable
- Code generation and completion
- Wide language support

**Benchmarks**:
- Outperforms CodeLlama-34B (2x its size)
- Trained on 3.3-4.3 trillion tokens

## Configuration

### Environment Variables

```bash
# In .env file
DEFAULT_AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434

# Model selection by category
OLLAMA_MODEL_SECURITY=granite-code:34b
OLLAMA_MODEL_BEST_PRACTICES=llama3.3:70b
OLLAMA_MODEL_FRAMEWORK=codestral:22b
OLLAMA_MODEL_IAC=granite-code:20b
OLLAMA_MODEL_FALLBACK=starcoder2:15b
OLLAMA_MODEL_DEFAULT=granite-code:20b
```

### Verifying Installation

```bash
# Check Ollama status
ollama list

# Test a model
ollama run granite-code:20b "Write a Python function to check if a number is prime"

# Health check
curl http://localhost:11434/api/tags
```

## Performance Tuning

### GPU Configuration

```bash
# Set VRAM limit (example: 24GB)
export OLLAMA_NUM_GPU=1
export OLLAMA_GPU_MEMORY_FRACTION=0.9

# For multi-GPU
export OLLAMA_NUM_GPU=2
```

### CPU-Only Mode

```bash
# Force CPU usage (slower but works without GPU)
export OLLAMA_NUM_GPU=0
ollama run granite-code:20b
```

### Concurrent Requests

```bash
# Set max parallel requests (default: 4)
export OLLAMA_MAX_LOADED_MODELS=2
export OLLAMA_NUM_PARALLEL=4
```

## Model Management

### Update Models

```bash
# Update specific model
ollama pull granite-code:34b

# Update all installed models
ollama list | grep -v NAME | awk '{print $1}' | xargs -I {} ollama pull {}
```

### Remove Models

```bash
# Remove unused model
ollama rm codellama:13b

# Clean up space
ollama prune
```

### Check Model Info

```bash
# Get model details
ollama show granite-code:34b

# List all models
ollama list
```

## Troubleshooting

### Ollama Not Starting

```bash
# Check Ollama service
systemctl status ollama

# Restart service
sudo systemctl restart ollama

# Check logs
journalctl -u ollama -f
```

### Out of Memory

```bash
# Use smaller quantized models
ollama pull granite-code:8b       # Instead of 34b
ollama pull starcoder2:7b          # Instead of 15b

# Reduce concurrent requests
export OLLAMA_MAX_LOADED_MODELS=1
export OLLAMA_NUM_PARALLEL=2
```

### Slow Inference

```bash
# Enable GPU acceleration
export OLLAMA_NUM_GPU=1

# Use smaller models
ollama pull granite-code:8b

# Reduce context window in API calls
# (configure in application settings)
```

### Model Download Failed

```bash
# Retry download
ollama pull granite-code:34b

# Use mirror or VPN if blocked
export OLLAMA_HOST=http://your-mirror:11434
```

## Security Considerations

### Local Deployment Only
- Ollama runs locally - no data sent to external servers
- Models execute on your infrastructure
- Full control over model weights and data

### Network Security
```bash
# Bind to localhost only (default)
export OLLAMA_HOST=127.0.0.1:11434

# For Docker/container access
export OLLAMA_HOST=0.0.0.0:11434

# Use authentication proxy (recommended for production)
```

### Model Verification
```bash
# Verify model signatures (when available)
ollama show granite-code:34b --modelfile

# Check model provenance
ollama list --json | jq '.models[] | {name, digest}'
```

## Integration with PR Reviewer

### Automatic Model Selection

The PR Reviewer automatically selects models based on review category:

```python
from app.providers.ollama import OllamaProvider

# Security review
model = OllamaProvider.get_model_for_category("security")
# Returns: "granite-code:34b"

# Framework review with large codebase
model = OllamaProvider.get_model_for_category("framework", large_context=True)
# Returns: "codestral:22b" (256K context)

# Default fallback
model = OllamaProvider.get_model_for_category("unknown")
# Returns: "granite-code:20b"
```

### Manual Model Override

```bash
# Override via environment variable
export OLLAMA_MODEL_SECURITY=granite-code:20b  # Use smaller model

# Or via API request
curl -X POST /api/v1/reviews \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "user/repo",
    "pr_number": 123,
    "ai_provider": "ollama",
    "model": "granite-code:8b"
  }'
```

## Resource Planning

### VRAM Requirements (Quantized Q4/Q5)

| Model | VRAM (Q4) | VRAM (Q5) | Recommended GPU |
|-------|-----------|-----------|-----------------|
| granite-code:8b | 5 GB | 6 GB | RTX 3060 (12GB) |
| starcoder2:15b | 9 GB | 11 GB | RTX 3080 (10GB) |
| granite-code:20b | 12 GB | 14 GB | RTX 3090 (24GB) |
| codestral:22b | 13 GB | 16 GB | RTX 3090 (24GB) |
| granite-code:34b | 18 GB | 22 GB | RTX 4090 (24GB) |
| llama3.3:70b | 40 GB | 48 GB | A100 (40GB) x2 |

### Inference Speed Estimates

| Model Size | GPU | Tokens/sec | Latency (avg) |
|-----------|-----|------------|---------------|
| 8B | RTX 3090 | ~60 | ~500ms |
| 20B | RTX 3090 | ~25 | ~1.2s |
| 34B | RTX 4090 | ~20 | ~1.5s |
| 70B | A100 40GB | ~10 | ~3s |

## Further Reading

- [AI Model Recommendations](ai-model-recommendations.md) - Detailed model comparison and selection guide
- [Ollama Documentation](https://github.com/ollama/ollama/blob/main/docs/README.md) - Official Ollama docs
- [IBM Granite Code](https://github.com/ibm-granite/granite-code-models) - Granite model details
- [Meta Llama](https://www.llama.com/) - Llama model information
- [Mistral Codestral](https://mistral.ai/news/codestral) - Codestral announcement

---

**Last Updated**: 2025-01-08
**Maintained by**: Darwin PR Reviewer Team
