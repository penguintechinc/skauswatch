# AI Model Recommendations for PR Review

## Executive Summary

Based on comprehensive research of open-source AI models for security vulnerability detection and programming design improvements, this document provides recommendations for the AI PR Reviewer service.

**Key Finding**: While Chinese models (DeepSeek, Qwen) currently lead in benchmarks, strong Western alternatives exist from Meta, IBM, Mistral, and the BigCode project.

---

## Recommended Open-Source Models (Western/US-Based)

### Tier 1: Production-Ready Models

#### 1. **IBM Granite Code 20B/34B** ⭐ TOP RECOMMENDATION
- **Developer**: IBM (US)
- **License**: Apache 2.0
- **Sizes**: 3B, 8B, 20B, 34B parameters
- **Ollama Model**: `granite-code:20b`, `granite-code:34b`

**Strengths**:
- **Explicit vulnerability detection capability** built into the model
- Trained on enterprise-grade, license-permissive data
- PII redaction and malware scanning during training
- Strong performance on code generation, fixing, and explanation
- Comprehensive language support: Python, JavaScript, Java, Go, C++, Rust
- Achieves best-in-class performance at 7B-8B scale
- Designed for enterprise security and compliance

**Benchmarks**:
- HumanEvalPack: Competitive with larger models
- CyberMetric Dataset: Excellent on cybersecurity benchmarks
- Vulnerability detection: Explicit support with strong results

**Use Cases**:
- **Security reviews** (primary strength)
- Code fixing and explanation
- Best practices recommendations
- Enterprise compliance checks

**Recommendation**: Use as **primary model for security reviews**

---

#### 2. **Meta Llama 3.3 70B**
- **Developer**: Meta (US)
- **License**: Llama 3 Community License
- **Size**: 70B parameters
- **Ollama Model**: `llama3.3:70b`

**Strengths**:
- State-of-the-art performance from Meta
- Strong multi-vulnerability detection (F1: 0.90 for single-vuln files)
- Language-specific performance: C (94.4% recall), JavaScript (93.0% recall)
- Can be fine-tuned for specific vulnerability types
- General-purpose model with strong code capabilities

**Limitations**:
- Performance drops with multiple vulnerabilities (F1: 0.62 for 9-vuln files)
- Python vulnerability detection weaker (51.1% recall)
- Fine-tuning for security can impact safety scores

**Benchmarks**:
- HumanEval: Strong performance
- Multi-vulnerability detection: F1 0.90 (single), 0.62 (multi)
- Fine-tuned variants beat GPT-4 on security tasks

**Use Cases**:
- **Programming design reviews** (primary strength)
- Best practices and architecture feedback
- General code quality improvements
- Fine-tuned for specific security patterns

**Recommendation**: Use for **design and best practices reviews**

---

#### 3. **Mistral Codestral 22B**
- **Developer**: Mistral AI (France/EU)
- **License**: Mistral AI Non-Production License (research/non-commercial)
- **Size**: 22B parameters, 256K context window
- **Ollama Model**: `codestral:22b`

**Strengths**:
- Excellent code generation (86.6% HumanEval)
- Massive 256K token context window (great for large codebases)
- 80+ programming language support
- Fill-in-the-middle (FIM) score: 95.3%
- JavaScript-specific strength: 87.96% HumanEvalFIM
- Can be deployed locally for data security

**Limitations**:
- Less restrictive guardrails than Claude/GPT-4
- Security logic needs manual scrutiny
- License restricts commercial production use (check latest terms)

**Benchmarks**:
- HumanEval: 86.6%
- JavaScript HumanEvalFIM: 87.96%
- FIM pass@1: 95.3% average

**Use Cases**:
- **Framework-specific reviews** (primary strength)
- Code completion and suggestions
- Large codebase analysis (256K context)
- Multi-language projects

**Recommendation**: Use for **framework and IaC reviews**

---

#### 4. **StarCoder2 15B**
- **Developer**: BigCode Project (Hugging Face, ServiceNow, multi-org)
- **License**: Apache 2.0 / OpenRAIL-M
- **Sizes**: 3B, 7B, 15B parameters
- **Ollama Model**: `starcoder2:15b`

**Strengths**:
- Fully open-source (Apache 2.0)
- Trained on 3.3-4.3 trillion tokens
- High-quality data from GitHub PRs, Kaggle notebooks, documentation
- StarCoder2-15B outperforms CodeLlama-34B (2x its size)
- Strong code generation and completion
- Responsible development practices

**Limitations**:
- No specific security vulnerability benchmarks found
- More focused on code generation than security analysis

**Benchmarks**:
- BigCodeBench: Strong performance
- Outperforms similar-sized models
- 15B matches CodeLlama-34B

**Use Cases**:
- Code generation and completion
- General code review
- Supporting model for non-security reviews

**Recommendation**: Use as **secondary/fallback model**

---

### Tier 2: Specialized Use Cases

#### 5. **Meta CodeLlama 70B**
- **Developer**: Meta (US)
- **License**: Llama 2 Community License
- **Size**: 70B parameters
- **Ollama Model**: `codellama:70b`

**Strengths**:
- HumanEval: 67.8%, MBPP: 62.2%
- On par with ChatGPT for code tasks
- Automated code review and bug detection
- Mature model with wide adoption

**Limitations**:
- Older generation (superseded by Llama 3.x)
- Variable performance based on context window
- "Still a lot of work to be done" for reliable vulnerability detection
- Poor at identifying vulnerability types (best F1: 0.16)

**Benchmarks**:
- HumanEval: 67.8%
- MBPP: 62.2%
- Vulnerability type identification: F1 0.16 (weak)

**Use Cases**:
- Legacy fallback
- General code review
- Non-security focused reviews

**Recommendation**: **Consider upgrading to Llama 3.3 70B instead**

---

## Model Selection Strategy

### By Review Category

| Review Category | Primary Model | Secondary Model | Rationale |
|----------------|---------------|-----------------|-----------|
| **Security** | IBM Granite Code 34B | Llama 3.3 70B | Granite explicitly designed for vulnerability detection |
| **Best Practices** | Llama 3.3 70B | Mistral Codestral 22B | Strong general programming knowledge |
| **Framework** | Mistral Codestral 22B | Llama 3.3 70B | 256K context, 80+ languages, framework patterns |
| **IaC** | IBM Granite Code 20B | Mistral Codestral 22B | Enterprise focus, compliance built-in |

### By Performance Requirements

| Requirement | Recommended Model | Notes |
|------------|-------------------|-------|
| **Fastest** | Granite Code 8B | Best performance at smaller size |
| **Most Accurate** | Llama 3.3 70B | Highest quality, slowest inference |
| **Best Balance** | Granite Code 20B | Security-focused, good speed |
| **Largest Context** | Codestral 22B | 256K tokens for huge codebases |

### By Resource Constraints

| VRAM Available | Recommended Model | Quantization |
|----------------|-------------------|--------------|
| 8-16 GB | StarCoder2 3B or Granite 3B | Q4_K_M |
| 16-24 GB | Granite Code 8B | Q4_K_M |
| 24-48 GB | Granite Code 20B or Codestral 22B | Q5_K_M |
| 48+ GB | Llama 3.3 70B or Granite 34B | Q4_K_M or Q5_K_M |

---

## Implementation Recommendations

### Default Configuration

```python
# services/flask-backend/app/config.py
OLLAMA_MODELS = {
    "security": "granite-code:34b",        # Primary: IBM Granite for security
    "best_practices": "llama3.3:70b",      # Primary: Llama 3.3 for design
    "framework": "codestral:22b",          # Primary: Codestral for frameworks
    "iac": "granite-code:20b",             # Primary: Granite for IaC
    "fallback": "starcoder2:15b",          # Fallback: StarCoder2
}

# Default model when category not specified
DEFAULT_OLLAMA_MODEL = "granite-code:20b"
```

### Ollama Setup Commands

```bash
# Install recommended models
ollama pull granite-code:34b        # Security reviews (18GB)
ollama pull llama3.3:70b            # Best practices (40GB)
ollama pull codestral:22b           # Framework reviews (13GB)
ollama pull granite-code:20b        # IaC reviews (12GB)
ollama pull starcoder2:15b          # Fallback (9GB)

# Smaller alternatives for resource-constrained environments
ollama pull granite-code:8b         # Security (lightweight)
ollama pull starcoder2:7b           # General (lightweight)
```

### Model Selection Logic

```python
def get_ollama_model_for_review(category: str, large_context: bool = False) -> str:
    """Select appropriate Ollama model based on review category.

    Args:
        category: Review category (security, best_practices, framework, iac)
        large_context: Whether codebase is very large (>100K tokens)

    Returns:
        Ollama model name
    """
    if large_context:
        return "codestral:22b"  # 256K context window

    model_map = {
        "security": "granite-code:34b",
        "best_practices": "llama3.3:70b",
        "framework": "codestral:22b",
        "iac": "granite-code:20b",
    }

    return model_map.get(category, "granite-code:20b")
```

---

## Critical Security Findings

### AI-Generated Code Vulnerability Rate

**CRITICAL**: Research shows that **45% of AI-generated code samples failed security tests** and introduced OWASP Top 10 vulnerabilities. Security performance remained flat regardless of model size or training sophistication.

**Implication**: Do NOT rely solely on any AI model for security validation. Always combine with:
- Static analysis tools (semgrep, bandit, gosec)
- Dynamic security scanners (trivy, grype)
- Manual security review for critical code
- Multiple model consensus for security findings

### OWASP Top 10 for LLM Applications 2025

1. **Prompt Injection** - User inputs manipulate LLM behavior
2. **Sensitive Information Disclosure** - Models leak secrets/PII
3. **Supply Chain** - Vulnerable models or training data
4. **Data and Model Poisoning** - Malicious training data
5. **Improper Output Handling** - XSS, SQL injection from outputs
6. **Excessive Agency** - Over-privileged model actions
7. **System Prompt Leakage** - Exposure of system instructions
8. **Vector and Embedding Weaknesses** - Embedding vulnerabilities
9. **Misinformation** - Hallucinations and false information
10. **Unbounded Consumption** - Resource exhaustion attacks

**Mitigation in PR Reviewer**:
- Sanitize and validate all inputs before passing to models
- Never execute AI-generated code without review
- Limit model permissions and access
- Rate limiting and resource quotas
- Multiple model validation for critical findings

---

## Model Comparison Matrix

| Model | Size | License | Security Focus | Context | Languages | HumanEval | Best For |
|-------|------|---------|----------------|---------|-----------|-----------|----------|
| **Granite Code 34B** | 34B | Apache 2.0 | ⭐⭐⭐⭐⭐ | 8K | 92 | ~75% | Security |
| **Llama 3.3 70B** | 70B | Llama 3 | ⭐⭐⭐⭐ | 128K | General | ~80% | Design |
| **Codestral 22B** | 22B | Non-Prod | ⭐⭐⭐ | 256K | 80+ | 86.6% | Framework |
| **StarCoder2 15B** | 15B | Apache 2.0 | ⭐⭐⭐ | 16K | 619 | ~70% | Code Gen |
| **CodeLlama 70B** | 70B | Llama 2 | ⭐⭐ | 16K | General | 67.8% | Legacy |

---

## Deployment Recommendations

### For Different Deployment Scenarios

#### Cloud/High-Resource Deployment
```yaml
# Use largest, most accurate models
security_model: granite-code:34b
design_model: llama3.3:70b
framework_model: codestral:22b
iac_model: granite-code:20b
```

#### Edge/Medium-Resource Deployment
```yaml
# Balance accuracy and resource usage
security_model: granite-code:20b
design_model: granite-code:20b
framework_model: starcoder2:15b
iac_model: granite-code:8b
```

#### Lightweight/Low-Resource Deployment
```yaml
# Minimal resource usage
security_model: granite-code:8b
design_model: starcoder2:7b
framework_model: starcoder2:7b
iac_model: granite-code:8b
```

---

## Future Considerations

### Emerging Models to Watch

1. **IBM Granite 4.0** - Enhanced security and scale (announced 2025)
2. **Meta Llama 4.x** - Next generation (expected 2026)
3. **BigCode StarCoder3** - Next iteration with improved training
4. **Mistral Codestral 2.0** - Potential commercial license updates

### Fine-Tuning Opportunities

Consider fine-tuning Granite Code or Llama 3.3 on:
- Project-specific security patterns
- Organizational coding standards
- Historical vulnerability datasets
- Framework-specific best practices

### Model Ensemble Approach

For critical security reviews, use **multiple models** and require consensus:
```python
# High-confidence approach
security_models = [
    "granite-code:34b",      # IBM security focus
    "llama3.3:70b",          # Meta general quality
    "codestral:22b",         # Mistral alternative view
]

# Require 2/3 models to agree on critical vulnerabilities
```

---

## Sources and References

- [IBM Granite Code Models](https://github.com/ibm-granite/granite-code-models)
- [IBM Granite Cybersecurity Benchmarking](https://www.redhat.com/en/blog/comprehensive-benchmarking-granite-and-instructlab-models-cybersecurity)
- [Meta Llama 3.3 Security Report](https://www.promptfoo.dev/models/reports/llama-3.3-70b)
- [Evaluating Llama 3.2 for Vulnerability Detection](https://arxiv.org/abs/2503.07770)
- [Mistral Codestral Announcement](https://mistral.ai/news/codestral-25-08)
- [StarCoder2 GitHub Repository](https://github.com/bigcode-project/starcoder2)
- [OWASP Top 10 for LLMs 2025](https://genai.owasp.org/llm-top-10/)
- [Veracode GenAI Code Security Report](https://www.veracode.com/blog/genai-code-security-report/)

---

**Document Version**: 1.0
**Last Updated**: 2025-01-08
**Maintained by**: Darwin PR Reviewer Team
