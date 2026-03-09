# AI PR Reviewer - Usage Guide

This guide provides hardware recommendations, model selection strategies, and configuration examples for running the AI PR Reviewer with optimal performance.

## Table of Contents

- [Hardware Recommendations](#hardware-recommendations)
  - [NVIDIA GPUs](#nvidia-gpus)
  - [AMD GPUs](#amd-gpus)
  - [Intel GPUs](#intel-gpus)
- [GPU Selection Guide](#gpu-selection-guide)
- [Configuration Examples](#configuration-examples)
- [Review Category Configuration](#review-category-configuration)
- [Performance Tuning](#performance-tuning)
- [Multi-GPU Configurations](#multi-gpu-configurations)

---

## Hardware Recommendations

### NVIDIA GPUs

#### NVIDIA A-Series Data Center GPUs

**Recommended for production deployments and high-volume review workloads.**

| GPU Model | VRAM | Recommended Models | Max Concurrent | Use Case |
|-----------|------|-------------------|----------------|----------|
| **A6000** | 48 GB | All models up to 34B | 2-3 reviews | High-end workstation |
| **A6000 Ada** | 48 GB | All models up to 34B | 2-3 reviews | Next-gen workstation |
| **A100 40GB** | 40 GB | All models up to 34B | 2 reviews | Cloud/datacenter |
| **A100 80GB** | 80 GB | All models including 70B | 4-5 reviews | Enterprise production |
| **A800 80GB** | 80 GB | All models including 70B | 4-5 reviews | Enterprise (export-restricted) |
| **H100 80GB** | 80 GB | All models including 70B | 6-8 reviews | Latest gen, fastest |
| **H100 NVL** | 94 GB (2x47) | All models, multi-instance | 8-10 reviews | Dual-die, highest throughput |

#### NVIDIA RTX 4000 Series Consumer/Prosumer GPUs

| GPU Model | VRAM | Recommended Models | Max Concurrent | Price Range |
|-----------|------|-------------------|----------------|-------------|
| **RTX 4060** | 8 GB | granite-code:8b, starcoder2:7b | 1 review | $300 |
| **RTX 4060 Ti** | 8/16 GB | granite-code:8b, starcoder2:15b | 1 review | $400-500 |
| **RTX 4070** | 12 GB | granite-code:20b, codestral:22b | 1 review | $600 |
| **RTX 4070 Ti** | 12 GB | granite-code:20b, codestral:22b | 1 review | $800 |
| **RTX 4070 Ti Super** | 16 GB | granite-code:20b, starcoder2:15b | 1-2 reviews | $900 |
| **RTX 4080** | 16 GB | granite-code:34b (tight) | 1 review | $1,200 |
| **RTX 4080 Super** | 16 GB | granite-code:34b (tight) | 1 review | $1,000 |
| **RTX 4090** | 24 GB | granite-code:34b, codestral:22b | 1-2 reviews | $1,600 |

#### NVIDIA RTX 5000 Series Consumer/Prosumer GPUs (2025+)

| GPU Model | VRAM | Recommended Models | Expected Price |
|-----------|------|-------------------|----------------|
| **RTX 5060** | 8 GB | granite-code:8b, starcoder2:7b | ~$300 |
| **RTX 5060 Ti** | 12 GB | granite-code:20b | ~$450 |
| **RTX 5070** | 12 GB | granite-code:20b, codestral:22b | ~$600 |
| **RTX 5070 Ti** | 16 GB | granite-code:34b | ~$800 |
| **RTX 5080** | 16 GB | granite-code:34b | ~$1,200 |
| **RTX 5090** | 32 GB | granite-code:34b, llama3.3:70b (Q4) | ~$2,000 |

#### NVIDIA RTX Professional/Workstation GPUs

| GPU Model | VRAM | Recommended Models | Price Range |
|-----------|------|-------------------|-------------|
| **RTX A2000** | 6/12 GB | granite-code:8b | $500-700 |
| **RTX A4000** | 16 GB | granite-code:34b | $1,000 |
| **RTX A4500** | 20 GB | granite-code:34b, codestral:22b | $1,500 |
| **RTX A5000** | 24 GB | granite-code:34b, codestral:22b | $2,500 |
| **RTX A5500** | 24 GB | granite-code:34b, codestral:22b | $3,000 |
| **RTX A6000** | 48 GB | All models up to 34B | $4,500 |
| **RTX A6000 Ada** | 48 GB | All models up to 34B | $6,500 |
| **RTX 6000 Ada** | 48 GB | All models up to 34B | $7,000 |

#### NVIDIA Previous Generation (Good Used Value)

| GPU Model | VRAM | Recommended Models | Typical Used Price |
|-----------|------|-------------------|--------------------|
| **RTX 3060** | 12 GB | granite-code:20b | $200-250 |
| **RTX 3060 Ti** | 8 GB | granite-code:8b | $250-300 |
| **RTX 3070** | 8 GB | granite-code:8b | $350-400 |
| **RTX 3070 Ti** | 8 GB | granite-code:8b | $400-450 |
| **RTX 3080** | 10 GB | granite-code:20b | $500-600 |
| **RTX 3080 Ti** | 12 GB | granite-code:20b | $600-700 |
| **RTX 3090** | 24 GB | granite-code:34b, codestral:22b | $800-1,000 |
| **RTX 3090 Ti** | 24 GB | granite-code:34b, codestral:22b | $900-1,100 |

---

### AMD GPUs

#### AMD Radeon Instinct/Data Center GPUs

**Professional compute cards with ROCm support for AI workloads.**

| GPU Model | VRAM | Recommended Models | Max Concurrent | Use Case |
|-----------|------|-------------------|----------------|----------|
| **MI210** | 64 GB | All models including 70B | 3-4 reviews | Data center |
| **MI250** | 128 GB (2x64) | All models, multi-instance | 6-8 reviews | HPC/Enterprise |
| **MI250X** | 128 GB (2x64) | All models, multi-instance | 6-8 reviews | High-end HPC |
| **MI300A** | 128 GB | All models, multi-instance | 8-10 reviews | Latest gen |
| **MI300X** | 192 GB | All models, highest density | 10-12 reviews | Flagship datacenter |

**AMD Instinct Notes**:
- Excellent value per GB of VRAM
- ROCm support improving (not as mature as CUDA)
- Best for on-premise deployments
- MI300X: Best price/performance for 70B models

#### AMD Radeon RX 7000 Series (RDNA 3)

**Latest consumer GPUs with good AI inference support.**

| GPU Model | VRAM | Recommended Models | Max Concurrent | Price Range |
|-----------|------|-------------------|----------------|-------------|
| **RX 7600** | 8 GB | granite-code:8b, starcoder2:7b | 1 review | $250 |
| **RX 7600 XT** | 16 GB | granite-code:20b, starcoder:15b | 1-2 reviews | $330 |
| **RX 7700 XT** | 12 GB | granite-code:20b | 1 review | $400 |
| **RX 7800 XT** | 16 GB | granite-code:34b (tight) | 1 review | $500 |
| **RX 7900 GRE** | 16 GB | granite-code:34b (tight) | 1 review | $550 |
| **RX 7900 XT** | 20 GB | granite-code:34b | 1 review | $700 |
| **RX 7900 XTX** | 24 GB | granite-code:34b, codestral:22b | 1-2 reviews | $900 |

**RX 7000 Highlights**:
- **RX 7600 XT (16GB)**: Best budget 16GB option ($330)
- **RX 7900 XTX (24GB)**: Competes with RTX 4090, $700 cheaper
- ROCm 6.0+ required for good Ollama support

#### AMD Radeon RX 6000 Series (RDNA 2)

**Previous generation with good used value.**

| GPU Model | VRAM | Recommended Models | Typical Used Price |
|-----------|------|-------------------|--------------------|
| **RX 6600** | 8 GB | granite-code:8b | $150-180 |
| **RX 6600 XT** | 8 GB | granite-code:8b | $180-220 |
| **RX 6700 XT** | 12 GB | granite-code:20b | $250-300 |
| **RX 6750 XT** | 12 GB | granite-code:20b | $280-320 |
| **RX 6800** | 16 GB | granite-code:34b (tight) | $350-400 |
| **RX 6800 XT** | 16 GB | granite-code:34b (tight) | $400-450 |
| **RX 6900 XT** | 16 GB | granite-code:34b (tight) | $450-500 |
| **RX 6950 XT** | 16 GB | granite-code:34b (tight) | $500-550 |

#### AMD Radeon PRO Workstation GPUs

**Professional cards with large VRAM.**

| GPU Model | VRAM | Recommended Models | Price Range |
|-----------|------|-------------------|-------------|
| **Radeon PRO W6600** | 8 GB | granite-code:8b | $400 |
| **Radeon PRO W6800** | 32 GB | granite-code:34b, codestral:22b, granite:20b | $2,200 |
| **Radeon PRO W7800** | 32 GB | granite-code:34b, codestral:22b, granite:20b | $2,500 |
| **Radeon PRO W7900** | 48 GB | All models up to 34B | $3,500 |

**Radeon PRO Highlights**:
- **W6800/W7800 (32GB)**: Excellent value for 32GB VRAM
- **W7900 (48GB)**: Competes with RTX A6000 at lower price
- ECC memory for production reliability

---

### Intel GPUs

#### Intel Data Center Max Series

**Latest Intel Xe-HPC architecture for AI workloads.**

| GPU Model | VRAM | Recommended Models | Max Concurrent | Use Case |
|-----------|------|-------------------|----------------|----------|
| **Data Center GPU Max 1100** | 48 GB | All models up to 34B | 2-3 reviews | Entry datacenter |
| **Data Center GPU Max 1350** | 96 GB | All models including 70B (Q4) | 4-5 reviews | High-end datacenter |
| **Data Center GPU Max 1550** | 128 GB | All models including 70B | 6-8 reviews | Enterprise |

**Intel Max Notes**:
- OneAPI and SYCL support for AI frameworks
- Strong FP64 performance (scientific computing)
- Improving Ollama/PyTorch support via IPEX
- Best value for high-VRAM needs

#### Intel Arc Alchemist Series (Consumer)

**First-gen consumer Arc GPUs with AI acceleration.**

| GPU Model | VRAM | Recommended Models | Max Concurrent | Price Range |
|-----------|------|-------------------|----------------|-------------|
| **Arc A310** | 4 GB | starcoder2:3b (small models only) | 1 review | $100 |
| **Arc A380** | 6 GB | granite-code:8b | 1 review | $140 |
| **Arc A580** | 8 GB | granite-code:8b, starcoder2:7b | 1 review | $180 |
| **Arc A750** | 8 GB | granite-code:8b, starcoder2:7b | 1 review | $220 |
| **Arc A770** | 8/16 GB | granite-code:20b (16GB), granite:8b (8GB) | 1 review | $280-350 |

**Intel Arc Highlights**:
- **Arc A770 16GB**: Best budget 16GB option ($280)
- Excellent media encoding (bonus for video content)
- Improving driver maturity for AI workloads
- XMX (Xe Matrix Extensions) AI acceleration

#### Intel Arc Battlemage Series (2024+)

**Second-gen Arc GPUs with improved AI performance.**

| GPU Model | VRAM (Rumored) | Expected Models | Expected Price |
|-----------|----------------|-----------------|----------------|
| **Arc B570** | 10/12 GB | granite-code:8b, starcoder2:7b | ~$250 |
| **Arc B580** | 12 GB | granite-code:20b | ~$300 |
| **Arc B770** | 16 GB | granite-code:34b (tight) | ~$400 |

**Battlemage Notes**:
- Improved XMX AI acceleration (2x faster)
- Better driver support and Ollama compatibility expected
- Potentially best value 12-16GB options

---

## GPU Selection Guide

### By Budget

| Budget | Best NVIDIA | Best AMD | Best Intel | Recommended Models |
|--------|-------------|----------|------------|-------------------|
| **<$200** | RTX 3060 (used) | RX 6600 (used) | Arc A580 | granite-code:8b |
| **$200-400** | RTX 4060 Ti | RX 7600 XT | Arc A770 16GB | granite-code:20b |
| **$400-700** | RTX 4070 | RX 7900 XT | - | granite-code:20b, codestral:22b |
| **$700-1,200** | RTX 4080 Super | RX 7900 XTX | - | granite-code:34b |
| **$1,200-2,000** | RTX 4090 | - | - | granite-code:34b, codestral:22b |
| **$2,000-4,000** | RTX A6000 | Radeon PRO W7900 | - | All models up to 34B |
| **$4,000+** | A100 80GB | MI300X | Max 1550 | All models including 70B |

### Ollama Model Recommendations by GPU VRAM

**4-6 GB VRAM** (Arc A310, Arc A380):
```bash
OLLAMA_SECURITY_LLM=starcoder2:3b              # Security (lightweight)
OLLAMA_BEST_PRACTICES_LLM=starcoder2:3b        # Best practices
OLLAMA_FRAMEWORK_LLM=starcoder2:3b             # Framework
OLLAMA_IAC_LLM=starcoder2:3b                   # IaC
```
- **Models**: 3B parameter models only
- **Limitation**: Significantly reduced quality, not recommended for production

**8 GB VRAM** (RTX 4060, RX 7600, Arc A770 8GB):
```bash
OLLAMA_SECURITY_LLM=granite-code:8b            # Security (5GB)
OLLAMA_BEST_PRACTICES_LLM=granite-code:8b      # Best practices (5GB)
OLLAMA_FRAMEWORK_LLM=starcoder2:7b             # Framework (4GB)
OLLAMA_IAC_LLM=granite-code:8b                 # IaC (5GB)
```
- **Models**: granite-code:8b, starcoder2:7b
- **Use Case**: Development, testing, small teams

**12 GB VRAM** (RTX 4070, RTX 3060, RX 7700 XT):
```bash
OLLAMA_SECURITY_LLM=granite-code:20b           # Security (12GB)
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # Best practices (reuse)
OLLAMA_FRAMEWORK_LLM=granite-code:20b          # Framework (reuse)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (reuse)
```
- **Models**: granite-code:20b (single model, swap as needed)
- **Use Case**: Small production teams, balanced quality

**16 GB VRAM** (RTX 4060 Ti 16GB, RX 7600 XT, Arc A770 16GB):
```bash
OLLAMA_SECURITY_LLM=granite-code:20b           # Security (12GB)
OLLAMA_BEST_PRACTICES_LLM=starcoder2:15b       # Best practices (9GB)
OLLAMA_FRAMEWORK_LLM=granite-code:20b          # Framework (12GB)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (12GB)
```
- **Models**: granite-code:20b + starcoder2:15b
- **Use Case**: Production-ready, good quality
- **Note**: Can run one 20B model at a time comfortably

**20-24 GB VRAM** (RTX 4090, RTX 3090, RX 7900 XT/XTX):
```bash
OLLAMA_SECURITY_LLM=granite-code:34b           # Security (18GB)
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # Best practices (12GB, swap)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # Framework (13GB, swap)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (12GB, swap)
```
- **Models**: granite-code:34b, codestral:22b, granite-code:20b
- **Use Case**: High-quality production reviews
- **Note**: Load one model at a time, ~30s swap overhead

**32 GB VRAM** (RTX 5090, Radeon PRO W7800):
```bash
OLLAMA_SECURITY_LLM=granite-code:34b           # Security (18GB)
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # Best practices (12GB)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # Framework (13GB, swap)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (12GB, shared)
```
- **Models**: Can keep 2 models loaded simultaneously
- **Use Case**: Faster reviews with dual-model concurrency
- **Note**: 34B + 20B = 30GB (fits with headroom)

**48 GB VRAM** (RTX A6000, Radeon PRO W7900, Intel Max 1100):
```bash
OLLAMA_SECURITY_LLM=granite-code:34b           # Security (18GB)
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # Best practices (12GB)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # Framework (13GB)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (12GB, shared)
OLLAMA_MAX_LOADED_MODELS=3                     # Keep 3 loaded
```
- **Models**: All recommended models except 70B
- **Use Case**: Professional multi-model concurrent reviews
- **Note**: 34B + 20B + 22B = ~53GB (tight, load 2-3 at once)

**64-80 GB VRAM** (A100 40/80GB, MI210):
```bash
OLLAMA_SECURITY_LLM=granite-code:34b           # Security (18GB)
OLLAMA_BEST_PRACTICES_LLM=llama3.3:70b-q4      # Best practices (32GB quantized)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # Framework (13GB)
OLLAMA_IAC_LLM=granite-code:20b                # IaC (12GB)
OLLAMA_MAX_LOADED_MODELS=4                     # Keep 4 loaded
```
- **Models**: All models including llama3.3:70b (Q4 quantization)
- **Use Case**: Enterprise, highest quality reviews
- **Note**: 70B requires Q4 quantization to fit with other models

**128+ GB VRAM** (MI250X, MI300X, Intel Max 1550):
```bash
OLLAMA_SECURITY_LLM=granite-code:34b           # Security (18GB)
OLLAMA_BEST_PRACTICES_LLM=llama3.3:70b         # Best practices (40GB, Q5/Q6)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # Framework (13GB)
OLLAMA_IAC_LLM=granite-code:34b                # IaC (18GB)
OLLAMA_MAX_LOADED_MODELS=5                     # Keep all loaded
OLLAMA_NUM_PARALLEL=4                          # 4 concurrent reviews
```
- **Models**: All models, multiple instances possible
- **Use Case**: Maximum throughput, SaaS deployments
- **Note**: Can run multiple 70B instances or all models simultaneously

### Cross-Vendor Model Capability Matrix

| VRAM | NVIDIA Example | AMD Example | Intel Example | Recommended Models |
|------|----------------|-------------|---------------|-------------------|
| **8 GB** | RTX 4060 | RX 7600 | Arc A770 8GB | granite:8b, starcoder2:7b |
| **12 GB** | RTX 4070 | RX 7700 XT | Arc B580 (expected) | granite:20b (single model) |
| **16 GB** | RTX 4060 Ti | RX 7600 XT | Arc A770 16GB | granite:20b + starcoder2:15b |
| **24 GB** | RTX 4090 | RX 7900 XTX | - | granite:34b, codestral:22b (swap) |
| **32 GB** | RTX 5090 (expected) | Radeon PRO W7800 | - | granite:34b + granite:20b (concurrent) |
| **48 GB** | RTX A6000 | Radeon PRO W7900 | Max 1100 | All models except 70B (multi-load) |
| **80 GB** | A100 80GB | MI210 64GB | Max 1350 96GB | All models + llama3.3:70b-q4 |
| **128+ GB** | - | MI300X 192GB | Max 1550 128GB | All models, multiple 70B instances |

---

## OpenAI Model Recommendations

### OpenAI Models for Code Review

OpenAI provides several models suitable for code review tasks. Choose based on your quality, speed, and cost requirements.

#### Recommended OpenAI Models

**GPT-4o (Optimized)** - Best balance of quality and speed
```bash
DEFAULT_AI_PROVIDER=openai
OPENAI_API_KEY=sk-xxx

# Model configuration
OPENAI_SECURITY_MODEL=gpt-4o                    # Security reviews
OPENAI_BEST_PRACTICES_MODEL=gpt-4o              # Best practices
OPENAI_FRAMEWORK_MODEL=gpt-4o                   # Framework reviews
OPENAI_IAC_MODEL=gpt-4o                         # IaC reviews
```

**Performance**:
- Context: 128K tokens
- Speed: ~60 tokens/sec
- Cost: $2.50/1M input, $10/1M output
- Quality: Excellent (near GPT-4 Turbo quality, 2x faster)

**Best For**: Production deployments needing balance of quality and speed

---

**GPT-4o Mini** - Budget-friendly option
```bash
DEFAULT_AI_PROVIDER=openai

# Model configuration
OPENAI_SECURITY_MODEL=gpt-4o-mini               # Security (lightweight)
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini         # Best practices
OPENAI_FRAMEWORK_MODEL=gpt-4o-mini              # Framework reviews
OPENAI_IAC_MODEL=gpt-4o-mini                    # IaC reviews
```

**Performance**:
- Context: 128K tokens
- Speed: ~100 tokens/sec
- Cost: $0.15/1M input, $0.60/1M output (94% cheaper than GPT-4o)
- Quality: Good (better than GPT-3.5 Turbo)

**Best For**: High-volume reviews, cost-sensitive deployments, non-critical code

---

**GPT-4 Turbo** - Highest quality
```bash
DEFAULT_AI_PROVIDER=openai

# Model configuration
OPENAI_SECURITY_MODEL=gpt-4-turbo               # Security (highest quality)
OPENAI_BEST_PRACTICES_MODEL=gpt-4-turbo         # Best practices
OPENAI_FRAMEWORK_MODEL=gpt-4o                   # Framework (faster)
OPENAI_IAC_MODEL=gpt-4-turbo                    # IaC (highest quality)
```

**Performance**:
- Context: 128K tokens
- Speed: ~30 tokens/sec
- Cost: $10/1M input, $30/1M output
- Quality: Highest (most thorough analysis)

**Best For**: Critical security reviews, compliance requirements, enterprise audits

---

**o1-preview / o1-mini** - Advanced reasoning
```bash
DEFAULT_AI_PROVIDER=openai

# Model configuration (use for complex security analysis only)
OPENAI_SECURITY_MODEL=o1-preview                # Deep security analysis
OPENAI_BEST_PRACTICES_MODEL=gpt-4o              # Standard (o1 too slow)
OPENAI_FRAMEWORK_MODEL=gpt-4o                   # Standard
OPENAI_IAC_MODEL=o1-mini                        # IaC reasoning
```

**Performance (o1-preview)**:
- Context: 128K tokens
- Speed: ~15 tokens/sec (uses chain-of-thought reasoning)
- Cost: $15/1M input, $60/1M output
- Quality: Exceptional for complex security patterns

**Performance (o1-mini)**:
- Context: 128K tokens
- Speed: ~25 tokens/sec
- Cost: $3/1M input, $12/1M output
- Quality: Excellent reasoning at lower cost

**Best For**: Complex vulnerability detection, architectural security reviews, IaC compliance

---

### OpenAI Model Selection by Use Case

| Use Case | Recommended Model | Alternative | Reasoning |
|----------|------------------|-------------|-----------|
| **Security Reviews** | gpt-4o | o1-preview (critical) | Balance of quality and speed |
| **Best Practices** | gpt-4o | gpt-4o-mini (budget) | General code quality doesn't need highest tier |
| **Framework Reviews** | gpt-4o | gpt-4o-mini | Framework patterns well-known to all models |
| **IaC Reviews** | gpt-4-turbo | o1-mini | Infrastructure requires careful analysis |
| **High Volume** | gpt-4o-mini | gpt-4o | Cost optimization for many reviews |
| **Critical/Compliance** | gpt-4-turbo | o1-preview | Highest quality for audits |
| **Budget-Conscious** | gpt-4o-mini | gpt-4o | 94% cost reduction |

### OpenAI Cost Optimization Strategies

**Strategy 1: Hybrid Model Approach**
```bash
# Use expensive models only for security
OPENAI_SECURITY_MODEL=gpt-4-turbo               # $10/1M input
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini         # $0.15/1M input
OPENAI_FRAMEWORK_MODEL=gpt-4o-mini              # $0.15/1M input
OPENAI_IAC_MODEL=gpt-4o                         # $2.50/1M input
```
**Savings**: ~75% vs all GPT-4 Turbo

**Strategy 2: Volume-Based Selection**
```bash
# <100 reviews/day: Use GPT-4o for everything
OPENAI_SECURITY_MODEL=gpt-4o
OPENAI_BEST_PRACTICES_MODEL=gpt-4o
OPENAI_FRAMEWORK_MODEL=gpt-4o
OPENAI_IAC_MODEL=gpt-4o

# >100 reviews/day: Use GPT-4o Mini for non-security
OPENAI_SECURITY_MODEL=gpt-4o
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini
OPENAI_FRAMEWORK_MODEL=gpt-4o-mini
OPENAI_IAC_MODEL=gpt-4o-mini
```

**Strategy 3: Category-Specific Models**
```bash
# Security: Highest quality (complex patterns)
OPENAI_SECURITY_MODEL=o1-preview

# Best Practices: Fast and cheap (well-known patterns)
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini

# Framework: Balanced (moderate complexity)
OPENAI_FRAMEWORK_MODEL=gpt-4o

# IaC: Reasoning required (compliance rules)
OPENAI_IAC_MODEL=o1-mini
```

### OpenAI Cost Examples (1000 reviews/month)

**Scenario**: Average 2K tokens input, 500 tokens output per review

| Configuration | Monthly Cost | Reviews/$ | Use Case |
|--------------|--------------|-----------|----------|
| All GPT-4 Turbo | $45,000 | 22 | Enterprise compliance |
| All GPT-4o | $6,250 | 160 | Production standard |
| All GPT-4o Mini | $375 | 2,667 | High-volume budget |
| Hybrid (Security: GPT-4o, Rest: Mini) | $2,000 | 500 | Balanced approach |
| Hybrid (Security: o1-preview, Rest: 4o Mini) | $8,000 | 125 | Maximum security quality |

---

## Anthropic Claude Model Recommendations

### Anthropic Models for Code Review

Anthropic Claude models excel at code analysis with strong safety and reasoning capabilities.

#### Recommended Anthropic Models

**Claude Sonnet 4.5** - Best overall for code review ⭐ RECOMMENDED
```bash
DEFAULT_AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxx

# Model configuration
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5-20250514      # Security reviews
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5-20250514 # Best practices
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5-20250514     # Framework reviews
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514           # IaC reviews
```

**Performance**:
- Context: 200K tokens (largest available)
- Speed: ~50 tokens/sec
- Cost: $3/1M input, $15/1M output
- Quality: Excellent (matches GPT-4o, better reasoning)

**Best For**: Production deployments, large codebases, complex architectural reviews

**Key Strengths**:
- Superior long-context understanding (200K tokens)
- Strong code reasoning and pattern recognition
- Excellent at explaining security vulnerabilities
- Lower cost than GPT-4 Turbo, similar quality

---

**Claude Opus 4.5** - Highest quality (when available)
```bash
DEFAULT_AI_PROVIDER=anthropic

# Model configuration (use for critical reviews only)
ANTHROPIC_SECURITY_MODEL=claude-opus-4-5-20251101        # Maximum quality
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5-20250514 # Standard
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5-20250514     # Standard
ANTHROPIC_IAC_MODEL=claude-opus-4-5-20251101             # IaC compliance
```

**Performance**:
- Context: 200K tokens
- Speed: ~25 tokens/sec (slower, more thorough)
- Cost: $15/1M input, $75/1M output
- Quality: Highest (most thorough analysis)

**Best For**: Critical security audits, compliance reviews, enterprise production code

**Note**: Opus 4.5 may have limited availability or rate limits

---

**Claude Haiku 4** - Fast and efficient
```bash
DEFAULT_AI_PROVIDER=anthropic

# Model configuration
ANTHROPIC_SECURITY_MODEL=claude-haiku-4-20250514         # Fast security scan
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4-20250514   # Fast best practices
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4-20250514        # Framework checks
ANTHROPIC_IAC_MODEL=claude-haiku-4-20250514              # Quick IaC scan
```

**Performance**:
- Context: 200K tokens
- Speed: ~100 tokens/sec (fastest)
- Cost: $0.80/1M input, $4/1M output
- Quality: Good (faster, lower cost, still capable)

**Best For**: High-volume reviews, CI/CD pipelines, quick feedback loops

**Key Strengths**:
- Fastest Claude model
- Very cost-effective
- Good enough quality for most use cases
- Still maintains 200K context window

---

**Claude Sonnet 3.5** - Previous generation (legacy)
```bash
DEFAULT_AI_PROVIDER=anthropic

# Model configuration (fallback if 4.5 unavailable)
ANTHROPIC_SECURITY_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_BEST_PRACTICES_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_FRAMEWORK_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_IAC_MODEL=claude-3-5-sonnet-20241022
```

**Performance**:
- Context: 200K tokens
- Speed: ~40 tokens/sec
- Cost: $3/1M input, $15/1M output (same as Sonnet 4.5)
- Quality: Very good (previous generation)

**Best For**: Fallback when Sonnet 4.5 unavailable, no cost difference

---

### Claude Model Selection by Use Case

| Use Case | Recommended Model | Alternative | Reasoning |
|----------|------------------|-------------|-----------|
| **Security Reviews** | claude-sonnet-4-5 | claude-opus-4-5 (critical) | Excellent reasoning, good speed |
| **Best Practices** | claude-sonnet-4-5 | claude-haiku-4 (volume) | General patterns well-handled |
| **Framework Reviews** | claude-sonnet-4-5 | claude-haiku-4 | Framework knowledge strong across models |
| **IaC Reviews** | claude-sonnet-4-5 | claude-opus-4-5 (compliance) | Good at compliance rules |
| **High Volume** | claude-haiku-4 | claude-sonnet-4-5 | 5x faster, 4x cheaper |
| **Critical/Compliance** | claude-opus-4-5 | claude-sonnet-4-5 | Highest quality available |
| **Large Codebases** | claude-sonnet-4-5 | - | 200K context excels here |

### Claude Cost Optimization Strategies

**Strategy 1: Hybrid Model Approach**
```bash
# Use Opus only for security, Haiku for everything else
ANTHROPIC_SECURITY_MODEL=claude-opus-4-5-20251101        # $15/1M input
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4-20250514   # $0.80/1M input
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4-20250514        # $0.80/1M input
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514           # $3/1M input
```
**Savings**: ~70% vs all Opus

**Strategy 2: Volume-Based Selection**
```bash
# <50 reviews/day: Use Sonnet for everything
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514

# >50 reviews/day: Use Haiku for non-security
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4-20250514
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4-20250514
ANTHROPIC_IAC_MODEL=claude-haiku-4-20250514
```

**Strategy 3: Quality-Tiered Approach**
```bash
# Critical security: Opus (highest quality)
ANTHROPIC_SECURITY_MODEL=claude-opus-4-5-20251101

# Moderate complexity: Sonnet (balanced)
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514

# High-volume/simple: Haiku (fast and cheap)
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4-20250514
```

### Claude Cost Examples (1000 reviews/month)

**Scenario**: Average 2K tokens input, 500 tokens output per review

| Configuration | Monthly Cost | Reviews/$ | Use Case |
|--------------|--------------|-----------|----------|
| All Opus 4.5 | $67,500 | 15 | Maximum quality compliance |
| All Sonnet 4.5 | $13,500 | 74 | **Production standard** ⭐ |
| All Haiku 4 | $2,600 | 385 | High-volume budget |
| Hybrid (Security: Opus, Rest: Haiku) | $8,750 | 114 | Balanced security focus |
| Hybrid (Security: Sonnet, Rest: Haiku) | $4,150 | 241 | Cost-optimized quality |

### Claude Key Advantages

**Why Choose Claude:**
1. **200K Context Window**: Largest available, handles entire repositories
2. **Strong Reasoning**: Excellent at explaining "why" not just "what"
3. **Safety-Focused**: Lower hallucination rates, more reliable
4. **Code Understanding**: Trained extensively on code and technical content
5. **Cost Efficiency**: Sonnet 4.5 cheaper than GPT-4 Turbo, similar quality

**Best Practices**:
- Use Sonnet 4.5 as default for most reviews
- Reserve Opus 4.5 for critical security and compliance
- Use Haiku 4 for high-volume CI/CD integration
- Leverage 200K context for large monorepo reviews

---

## Multi-Provider Comparison

### Quality Comparison Matrix

| Provider | Model | Security Quality | Speed | Context | Cost (Input/Output) |
|----------|-------|------------------|-------|---------|---------------------|
| **Anthropic** | Opus 4.5 | ⭐⭐⭐⭐⭐ | ★★☆☆☆ | 200K | $15/$75 |
| **OpenAI** | o1-preview | ⭐⭐⭐⭐⭐ | ★★☆☆☆ | 128K | $15/$60 |
| **OpenAI** | GPT-4 Turbo | ⭐⭐⭐⭐⭐ | ★★★☆☆ | 128K | $10/$30 |
| **Anthropic** | Sonnet 4.5 | ⭐⭐⭐⭐☆ | ★★★★☆ | 200K | $3/$15 |
| **OpenAI** | GPT-4o | ⭐⭐⭐⭐☆ | ★★★★☆ | 128K | $2.50/$10 |
| **Anthropic** | Haiku 4 | ⭐⭐⭐☆☆ | ★★★★★ | 200K | $0.80/$4 |
| **OpenAI** | GPT-4o Mini | ⭐⭐⭐☆☆ | ★★★★★ | 128K | $0.15/$0.60 |

### Recommended Configurations by Budget

**Budget: Unlimited (Enterprise)**
```bash
# Best quality regardless of cost
OPENAI_SECURITY_MODEL=o1-preview                # OpenAI reasoning
ANTHROPIC_SECURITY_MODEL=claude-opus-4-5        # Anthropic reasoning
# Use both and compare results for critical code
```

**Budget: $5,000-10,000/month (Production)**
```bash
# Anthropic Sonnet 4.5 as default
DEFAULT_AI_PROVIDER=anthropic
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5
```

**Budget: $1,000-5,000/month (Standard)**
```bash
# OpenAI GPT-4o as default
DEFAULT_AI_PROVIDER=openai
OPENAI_SECURITY_MODEL=gpt-4o
OPENAI_BEST_PRACTICES_MODEL=gpt-4o
OPENAI_FRAMEWORK_MODEL=gpt-4o
OPENAI_IAC_MODEL=gpt-4o
```

**Budget: <$1,000/month (Startup)**
```bash
# Claude Haiku or GPT-4o Mini
DEFAULT_AI_PROVIDER=anthropic
ANTHROPIC_SECURITY_MODEL=claude-haiku-4
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4
ANTHROPIC_IAC_MODEL=claude-haiku-4
```

---

## Configuration Examples

### Example 1: Budget Setup (Arc A770 16GB / RX 7600 XT 16GB)

```bash
# Use one balanced model for all categories
OLLAMA_SECURITY_LLM=granite-code:20b           # 12GB
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # Reuse
OLLAMA_FRAMEWORK_LLM=granite-code:20b          # Reuse
OLLAMA_IAC_LLM=granite-code:20b                # Reuse
OLLAMA_FALLBACK_LLM=starcoder2:7b              # 4GB

# Enable all categories
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
```

**Cost**: $280-350
**Performance**: ~25 tokens/sec, 8-10 reviews/hour

---

### Example 2: Mid-Range Setup (RTX 4090 / RX 7900 XTX - 24GB)

```bash
# Use best model that fits
OLLAMA_SECURITY_LLM=granite-code:34b           # 18GB
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # 12GB (fallback)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # 13GB
OLLAMA_IAC_LLM=granite-code:20b                # 12GB
OLLAMA_FALLBACK_LLM=starcoder2:15b             # 9GB

REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
```

**Cost**: $900-1,600
**Performance**: 15-20 tokens/sec, 6-8 reviews/hour

---

### Example 3: High-End Setup (RTX A6000 / AMD W7900 / Intel Max 1100 - 48GB)

```bash
# Load multiple models concurrently
OLLAMA_SECURITY_LLM=granite-code:34b           # 18GB
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # 12GB
OLLAMA_FRAMEWORK_LLM=codestral:22b             # 13GB
OLLAMA_IAC_LLM=granite-code:20b                # 12GB (shared)
OLLAMA_FALLBACK_LLM=starcoder2:15b             # 9GB

# Concurrent execution
OLLAMA_MAX_LOADED_MODELS=3
OLLAMA_NUM_PARALLEL=2

REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
```

**Cost**: $3,500-4,500
**Performance**: 15-25 tokens/sec, 12-15 reviews/hour

---

### Example 4: Enterprise Setup (A100 80GB / MI300X 192GB)

```bash
# Load ALL recommended models
OLLAMA_SECURITY_LLM=granite-code:34b           # 18GB
OLLAMA_BEST_PRACTICES_LLM=llama3.3:70b         # 40GB (Q4 quant)
OLLAMA_FRAMEWORK_LLM=codestral:22b             # 13GB
OLLAMA_IAC_LLM=granite-code:20b                # 12GB
OLLAMA_FALLBACK_LLM=starcoder2:15b             # 9GB

# High concurrency
OLLAMA_MAX_LOADED_MODELS=5
OLLAMA_NUM_PARALLEL=4
OLLAMA_GPU_MEMORY_FRACTION=0.95

REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
```

**Cost**: $10,000+ (NVIDIA), $8,000+ (AMD), $8,000+ (Intel)
**Performance**: 30-50 tokens/sec, 20-25 reviews/hour

---

## Review Category Configuration

### Via Environment Variables

```bash
# Enable/disable categories globally
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true

# Configure models per category
OLLAMA_SECURITY_LLM=granite-code:34b
OLLAMA_BEST_PRACTICES_LLM=llama3.3:70b
OLLAMA_FRAMEWORK_LLM=codestral:22b
OLLAMA_IAC_LLM=granite-code:20b
OLLAMA_FALLBACK_LLM=starcoder2:15b
OLLAMA_DEFAULT_LLM=granite-code:20b
```

### Via WebUI

Navigate to **Settings > AI Models** to configure:

- ✅ **Security Reviews**: Vulnerability detection (OWASP Top 10, SQL injection, XSS)
- ✅ **Best Practices**: Design patterns and code quality
- ✅ **Framework Reviews**: Framework-specific anti-patterns
- ✅ **IaC Reviews**: Infrastructure as Code best practices

### Via API

```bash
curl -X POST /api/v1/reviews \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "myorg/myrepo",
    "pr_number": 123,
    "categories": ["security", "iac"],
    "ai_provider": "ollama"
  }'
```

---

## Performance Tuning

### NVIDIA-Specific Optimizations

```bash
# Enable flash attention (faster inference)
OLLAMA_FLASH_ATTENTION=true

# GPU settings
OLLAMA_NUM_GPU=1
OLLAMA_GPU_MEMORY_FRACTION=0.9

# CUDA optimization
CUDA_VISIBLE_DEVICES=0
```

### AMD ROCm Optimizations

```bash
# ROCm configuration
export HSA_OVERRIDE_GFX_VERSION=11.0.0        # For RX 7000 series
export ROCM_PATH=/opt/rocm
export HIP_VISIBLE_DEVICES=0

# Ollama with ROCm
OLLAMA_GPU_DRIVER=rocm
OLLAMA_NUM_GPU=1
```

### Intel oneAPI Optimizations

```bash
# Intel Extension for PyTorch (IPEX)
export ONEAPI_DEVICE_SELECTOR=level_zero:0

# Ollama with Intel
OLLAMA_GPU_DRIVER=level_zero
OLLAMA_NUM_GPU=1
```

---

## Multi-GPU Configurations

### Dual GPU Setups

**Budget**: 2x RX 7600 XT (32GB total) - $660
```bash
OLLAMA_NUM_GPU=2
# GPU 0: Security
OLLAMA_SECURITY_LLM=granite-code:34b           # 18GB on GPU 0
# GPU 1: Everything else
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b     # 12GB on GPU 1
```

**Performance**: 2x RTX 4090 (48GB total) - $3,200
```bash
OLLAMA_NUM_GPU=2
# Load balance all models
```

**Enterprise**: 2x AMD MI300X (384GB total) - $16,000+
```bash
OLLAMA_NUM_GPU=2
# Run multiple 70B models simultaneously
```

---

## Quick Reference Table - Ollama Models by GPU

| GPU | Vendor | VRAM | Ollama Configuration | Concurrent Models | Price |
|-----|--------|------|---------------------|-------------------|-------|
| **Arc A580** | Intel | 8 GB | `granite:8b` only | 1 model | $180 |
| **RX 7600** | AMD | 8 GB | `granite:8b` only | 1 model | $250 |
| **RTX 4060** | NVIDIA | 8 GB | `granite:8b` only | 1 model | $300 |
| **RTX 3060** | NVIDIA | 12 GB | `granite:20b` (single) | 1 model | $200 (used) |
| **RX 7700 XT** | AMD | 12 GB | `granite:20b` (single) | 1 model | $400 |
| **RTX 4070** | NVIDIA | 12 GB | `granite:20b` (single) | 1 model | $600 |
| **Arc A770 16GB** | Intel | 16 GB | `granite:20b` + `starcoder2:15b` | 1 at a time | $350 |
| **RX 7600 XT** | AMD | 16 GB | `granite:20b` + `starcoder2:15b` | 1 at a time | $330 |
| **RTX 4060 Ti 16GB** | NVIDIA | 16 GB | `granite:20b` + `starcoder2:15b` | 1 at a time | $500 |
| **RTX 3090** | NVIDIA | 24 GB | `granite:34b`, `codestral:22b` (swap) | 1 at a time | $900 (used) |
| **RX 7900 XTX** | AMD | 24 GB | `granite:34b`, `codestral:22b` (swap) | 1 at a time | $900 |
| **RTX 4090** | NVIDIA | 24 GB | `granite:34b`, `codestral:22b` (swap) | 1 at a time | $1,600 |
| **Radeon PRO W7800** | AMD | 32 GB | `granite:34b` + `granite:20b` | 2 concurrent | $2,500 |
| **Radeon PRO W7900** | AMD | 48 GB | All except `llama3.3:70b` | 2-3 concurrent | $3,500 |
| **RTX A6000** | NVIDIA | 48 GB | All except `llama3.3:70b` | 2-3 concurrent | $4,500 |
| **Intel Max 1100** | Intel | 48 GB | All except `llama3.3:70b` | 2-3 concurrent | ~$4,000 |
| **MI210** | AMD | 64 GB | All + `llama3.3:70b-q4` | 3-4 concurrent | $5-7K |
| **A100 40GB** | NVIDIA | 40 GB | All + `llama3.3:70b-q4` | 2-3 concurrent | $10K+ |
| **A100 80GB** | NVIDIA | 80 GB | All + `llama3.3:70b-q4` | 4-5 concurrent | $10K+ |
| **Intel Max 1350** | Intel | 96 GB | All + `llama3.3:70b-q4` | 4-5 concurrent | ~$8K |
| **MI300X** | AMD | 192 GB | All + `llama3.3:70b` (Q5/Q6) | 8+ concurrent | $15K+ |
| **Intel Max 1550** | Intel | 128 GB | All + `llama3.3:70b` (Q5/Q6) | 6-8 concurrent | ~$10K |

---

## Further Reading

- [AI Model Recommendations](ai-model-recommendations.md) - Model comparison and selection
- [Ollama Setup Guide](ollama-setup.md) - Installation and configuration
- [ROCm Installation](https://rocm.docs.amd.com/) - AMD GPU setup
- [Intel oneAPI](https://www.intel.com/content/www/us/en/developer/tools/oneapi/overview.html) - Intel GPU setup

---

**Last Updated**: 2025-01-08
**Maintained by**: Darwin PR Reviewer Team
