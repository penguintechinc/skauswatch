# Darwin - Configuration Reference

**Audience:** DevOps | Admins

---

## ⚙️ Environment Variables

Darwin configuration is managed entirely through environment variables. All variables are optional unless marked **REQUIRED**.

### AI Provider Selection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DARWIN_AI_PROVIDER` | ✅ YES | — | AI backend to use: `claude`, `openai`, or `ollama` |
| `DARWIN_FALLBACK_PROVIDER` | ❌ NO | — | Fallback provider if primary fails |

---

## 🤖 Anthropic Claude Configuration

**Required when**: `DARWIN_AI_PROVIDER=claude`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | ✅ YES | — | API key from https://console.anthropic.com |
| `ANTHROPIC_SECURITY_MODEL` | ❌ NO | `claude-sonnet-4-5-20250514` | Model for security reviews |
| `ANTHROPIC_BEST_PRACTICES_MODEL` | ❌ NO | `claude-sonnet-4-5-20250514` | Model for best practices |
| `ANTHROPIC_FRAMEWORK_MODEL` | ❌ NO | `claude-sonnet-4-5-20250514` | Model for framework reviews |
| `ANTHROPIC_IAC_MODEL` | ❌ NO | `claude-sonnet-4-5-20250514` | Model for IaC reviews |
| `ANTHROPIC_TIMEOUT_SECONDS` | ❌ NO | `60` | API request timeout |
| `ANTHROPIC_MAX_RETRIES` | ❌ NO | `3` | Retry attempts on failure |

**Available Models** (as of March 2025):
- `claude-opus-4-5-20251101` (highest quality, slowest, most expensive)
- `claude-sonnet-4-5-20250514` (recommended: balanced)
- `claude-haiku-4-20250514` (fastest, cheapest, acceptable quality)
- `claude-3-5-sonnet-20241022` (legacy)

---

## 🤖 OpenAI Configuration

**Required when**: `DARWIN_AI_PROVIDER=openai`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | ✅ YES | — | API key from https://platform.openai.com/api-keys |
| `OPENAI_SECURITY_MODEL` | ❌ NO | `gpt-4o` | Model for security reviews |
| `OPENAI_BEST_PRACTICES_MODEL` | ❌ NO | `gpt-4o` | Model for best practices |
| `OPENAI_FRAMEWORK_MODEL` | ❌ NO | `gpt-4o` | Model for framework reviews |
| `OPENAI_IAC_MODEL` | ❌ NO | `gpt-4o` | Model for IaC reviews |
| `OPENAI_TIMEOUT_SECONDS` | ❌ NO | `60` | API request timeout |
| `OPENAI_MAX_RETRIES` | ❌ NO | `3` | Retry attempts on failure |
| `OPENAI_ORG_ID` | ❌ NO | — | Organization ID (if using org account) |

**Available Models**:
- `gpt-4-turbo` (highest quality, expensive)
- `gpt-4o` (recommended: good balance)
- `gpt-4o-mini` (cheapest, still capable)
- `o1-preview`, `o1-mini` (advanced reasoning for complex reviews)

---

## 🦙 Ollama Configuration

**Required when**: `DARWIN_AI_PROVIDER=ollama`

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OLLAMA_URL` | ✅ YES | — | Ollama endpoint: `http://ollama:11434` or `http://localhost:11434` |
| `OLLAMA_SECURITY_LLM` | ❌ NO | `granite-code:34b` | Model for security reviews |
| `OLLAMA_BEST_PRACTICES_LLM` | ❌ NO | `granite-code:20b` | Model for best practices |
| `OLLAMA_FRAMEWORK_LLM` | ❌ NO | `codestral:22b` | Model for framework reviews |
| `OLLAMA_IAC_LLM` | ❌ NO | `granite-code:20b` | Model for IaC reviews |
| `OLLAMA_FALLBACK_LLM` | ❌ NO | `starcoder2:7b` | Fallback model if primary not loaded |
| `OLLAMA_TIMEOUT_SECONDS` | ❌ NO | `120` | Model inference timeout |
| `OLLAMA_MAX_RETRIES` | ❌ NO | `2` | Retry attempts on failure |
| `OLLAMA_NUM_PARALLEL` | ❌ NO | `1` | Concurrent model inference requests |
| `OLLAMA_KEEP_ALIVE` | ❌ NO | `5m` | Keep model in memory for 5 minutes |

**Recommended Models**:
- `granite-code:34b` — General-purpose, high quality
- `granite-code:20b` — Balanced quality/speed
- `codestral:22b` — Good at framework patterns
- `llama3.3:70b` — Highest quality (requires high VRAM)
- `starcoder2:7b` — Lightweight fallback

---

## 🔐 Webhook Secrets

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DARWIN_GITHUB_WEBHOOK_SECRET` | ✅ YES | — | Secret for GitHub webhook validation (minimum 32 chars) |
| `DARWIN_GITLAB_WEBHOOK_SECRET` | ✅ YES | — | Secret for GitLab webhook validation (minimum 32 chars) |

**Generation** (generate a random secret):
```bash
openssl rand -hex 32
# or
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📋 Review Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REVIEW_SECURITY_ENABLED` | ❌ NO | `true` | Enable security review category |
| `REVIEW_BEST_PRACTICES_ENABLED` | ❌ NO | `true` | Enable best practices category |
| `REVIEW_FRAMEWORK_ENABLED` | ❌ NO | `true` | Enable framework review category |
| `REVIEW_IAC_ENABLED` | ❌ NO | `true` | Enable IaC review category |
| `REVIEW_MAX_DIFF_SIZE_KB` | ❌ NO | `500` | Max PR diff size to analyze (KB) |
| `REVIEW_MIN_CONFIDENCE` | ❌ NO | `0.7` | Minimum confidence to include finding (0.0-1.0) |

---

## 💰 Cost & Rate Controls

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DARWIN_MAX_REVIEWS_PER_DAY` | ❌ NO | `1000` | Daily review limit per tenant |
| `DARWIN_MAX_MONTHLY_COST_UUSD` | ❌ NO | `100000` | Monthly cost limit in 1/100th USD (default: $1000) |
| `DARWIN_RATE_LIMIT_REQUESTS_PER_MINUTE` | ❌ NO | `60` | API rate limit (requests/minute) |

**Cost Unit** (UUSD):
- 1 UUSD = 1/100th of a US dollar = 1 cent
- `100000` UUSD = $1000
- `5000` UUSD = $50

---

## 🗄️ Database Configuration

**Shared with SkausWatch core**.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_TYPE` | ✅ YES | — | `postgresql`, `mysql`, or `sqlite` |
| `DB_HOST` | ✅ YES | — | Database hostname or IP |
| `DB_PORT` | ❌ NO | `5432` | Database port |
| `DB_NAME` | ✅ YES | — | Database name |
| `DB_USER` | ✅ YES | — | Database username |
| `DB_PASS` | ✅ YES | — | Database password |
| `DB_POOL_SIZE` | ❌ NO | `20` | Connection pool size |
| `DB_MAX_RETRIES` | ❌ NO | `5` | Retry attempts on connection failure |
| `DB_RETRY_DELAY` | ❌ NO | `5` | Delay between retries (seconds) |

---

## 📬 Redis Configuration

**Shared with SkausWatch core**.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_URL` | ✅ YES | — | Redis connection: `redis://host:port/db` |
| `REDIS_KEY_PREFIX` | ❌ NO | `darwin:` | Key prefix for Darwin data |
| `REDIS_TIMEOUT_SECONDS` | ❌ NO | `10` | Connection timeout |

---

## 🔐 License Server

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LICENSE_KEY` | ✅ YES | — | PenguinTech license key (format: `PENG-XXXX-XXXX-XXXX-XXXX-ABCD`) |
| `LICENSE_SERVER_URL` | ❌ NO | `https://license.penguintech.io` | License server endpoint |
| `RELEASE_MODE` | ❌ NO | `false` | Enable license validation (`true` for production) |

---

## 📊 Logging & Monitoring

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_LEVEL` | ❌ NO | `info` | Log level: `debug`, `info`, `warning`, `error` |
| `LOG_FORMAT` | ❌ NO | `json` | Log format: `json` or `text` |
| `METRICS_PORT` | ❌ NO | `9090` | Prometheus metrics port |
| `HEALTH_CHECK_INTERVAL` | ❌ NO | `30` | Health check interval (seconds) |

---

## 📝 Example Configuration Files

### Development (.env.local)

```bash
# AI Provider
DARWIN_AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_SECURITY_LLM=granite-code:8b
OLLAMA_BEST_PRACTICES_LLM=granite-code:8b
OLLAMA_FRAMEWORK_LLM=starcoder2:7b
OLLAMA_IAC_LLM=granite-code:8b

# Webhooks
DARWIN_GITHUB_WEBHOOK_SECRET=local-dev-secret-12345678901234567890
DARWIN_GITLAB_WEBHOOK_SECRET=local-dev-secret-12345678901234567890

# Database
DB_TYPE=postgresql
DB_HOST=postgres
DB_PORT=5432
DB_NAME=skauswatch
DB_USER=dev
DB_PASS=dev123
DB_POOL_SIZE=5

# Redis
REDIS_URL=redis://redis:6379/0

# License
LICENSE_KEY=PENG-DEV0-LOCAL-TRIAL-0000-ABCD
RELEASE_MODE=false

# Logging
LOG_LEVEL=debug
```

### Production (.env.prod)

```bash
# AI Provider
DARWIN_AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4-20250514
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514

# Webhooks
DARWIN_GITHUB_WEBHOOK_SECRET=generated-secure-32-character-secret-xxxx
DARWIN_GITLAB_WEBHOOK_SECRET=generated-secure-32-character-secret-xxxx

# Reviews
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
REVIEW_MAX_DIFF_SIZE_KB=1000

# Cost Controls
DARWIN_MAX_REVIEWS_PER_DAY=500
DARWIN_MAX_MONTHLY_COST_UUSD=50000  # $500/month

# Database
DB_TYPE=postgresql
DB_HOST=prod-db.internal
DB_PORT=5432
DB_NAME=skauswatch_prod
DB_USER=darwin_prod_user
DB_PASS=very-secure-password-here
DB_POOL_SIZE=30

# Redis
REDIS_URL=redis://prod-redis.internal:6379/1

# License
LICENSE_KEY=PENG-PROD-XXXXX-XXXXX-XXXXX-XXXXX
RELEASE_MODE=true

# Logging
LOG_LEVEL=warning
```

### Cost-Conscious (Budget Mode)

```bash
# AI Provider - Use cheapest models
DARWIN_AI_PROVIDER=openai
OPENAI_API_KEY=sk-xxxxxxxx
OPENAI_SECURITY_MODEL=gpt-4o-mini         # $0.15/$0.60 per 1M tokens
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini
OPENAI_FRAMEWORK_MODEL=gpt-4o-mini
OPENAI_IAC_MODEL=gpt-4o-mini

# Limit reviews
DARWIN_MAX_REVIEWS_PER_DAY=50
DARWIN_MAX_MONTHLY_COST_UUSD=10000  # $100/month

# Disable non-critical categories
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=false
REVIEW_FRAMEWORK_ENABLED=false
REVIEW_IAC_ENABLED=false
```

---

## 🔧 Configuration Validation

Validate your configuration before deployment:

```bash
# Check all required variables are set
python3 -c "
import os
required = ['DARWIN_AI_PROVIDER', 'DARWIN_GITHUB_WEBHOOK_SECRET',
            'DARWIN_GITLAB_WEBHOOK_SECRET', 'DB_HOST', 'REDIS_URL']
missing = [v for v in required if not os.getenv(v)]
print(f'Missing: {missing}' if missing else 'All required vars set ✓')
"

# Validate API keys format
python3 -c "
import os
key = os.getenv('ANTHROPIC_API_KEY', '')
if key and not key.startswith('sk-ant-'):
    print('⚠️ ANTHROPIC_API_KEY may be invalid (should start with sk-ant-)')
else:
    print('✓ ANTHROPIC_API_KEY format ok')
"
```

---

## 🔄 Runtime Configuration Changes

Some variables can be updated without restart:

| Variable | Requires Restart | Notes |
|----------|------------------|-------|
| `LOG_LEVEL` | ❌ NO | Takes effect immediately |
| `REVIEW_*_ENABLED` | ❌ NO | New reviews use updated setting |
| `DARWIN_MAX_REVIEWS_PER_DAY` | ❌ NO | Next day uses new limit |
| `DARWIN_MAX_MONTHLY_COST_UUSD` | ❌ NO | Next check uses new limit |
| `DARWIN_AI_PROVIDER` | ✅ YES | Provider change requires restart |
| `ANTHROPIC_API_KEY` | ✅ YES | API key change requires restart |
| Database variables | ✅ YES | Connection string change requires restart |

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
