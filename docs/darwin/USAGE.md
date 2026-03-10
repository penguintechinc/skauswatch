# Darwin - Usage Guide

**Audience:** Developers | DevOps | Admins

---

## 📋 Prerequisites

Before deploying Darwin, ensure you have:

### Required
- ✅ SkausWatch v1.x deployed (core services running)
- ✅ PostgreSQL 15+ (shared with SkausWatch)
- ✅ Redis 7+ (shared with SkausWatch)
- ✅ At least one AI provider configured:
  - **Claude**: Anthropic API key (https://console.anthropic.com)
  - **OpenAI**: OpenAI API key (https://platform.openai.com/api-keys)
  - **Ollama**: Self-hosted Ollama instance (http://ollama:11434)
- ✅ GitHub/GitLab repository webhook credentials
- ✅ PenguinTech license with `darwin` feature enabled

### Optional
- 📦 GPU (for local Ollama): NVIDIA/AMD/Intel GPU (see [OVERVIEW.md](./OVERVIEW.md))
- 📊 Grafana: For monitoring Darwin metrics

---

## ⚙️ Configuration Steps

### Step 1: Set Environment Variables

Create `.env` file in Darwin service root with required variables:

```bash
# AI Provider Selection
DARWIN_AI_PROVIDER=claude              # claude | openai | ollama

# Anthropic/Claude (if provider=claude)
ANTHROPIC_API_KEY=sk-ant-xxxxxxxx
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_BEST_PRACTICES_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_FRAMEWORK_MODEL=claude-sonnet-4-5-20250514
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5-20250514

# OpenAI (if provider=openai)
OPENAI_API_KEY=sk-xxxxxxxx
OPENAI_SECURITY_MODEL=gpt-4o
OPENAI_BEST_PRACTICES_MODEL=gpt-4o
OPENAI_FRAMEWORK_MODEL=gpt-4o
OPENAI_IAC_MODEL=gpt-4o

# Ollama (if provider=ollama)
OLLAMA_URL=http://ollama:11434
OLLAMA_SECURITY_LLM=granite-code:34b
OLLAMA_BEST_PRACTICES_LLM=granite-code:20b
OLLAMA_FRAMEWORK_LLM=codestral:22b
OLLAMA_IAC_LLM=granite-code:20b

# Webhook Secrets (must match GitHub/GitLab repo settings)
DARWIN_GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
DARWIN_GITLAB_WEBHOOK_SECRET=your-webhook-secret-here

# Review Configuration
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true

# Rate & Cost Controls
DARWIN_MAX_REVIEWS_PER_DAY=100
DARWIN_MAX_MONTHLY_COST_UUSD=10000

# Database (shared with SkausWatch)
DB_TYPE=postgresql
DB_HOST=postgres
DB_PORT=5432
DB_NAME=skauswatch
DB_USER=skauswatch
DB_PASS=xxxxx
DB_POOL_SIZE=20

# Redis (shared with SkausWatch)
REDIS_URL=redis://redis:6379/0
REDIS_KEY_PREFIX=darwin:

# License Server
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
LICENSE_SERVER_URL=https://license.penguintech.io
RELEASE_MODE=true
```

### Step 2: Configure GitHub Webhook

For each GitHub repository you want to review:

1. Go to **Settings > Webhooks > Add webhook**
2. **Payload URL**: `https://your-darwin-instance/api/v1/webhooks/github`
3. **Content type**: `application/json`
4. **Events**:
   - ✅ Pull requests
   - ✅ Issues
   - ❌ Pushes (not needed)
5. **Active**: ✅ Checked
6. **Secret**: Enter the value of `DARWIN_GITHUB_WEBHOOK_SECRET`

### Step 3: Configure GitLab Webhook

For each GitLab project:

1. Go to **Settings > Integrations > Webhooks**
2. **URL**: `https://your-darwin-instance/api/v1/webhooks/gitlab`
3. **Secret token**: Enter the value of `DARWIN_GITLAB_WEBHOOK_SECRET`
4. **Trigger events**:
   - ✅ Merge requests
   - ✅ Issues
   - ❌ Push events (not needed)
5. **Add webhook**

---

## 🚀 Deployment

### Local Development (K8s Alpha)

```bash
# 1. Build Docker image
docker build -t localhost:32000/darwin:latest ./services/worker-darwin
docker push localhost:32000/darwin:latest

# 2. Deploy via Kustomize
kubectl apply --context local-alpha -k k8s/kustomize/overlays/alpha

# 3. Verify deployment
kubectl --context local-alpha get pods -n skauswatch
kubectl --context local-alpha logs -n skauswatch -l app=darwin-backend --tail=50

# 4. Access WebUI
# http://darwin.localhost.local:3000
# Admin: admin@localhost.local / admin123
```

### Production (Helm)

```bash
# 1. Build and push to registry
docker build -t registry.example.com/darwin:1.0.0 ./services/worker-darwin
docker push registry.example.com/darwin:1.0.0

# 2. Update Helm values
# Edit k8s/helm/darwin/values-prod.yaml
# - Set image repository and tag
# - Set DARWIN_AI_PROVIDER and API keys
# - Set webhook secrets

# 3. Deploy via Helm
helm upgrade --install darwin ./k8s/helm/darwin \
  --kube-context prod-cluster \
  --namespace skauswatch \
  --values ./k8s/helm/darwin/values.yaml \
  --values ./k8s/helm/darwin/values-prod.yaml

# 4. Verify
helm status darwin --kube-context prod-cluster --namespace skauswatch
```

---

## 🧪 Testing the Setup

### Verify Webhook Connectivity

```bash
# Test webhook secret is valid
curl -X POST https://your-darwin-instance/api/v1/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=abc123" \
  -d '{
    "action": "opened",
    "pull_request": {
      "number": 1,
      "title": "Test PR",
      "body": "This is a test"
    },
    "repository": {
      "full_name": "yourorg/yourrepo",
      "html_url": "https://github.com/yourorg/yourrepo"
    }
  }'
```

### Trigger a Test Review

1. Fork a test repository
2. Create a new branch
3. Make a small code change
4. Open a PR
5. Watch for Darwin's comment within 2-5 minutes

### Check Logs

```bash
# Flask backend logs
kubectl --context local-alpha logs -n skauswatch -l app=darwin-backend -f

# Celery worker logs
kubectl --context local-alpha logs -n skauswatch -l app=darwin-worker -f

# Check review status
kubectl --context local-alpha exec -n skauswatch -it postgres-xxx -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT id, pr_number, status, created_at FROM reviews ORDER BY created_at DESC LIMIT 10;"
```

---

## 📊 Common Workflows

### Enable All Review Categories

Set environment variables and restart:

```bash
REVIEW_SECURITY_ENABLED=true
REVIEW_BEST_PRACTICES_ENABLED=true
REVIEW_FRAMEWORK_ENABLED=true
REVIEW_IAC_ENABLED=true
```

Then redeploy:

```bash
kubectl rollout restart deployment/darwin-backend -n skauswatch
```

### Switch AI Providers

Update `DARWIN_AI_PROVIDER` and restart:

```bash
# From Claude to OpenAI
DARWIN_AI_PROVIDER=openai
OPENAI_API_KEY=sk-xxx
kubectl set env deployment/darwin-backend DARWIN_AI_PROVIDER=openai -n skauswatch
kubectl set env deployment/darwin-backend OPENAI_API_KEY=sk-xxx -n skauswatch
kubectl rollout restart deployment/darwin-backend -n skauswatch
```

### Adjust Cost Controls

Update limits and take effect immediately:

```bash
# Daily limit
DARWIN_MAX_REVIEWS_PER_DAY=50

# Monthly cost limit (in 1/100th USD cents)
DARWIN_MAX_MONTHLY_COST_UUSD=5000  # $50/month

# Apply changes
kubectl set env deployment/darwin-backend \
  DARWIN_MAX_REVIEWS_PER_DAY=50 \
  DARWIN_MAX_MONTHLY_COST_UUSD=5000 \
  -n skauswatch
```

### View Dashboard

Access the Darwin WebUI:

```bash
# Alpha/Local
http://darwin.localhost.local:3000

# Beta
https://skauswatch.penguintech.cloud/darwin

# Production
https://skauswatch.app/darwin
```

Login with:
- **Email**: admin@localhost.local
- **Password**: admin123

---

## 🔧 Troubleshooting

### Webhooks not triggering

1. Verify webhook secret matches in GitHub/GitLab settings
2. Check Darwin backend logs: `kubectl logs -l app=darwin-backend -n skauswatch`
3. Test endpoint directly (see above)
4. Verify network connectivity: `kubectl exec -it pod/darwin-backend -- curl https://github.com`

### Reviews not posting comments

1. Check if GitHub/GitLab token has write access to repo
2. Verify repository is configured in Darwin WebUI
3. Check AI provider API key is valid
4. Review Celery worker logs: `kubectl logs -l app=darwin-worker -n skauswatch`

### High latency/timeout

1. Check AI provider rate limits (Claude, OpenAI limits)
2. Monitor token usage: `kubectl logs -l app=darwin-backend | grep tokens`
3. Increase Celery worker replicas if backlog exists
4. Consider switching to faster model (e.g., Claude Haiku instead of Opus)

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for more details.

---

## 📞 Next Steps

- 🏗️ Review [ARCHITECTURE.md](./ARCHITECTURE.md) for system design
- 🔌 Check [API.md](./API.md) for webhook endpoint details
- ⚙️ Explore [CONFIGURATION.md](./CONFIGURATION.md) for all env vars
- 🧪 Read [TESTING.md](./TESTING.md) for test patterns

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
