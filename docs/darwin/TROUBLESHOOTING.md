# Darwin - Troubleshooting Guide

**Audience:** DevOps | Admins | Developers

---

## 🔍 Common Issues & Solutions

---

## ❌ Webhooks Not Triggering

### Symptom
GitHub/GitLab pushes events, but Darwin doesn't create reviews.

### Diagnosis

**Step 1: Verify webhook delivery**

1. Go to GitHub repo → Settings → Webhooks
2. Click the webhook URL
3. Scroll to "Recent Deliveries"
4. Check if latest delivery succeeded (green checkmark)
5. Click delivery to see request/response details

If red X, check the error response.

**Step 2: Check webhook secret**

```bash
# Verify secret matches environment variable
echo $DARWIN_GITHUB_WEBHOOK_SECRET

# Verify in GitHub: Settings > Webhooks > Edit
# Secret field should match exactly (case-sensitive)
```

### Solutions

| Issue | Solution |
|-------|----------|
| **Webhook secret mismatch** | Update secret in GitHub to match `DARWIN_GITHUB_WEBHOOK_SECRET`, or vice versa |
| **Wrong endpoint URL** | Verify `https://your-darwin/api/v1/webhooks/github` is correct |
| **Darwin not running** | Check service logs: `kubectl logs -l app=darwin-backend -n skauswatch` |
| **Network unreachable** | Verify GitHub can reach your Darwin instance (check firewall rules, DNS) |
| **CORS/TLS errors** | Ensure Darwin has valid HTTPS certificate |

### Debugging

Enable debug logging:

```bash
# Set log level to debug
kubectl set env deployment/darwin-backend LOG_LEVEL=debug -n skauswatch

# Tail logs
kubectl logs -f -l app=darwin-backend -n skauswatch | grep -i webhook

# Look for signature verification messages
# Should see: "Webhook signature verified" or "Invalid signature"
```

---

## ❌ Reviews Not Posting Comments

### Symptom
Review is created (status=completed), but no comment appears on PR.

### Diagnosis

**Step 1: Check review status**

```bash
# Query database
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT id, status, created_at FROM reviews WHERE pr_number=42 LIMIT 5;"
```

If status is `failed`, review the error:

```bash
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT error_message FROM reviews WHERE pr_number=42;"
```

**Step 2: Check Celery worker logs**

```bash
# Tail worker logs
kubectl logs -f -l app=darwin-worker -n skauswatch

# Look for failures:
# - "GitHub API error"
# - "GitLab API error"
# - "Comment posting failed"
```

**Step 3: Verify GitHub/GitLab token**

```bash
# Test GitHub API access
curl -H "Authorization: token YOUR_GITHUB_TOKEN" \
  https://api.github.com/repos/yourorg/yourrepo

# Test GitLab API access
curl -H "PRIVATE-TOKEN: YOUR_GITLAB_TOKEN" \
  https://gitlab.com/api/v4/projects/yourorg%2Fyourrepo
```

### Solutions

| Issue | Solution |
|-------|----------|
| **Missing GitHub token** | Set `GITHUB_API_TOKEN` env var in Darwin backend |
| **Invalid/expired token** | Regenerate token on GitHub/GitLab settings |
| **Insufficient permissions** | Token needs `repo:write` (GitHub) or `api+write_repository` (GitLab) |
| **Celery worker not running** | Check: `kubectl get pods -n skauswatch -l app=darwin-worker` |
| **Rate limit hit** | Wait 1 hour or use a token with higher rate limits |

---

## ❌ High Latency / Slow Reviews

### Symptom
Reviews take 5-10 minutes to complete, or timeout.

### Diagnosis

**Step 1: Check AI provider response time**

```bash
# Add timing logs (in review_worker.py)
import time
start = time.time()
result = provider.analyze_diff(diff)
elapsed = time.time() - start
logger.info(f"AI analysis took {elapsed:.2f}s")
```

**Step 2: Check Celery queue depth**

```bash
# View pending jobs
redis-cli llen darwin:queue:review

# Check if workers are processing
kubectl logs -l app=darwin-worker -n skauswatch | grep "Processing"
```

**Step 3: Check AI provider rate limits**

```bash
# For Claude
kubectl logs -l app=darwin-worker | grep -i "rate limit\|quota"

# For OpenAI
# Check usage at https://platform.openai.com/account/billing/overview
```

### Solutions

| Cause | Solution |
|-------|----------|
| **AI provider slow** | Switch to faster model (Claude Haiku, GPT-4o Mini) |
| **Rate limit** | Upgrade API plan, reduce `DARWIN_MAX_REVIEWS_PER_DAY` |
| **Queue overloaded** | Scale Celery workers: `kubectl scale deployment/darwin-worker --replicas=3` |
| **Large diff** | Increase `REVIEW_MAX_DIFF_SIZE_KB` or summarize diff first |
| **Network latency** | Verify Darwin → AI provider network latency |

### Performance Optimization

```bash
# Use faster models for less critical reviews
OPENAI_SECURITY_MODEL=gpt-4o                # Standard
OPENAI_BEST_PRACTICES_MODEL=gpt-4o-mini     # Faster, cheaper
OPENAI_FRAMEWORK_MODEL=gpt-4o-mini          # Faster
OPENAI_IAC_MODEL=gpt-4o                     # Keep thorough

# Or with Claude:
ANTHROPIC_SECURITY_MODEL=claude-sonnet-4-5      # Important
ANTHROPIC_BEST_PRACTICES_MODEL=claude-haiku-4   # Fast
ANTHROPIC_FRAMEWORK_MODEL=claude-haiku-4        # Fast
ANTHROPIC_IAC_MODEL=claude-sonnet-4-5           # Thorough
```

---

## 💰 Cost Overruns

### Symptom
Monthly AI cost exceeds budget or hits limit.

### Diagnosis

**Step 1: Calculate current usage**

```bash
# Query cost from database
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT SUM(cost_uusd) as total_cost_cents, COUNT(*) as review_count \
   FROM reviews WHERE created_at > NOW() - INTERVAL '30 days';"
```

Cost in USD = (total_cost_cents / 100)

**Step 2: Check which categories consume most**

```bash
# Most reviews by category
kubectl logs -l app=darwin-worker -n skauswatch | \
  grep -i "security\|framework\|best_practices\|iac" | \
  sort | uniq -c | sort -rn
```

**Step 3: Identify expensive model**

Claude Sonnet: $3/$15 per 1M tokens
Claude Opus: $15/$75 per 1M tokens
GPT-4o: $2.50/$10 per 1M tokens
GPT-4o Mini: $0.15/$0.60 per 1M tokens

### Solutions

| Issue | Solution |
|-------|----------|
| **Using expensive model** | Switch to cheaper: Claude Haiku, GPT-4o Mini |
| **Analyzing too many reviews** | Reduce `DARWIN_MAX_REVIEWS_PER_DAY` or scope to high-value repos only |
| **Large diffs** | Reduce `REVIEW_MAX_DIFF_SIZE_KB` to skip large changesets |
| **All categories enabled** | Disable less-critical: `REVIEW_IAC_ENABLED=false` |

---

## 🛑 "Cost Limit Exceeded" Error

### Symptom
Reviews fail with "Monthly cost limit reached" message.

### Solution

1. **Increase limit** (temporary):
   ```bash
   kubectl set env deployment/darwin-backend \
     DARWIN_MAX_MONTHLY_COST_UUSD=100000 \
     -n skauswatch
   ```

2. **Or reduce usage** (permanent):
   ```bash
   # Lower daily limit
   DARWIN_MAX_REVIEWS_PER_DAY=50

   # Or switch to cheaper provider
   DARWIN_AI_PROVIDER=openai
   OPENAI_SECURITY_MODEL=gpt-4o-mini
   ```

---

## 🔌 Ollama Connectivity Issues

### Symptom
Reviews fail with "Ollama connection refused" or "Model not found".

### Diagnosis

**Step 1: Verify Ollama is running**

```bash
# Check if Ollama pod exists
kubectl get pods -n skauswatch -l app=ollama

# Or if running locally:
curl http://localhost:11434/api/tags

# Should return JSON list of models
```

**Step 2: Check DNS/network**

```bash
# From Darwin pod, test connectivity
kubectl exec -it pod/darwin-backend-xxx -n skauswatch -- \
  curl http://ollama:11434/api/tags

# Should work if Ollama is in same namespace
```

**Step 3: Verify model is loaded**

```bash
# List available models
curl http://localhost:11434/api/tags | jq '.models[].name'

# Expected: granite-code:34b, granite-code:20b, codestral:22b, etc.
```

### Solutions

| Issue | Solution |
|-------|----------|
| **Ollama not running** | Deploy Ollama: `kubectl apply -f k8s/ollama-deployment.yaml` |
| **Wrong URL** | Set `OLLAMA_URL=http://ollama:11434` (or `http://localhost:11434` if local) |
| **Model not found** | Pull model: `curl -X POST http://ollama:11434/api/pull -d '{"name":"granite-code:20b"}'` |
| **Network unreachable** | Check firewall/network policy, ensure same K8s namespace |
| **OOM (Out of Memory)** | Reduce model size: use 7B instead of 34B |

---

## 📊 High Disk Usage

### Symptom
Database or logs consuming large disk space.

### Diagnosis

**Step 1: Check database size**

```bash
# PostgreSQL
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT pg_size_pretty(pg_database_size('skauswatch'));"
```

**Step 2: Identify large tables**

```bash
# Reviews table
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT pg_size_pretty(pg_total_relation_size('reviews'));"
```

**Step 3: Check log volume**

```bash
# Logs by pod
kubectl logs -l app=darwin-backend -n skauswatch --tail=10000 | wc -l

# Archive old logs
kubectl logs -l app=darwin-backend -n skauswatch \
  --timestamps=true --all-containers=true > /tmp/darwin-logs.txt
```

### Solutions

| Issue | Solution |
|-------|----------|
| **Old reviews in DB** | Archive old reviews: `DELETE FROM reviews WHERE created_at < NOW() - INTERVAL '90 days'` |
| **Verbose logging** | Reduce log level: `LOG_LEVEL=warning` instead of `debug` |
| **Large diffs in DB** | Avoid storing full diff: store only summary or delete after review |

---

## 🔐 Authentication / Permission Issues

### Symptom
API returns 401 Unauthorized or 403 Forbidden.

### Diagnosis

**Step 1: Check JWT token**

```bash
# Decode JWT (on https://jwt.io)
# Look for: exp (expiration), tenant_id, roles

# Or decode in Python:
python3 -c "import jwt; print(jwt.decode('token', options={'verify_signature': False}))"
```

**Step 2: Verify GitHub/GitLab token**

```bash
# Test GitHub token
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/user

# Test GitLab token
curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  https://gitlab.com/api/v4/user
```

### Solutions

| Issue | Solution |
|-------|----------|
| **Expired JWT** | Token expires after 1 hour; re-authenticate |
| **Invalid token** | Check `Authorization` header format: `Bearer <token>` |
| **Insufficient scopes** | Regenerate GitHub token with `repo:write` scope |
| **Missing GITHUB_API_TOKEN** | Set env var for comment posting |

---

## 🧠 AI Provider API Errors

### Claude / Anthropic Errors

```
401 Unauthorized → Invalid ANTHROPIC_API_KEY
429 Rate Limited → Reduce request frequency or upgrade plan
500 Server Error → Anthropic service issue, retry later
Timeout → Model overloaded, increase ANTHROPIC_TIMEOUT_SECONDS
```

### OpenAI Errors

```
401 Unauthorized → Invalid OPENAI_API_KEY
429 Rate Limited → Quota exceeded, reduce requests or upgrade billing
500 Server Error → OpenAI service issue, retry later
Context Length → Diff too large, reduce REVIEW_MAX_DIFF_SIZE_KB
```

### Ollama Errors

```
Connection Refused → Ollama not running, check deployment
Model Not Found → Pull model with curl command
OOM (Out of Memory) → Model too large for available VRAM
Timeout → Model inference slow, increase OLLAMA_TIMEOUT_SECONDS
```

---

## 📈 Monitoring & Health Checks

### Health Check Endpoint

```bash
# Check Darwin health
curl http://localhost:5000/healthz

# Expected output:
# {
#   "status": "healthy",
#   "database": "connected",
#   "redis": "connected",
#   "ai_provider": "connected"
# }
```

### Prometheus Metrics

```bash
# View metrics
curl http://localhost:9090/metrics | grep darwin

# Key metrics:
darwin_reviews_total              # Total reviews
darwin_reviews_duration_seconds   # Processing time
darwin_ai_tokens_used             # Token consumption
darwin_celery_queue_size          # Pending jobs
darwin_webhook_errors_total       # Webhook failures
```

---

## 🆘 When All Else Fails

### Gather Diagnostic Information

```bash
# Collect all logs
mkdir -p /tmp/darwin-diagnostics

# Backend logs
kubectl logs -l app=darwin-backend -n skauswatch > \
  /tmp/darwin-diagnostics/backend.log

# Worker logs
kubectl logs -l app=darwin-worker -n skauswatch > \
  /tmp/darwin-diagnostics/worker.log

# Database logs
kubectl logs -l app=postgres -n skauswatch > \
  /tmp/darwin-diagnostics/postgres.log

# Recent reviews
kubectl exec -it pod/postgres-xxx -n skauswatch -- \
  psql -U skauswatch -d skauswatch -c \
  "SELECT id, status, error_message, created_at FROM reviews ORDER BY created_at DESC LIMIT 50;" > \
  /tmp/darwin-diagnostics/recent-reviews.txt

# Config
env | grep DARWIN > /tmp/darwin-diagnostics/config.env

# Share with support
tar -czf darwin-diagnostics.tar.gz /tmp/darwin-diagnostics/
# Send to support@penguintech.io
```

### Contact Support

Email: support@penguintech.io

Include:
- Diagnostic tarball (see above)
- What you were trying to do
- Error message or unexpected behavior
- Steps to reproduce

---

**Last Updated**: 2025-03-10
**Version**: 1.0.0
