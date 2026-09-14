#!/usr/bin/env bash
# Zero-cost live-AWS smoke test for skauswatch_s3::credentials's two keyless
# identity paths: sts:AssumeRole (hybrid customer-role model) and
# sts:AssumeRoleWithWebIdentity (SPIFFE federation, dal2's IRSA equivalent —
# see docs/v2-port/aws-identity-runbook.md). This script owns all AWS
# infrastructure setup/teardown and JWT minting; crates/skauswatch-s3/tests/
# aws_live_identity.rs owns driving the two functions under test.
#
# Every resource created here is named "skauswatch-awslive-*" and is swept
# up by this script's own `on_exit` trap (below) even if it dies mid-run.
# Nothing here uses AWS resources that cost money beyond a handful of
# IAM/STS/S3 API calls (free tier covers all of it) — no EC2, no NAT, no
# data transfer of consequence.
#
# Usage: tests/smoke/aws_identity/run.sh
# Requires: aws CLI v2, openssl, curl — all invoked below. Credentials come
# only from AWS_SHARED_CREDENTIALS_FILE/AWS_PROFILE already exported by the
# caller; this script never accepts or prints key material.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REGION="us-east-1"
PREFIX="skauswatch-awslive"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/skauswatch-awslive.XXXXXX")"
STS_AUDIENCE="sts.amazonaws.com"
FEDERATED_SUBJECT="spiffe://penguintech.io/test/awslive"

AR_ROLE_NAME="${PREFIX}-arrole"
AR_EXTERNAL_ID="${PREFIX}-ext"
WID_ROLE_NAME="${PREFIX}-widrole"

log() { printf '[run.sh] %s\n' "$*" >&2; }

b64url() {
  base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

# ─── teardown: inline, self-contained, prefix-based sweep ──────────────────
# Runs unconditionally on exit (success, failure, or a bug above) so this
# script never depends on anything outside itself to clean up. Idempotent
# and safe to re-run — only ever touches "${PREFIX}-*" named resources.
# shellcheck disable=SC2317  # invoked only via the trap below; not dead code
teardown() {
  log "sweeping all ${PREFIX}-* AWS resources"
  local role pol ap arn b
  for role in $(aws iam list-roles --query "Roles[?starts_with(RoleName,'${PREFIX}')].RoleName" --output text 2>/dev/null); do
    for pol in $(aws iam list-role-policies --role-name "$role" --query 'PolicyNames' --output text 2>/dev/null); do
      aws iam delete-role-policy --role-name "$role" --policy-name "$pol" 2>/dev/null || true
    done
    for ap in $(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
      aws iam detach-role-policy --role-name "$role" --policy-arn "$ap" 2>/dev/null || true
    done
    aws iam delete-role --role-name "$role" 2>/dev/null && log "  deleted role $role"
  done
  for arn in $(aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text 2>/dev/null); do
    case "$arn" in
      *"$PREFIX"*)
        aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$arn" 2>/dev/null \
          && log "  deleted oidc provider $arn"
        ;;
    esac
  done
  for b in $(aws s3api list-buckets --query "Buckets[?starts_with(Name,'${PREFIX}')].Name" --output text 2>/dev/null); do
    aws s3 rm "s3://$b" --recursive >/dev/null 2>&1 || true
    aws s3api delete-bucket --bucket "$b" 2>/dev/null && log "  deleted bucket $b"
  done
  log "teardown sweep complete"
}

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

# ─── teardown: always runs, whatever happens above ─────────────────────────
TEST_EXIT_CODE=""
# shellcheck disable=SC2317  # invoked only via the trap below; not dead code
on_exit() {
  local rc=$?
  if [ -n "$TEST_EXIT_CODE" ]; then
    rc="$TEST_EXIT_CODE"
  fi
  log "tearing down all ${PREFIX}-* AWS resources (exit code so far: $rc)"
  teardown || log "WARNING: teardown sweep itself reported a failure — verify manually"
  rm -rf "$WORKDIR"
  exit "$rc"
}
trap on_exit EXIT

# ─── PATH 1 setup: sts:AssumeRole trusting our own ambient IAM identity ────
CALLER_ARN="$(aws sts get-caller-identity --query 'Arn' --output text)"
log "creating IAM role $AR_ROLE_NAME (sts:AssumeRole, trusts $CALLER_ARN)"

cat >"$WORKDIR/ar-trust-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "$CALLER_ARN" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "$AR_EXTERNAL_ID" }
      }
    }
  ]
}
EOF

AR_ROLE_ARN="$(aws iam create-role \
  --role-name "$AR_ROLE_NAME" \
  --assume-role-policy-document "file://$WORKDIR/ar-trust-policy.json" \
  --query 'Role.Arn' --output text)"
log "created $AR_ROLE_ARN"

# ─── PATH 2 setup: self-hosted OIDC issuer (S3-hosted JWKS) ────────────────
log "generating RSA keypair for the throwaway OIDC issuer"
openssl genrsa -out "$WORKDIR/oidc-key.pem" 2048 2>/dev/null

MODULUS_HEX="$(openssl rsa -in "$WORKDIR/oidc-key.pem" -noout -modulus | sed 's/^Modulus=//')"
# openssl's -modulus output is minimal hex (no ASN.1 sign-guard byte); pad
# to an even digit count if needed so xxd -r -p pairs hex digits into bytes
# correctly, then base64url-encode the resulting big-endian integer as the
# JWKS "n" value.
if [ $(( ${#MODULUS_HEX} % 2 )) -ne 0 ]; then
  MODULUS_HEX="0${MODULUS_HEX}"
fi
MODULUS_B64URL="$(printf '%s' "$MODULUS_HEX" | xxd -r -p | b64url)"
KID="$(openssl rand -hex 8)"

BUCKET="${PREFIX}-oidc-$(date +%s)-$(openssl rand -hex 4)"
ISSUER="https://${BUCKET}.s3.${REGION}.amazonaws.com"
ISSUER_HOST="${BUCKET}.s3.${REGION}.amazonaws.com"

log "creating public bucket $BUCKET to host the OIDC discovery doc + JWKS"
aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false

cat >"$WORKDIR/bucket-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadWellKnown",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET}/.well-known/*"
    }
  ]
}
EOF
# Bucket policy propagation across S3 is not always instantaneous —
# BlockPublicAcls/PublicAccessBlock and PutBucketPolicy can briefly race.
# Retry a handful of times before giving up.
policy_attempt=0
until aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$WORKDIR/bucket-policy.json" 2>"$WORKDIR/policy-err.log"; do
  policy_attempt=$((policy_attempt + 1))
  if [ "$policy_attempt" -ge 10 ]; then
    log "put-bucket-policy failed after $policy_attempt attempts:"
    cat "$WORKDIR/policy-err.log" >&2
    exit 1
  fi
  sleep 3
done

cat >"$WORKDIR/openid-configuration" <<EOF
{
  "issuer": "${ISSUER}",
  "jwks_uri": "${ISSUER}/.well-known/jwks.json",
  "authorization_endpoint": "${ISSUER}/authorize",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
EOF

cat >"$WORKDIR/jwks.json" <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "${KID}",
      "alg": "RS256",
      "n": "${MODULUS_B64URL}",
      "e": "AQAB"
    }
  ]
}
EOF

aws s3 cp "$WORKDIR/openid-configuration" \
  "s3://${BUCKET}/.well-known/openid-configuration" \
  --content-type application/json >/dev/null
aws s3 cp "$WORKDIR/jwks.json" \
  "s3://${BUCKET}/.well-known/jwks.json" \
  --content-type application/json >/dev/null

log "verifying the discovery doc + JWKS are publicly GET-able"
curl_attempt=0
until curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>"$WORKDIR/curl-err.log" \
   && curl -fsS "${ISSUER}/.well-known/jwks.json" >/dev/null 2>>"$WORKDIR/curl-err.log"; do
  curl_attempt=$((curl_attempt + 1))
  if [ "$curl_attempt" -ge 10 ]; then
    log "OIDC fixtures never became publicly readable:"
    cat "$WORKDIR/curl-err.log" >&2
    exit 1
  fi
  sleep 3
done
log "OIDC discovery doc + JWKS confirmed publicly readable at $ISSUER"

log "registering IAM OIDC provider for issuer $ISSUER"
# AWS requires (but does not validate, for amazonaws.com-hosted issuers) a
# thumbprint of the issuer's TLS chain root CA.
openssl s_client -servername "$ISSUER_HOST" -connect "${ISSUER_HOST}:443" -showcerts \
  </dev/null >"$WORKDIR/chain.txt" 2>/dev/null || true
awk '
  /-----BEGIN CERTIFICATE-----/ { start = NR }
  { buf[NR] = $0 }
  /-----END CERTIFICATE-----/ { last_start = start; last_end = NR }
  END { for (i = last_start; i <= last_end; i++) print buf[i] }
' "$WORKDIR/chain.txt" >"$WORKDIR/root.pem"
THUMBPRINT="$(openssl x509 -in "$WORKDIR/root.pem" -noout -fingerprint -sha1 \
  | sed 's/^.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')"

OIDC_PROVIDER_ARN="$(aws iam create-open-id-connect-provider \
  --url "$ISSUER" \
  --client-id-list "$STS_AUDIENCE" \
  --thumbprint-list "$THUMBPRINT" \
  --query 'OpenIDConnectProviderArn' --output text)"
log "created OIDC provider $OIDC_PROVIDER_ARN"

cat >"$WORKDIR/wid-trust-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "$OIDC_PROVIDER_ARN" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${ISSUER_HOST}:aud": "$STS_AUDIENCE",
          "${ISSUER_HOST}:sub": "$FEDERATED_SUBJECT"
        }
      }
    }
  ]
}
EOF

WID_ROLE_ARN="$(aws iam create-role \
  --role-name "$WID_ROLE_NAME" \
  --assume-role-policy-document "file://$WORKDIR/wid-trust-policy.json" \
  --query 'Role.Arn' --output text)"
log "created $WID_ROLE_ARN"

log "minting an RS256 JWT (aud=$STS_AUDIENCE, sub=$FEDERATED_SUBJECT) signed by the throwaway issuer key"
NOW="$(date +%s)"
EXP="$((NOW + 900))"
HEADER_JSON="{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"${KID}\"}"
CLAIMS_JSON="{\"iss\":\"${ISSUER}\",\"sub\":\"${FEDERATED_SUBJECT}\",\"aud\":\"${STS_AUDIENCE}\",\"iat\":${NOW},\"nbf\":${NOW},\"exp\":${EXP}}"
HEADER_B64="$(printf '%s' "$HEADER_JSON" | b64url)"
CLAIMS_B64="$(printf '%s' "$CLAIMS_JSON" | b64url)"
SIGNING_INPUT="${HEADER_B64}.${CLAIMS_B64}"
SIGNATURE_B64="$(printf '%s' "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$WORKDIR/oidc-key.pem" | b64url)"
WID_TOKEN="${SIGNING_INPUT}.${SIGNATURE_B64}"

# ─── eventual-consistency gate: poll the real exchange until it succeeds ───
log "polling sts:AssumeRoleWithWebIdentity until IAM trust-policy/OIDC-provider propagation completes (up to 90s)"
propagated=0
for _ in $(seq 1 18); do
  if aws sts assume-role-with-web-identity \
       --role-arn "$WID_ROLE_ARN" \
       --role-session-name skauswatch-s3scan \
       --web-identity-token "$WID_TOKEN" \
       --query 'Credentials.AccessKeyId' --output text >/dev/null 2>"$WORKDIR/wid-probe-err.log"; then
    propagated=1
    break
  fi
  sleep 5
done
if [ "$propagated" -ne 1 ]; then
  log "assume-role-with-web-identity never succeeded after 90s — last error:"
  cat "$WORKDIR/wid-probe-err.log" >&2
  exit 1
fi
log "raw-CLI AssumeRoleWithWebIdentity probe succeeded — AWS accepts the minted token"

# ─── drive our own code against real STS ───────────────────────────────────
export AR_ROLE_ARN AR_EXTERNAL_ID WID_ROLE_ARN WID_TOKEN
export SKAUSWATCH_AWS_LIVE=1
# Honor caller-provided CARGO_HOME/CARGO_TARGET_DIR overrides; otherwise let
# cargo use its own defaults (~/.cargo, ./target) rather than hardcoding a
# scratch path that only exists in one environment.
: "${CARGO_HOME:=}"
: "${CARGO_TARGET_DIR:=}"
if [ -n "$CARGO_HOME" ]; then export CARGO_HOME; fi
if [ -n "$CARGO_TARGET_DIR" ]; then export CARGO_TARGET_DIR; fi

log "running cargo test -p skauswatch-s3 --test aws_live_identity"
set +e
(cd "$REPO_ROOT" && cargo test -p skauswatch-s3 --test aws_live_identity -- --nocapture)
TEST_EXIT_CODE=$?
set -e
log "cargo test exit code: $TEST_EXIT_CODE"

exit "$TEST_EXIT_CODE"
