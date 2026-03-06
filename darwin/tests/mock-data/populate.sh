#!/bin/bash
# Mock Data Population Script
# Populates database with 3-4 items per feature for testing

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

log_info "Populating mock data..."

# Database connection details
DB_CONTAINER="${DB_CONTAINER:-project-template-postgres}"
FLASK_URL="${FLASK_URL:-http://localhost:5000}"

# Wait for Flask backend to be ready
wait_for_service "$FLASK_URL/healthz" 60

# Create test users via API
log_info "Creating test users..."

# Admin user (should already exist from initialization)
ADMIN_TOKEN=$(get_auth_token "$FLASK_URL" "$TEST_ADMIN_EMAIL" "$TEST_ADMIN_PASSWORD")

if [ -n "$ADMIN_TOKEN" ]; then
    log_success "Admin user authenticated"
else
    log_error "Failed to authenticate admin user"
    exit 1
fi

# Create 3 regular users
for i in {1..3}; do
    log_info "Creating user $i..."

    USER_RESPONSE=$(curl -s -X POST "$FLASK_URL/api/v1/users" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"user$i@example.com\",
            \"password\": \"password123\",
            \"username\": \"user$i\",
            \"first_name\": \"Test\",
            \"last_name\": \"User $i\"
        }")

    if echo "$USER_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
        log_success "User $i created"
    else
        log_warning "User $i may already exist or creation failed"
    fi
done

# Create mock reviews (3 per user)
log_info "Creating mock reviews..."

PLATFORMS=("github" "gitlab" "github")
REVIEW_TYPES=("differential" "whole" "differential")

for user_num in {1..3}; do
    # Get user token
    USER_TOKEN=$(get_auth_token "$FLASK_URL" "user$user_num@example.com" "password123")

    if [ -z "$USER_TOKEN" ]; then
        log_warning "Could not authenticate user$user_num, skipping reviews"
        continue
    fi

    # Create 3 reviews
    for review_num in {1..3}; do
        log_info "Creating review $review_num for user$user_num..."

        PLATFORM_IDX=$(( (review_num - 1) % 3 ))
        REVIEW_RESPONSE=$(curl -s -X POST "$FLASK_URL/api/v1/reviews" \
            -H "Authorization: Bearer $USER_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"external_id\": \"mock-user${user_num}-review${review_num}\",
                \"platform\": \"${PLATFORMS[$PLATFORM_IDX]}\",
                \"repository\": \"penguintechinc/darwin\",
                \"review_type\": \"${REVIEW_TYPES[$PLATFORM_IDX]}\",
                \"categories\": [\"security\", \"best_practices\"],
                \"ai_provider\": \"claude\",
                \"pull_request_id\": $((review_num + user_num * 10)),
                \"pull_request_url\": \"https://github.com/penguintechinc/darwin/pull/$((review_num + user_num * 10))\"
            }")

        if echo "$REVIEW_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
            log_success "Review $review_num created for user$user_num"
        else
            log_warning "Review creation may have failed: $REVIEW_RESPONSE"
        fi
    done
done

# Verify mock data
log_info "Verifying mock data..."

# Count users
USER_COUNT=$(docker exec "$DB_CONTAINER" psql -U app_user -d app_db -t -c \
    "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d ' ')

log_info "Total users in database: $USER_COUNT"

# Count reviews
REVIEW_COUNT=$(docker exec "$DB_CONTAINER" psql -U app_user -d app_db -t -c \
    "SELECT COUNT(*) FROM reviews;" 2>/dev/null | tr -d ' ')

log_info "Total reviews in database: $REVIEW_COUNT"

if [ "$USER_COUNT" -ge 4 ] && [ "$REVIEW_COUNT" -ge 9 ]; then
    log_success "Mock data populated successfully!"
    log_info "  - Users: $USER_COUNT"
    log_info "  - Reviews: $REVIEW_COUNT"
else
    log_warning "Mock data may be incomplete"
    log_info "  - Users: $USER_COUNT (expected >= 4)"
    log_info "  - Reviews: $REVIEW_COUNT (expected >= 9)"
fi
