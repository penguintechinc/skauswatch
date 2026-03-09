#!/bin/bash
# Alpha Test 03: Mock Data Integration
# Populates database with mock data and verifies integrity

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Alpha Mock Data Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Test 1: Run mock data population script
log_info "Test 1/4: Populating mock data..."
if [ -f "$SCRIPT_DIR/../mock-data/populate.sh" ]; then
    if bash "$SCRIPT_DIR/../mock-data/populate.sh" > "$LOG_DIR/mock-data.log" 2>&1; then
        log_success "Mock data populated"
        save_test_result "mock-data-populate" "PASS"
    else
        log_error "Failed to populate mock data"
        save_test_result "mock-data-populate" "FAIL"
        exit 1
    fi
else
    log_warning "Mock data script not found, skipping"
    save_test_result "mock-data-populate" "SKIP"
fi

# Test 2: Verify database has data
log_info "Test 2/4: Verifying database contains data..."
USER_COUNT=$(docker exec project-template-postgres psql -U app_user -d app_db -t -c "SELECT COUNT(*) FROM users;" 2>/dev/null | tr -d ' ')

if [ -n "$USER_COUNT" ] && [ "$USER_COUNT" -gt 0 ]; then
    log_success "Database contains $USER_COUNT users"
    save_test_result "verify-users" "PASS" "$USER_COUNT users found"
else
    log_error "No users found in database"
    save_test_result "verify-users" "FAIL"
    exit 1
fi

# Test 3: Verify review data
log_info "Test 3/4: Verifying review data..."
REVIEW_COUNT=$(docker exec project-template-postgres psql -U app_user -d app_db -t -c "SELECT COUNT(*) FROM reviews;" 2>/dev/null | tr -d ' ')

if [ -n "$REVIEW_COUNT" ]; then
    log_success "Database contains $REVIEW_COUNT reviews"
    save_test_result "verify-reviews" "PASS" "$REVIEW_COUNT reviews found"
else
    log_warning "No reviews found in database"
    save_test_result "verify-reviews" "WARN"
fi

# Test 4: Verify data relationships (tenant membership integrity)
log_info "Test 4/5: Verifying data relationships..."
ORPHAN_MEMBERS=$(docker exec project-template-postgres psql -U app_user -d app_db -t -c \
    "SELECT COUNT(*) FROM tenant_members tm LEFT JOIN users u ON tm.user_id = u.id WHERE u.id IS NULL;" 2>/dev/null | tr -d ' ')

if [ -z "$ORPHAN_MEMBERS" ] || [ "$ORPHAN_MEMBERS" = "0" ]; then
    log_success "No orphaned tenant members (all have valid user references)"
    save_test_result "data-integrity" "PASS"
else
    log_error "Found $ORPHAN_MEMBERS orphaned tenant members"
    save_test_result "data-integrity" "FAIL"
    exit 1
fi

# Test 5: Verify review-user association (triggered_by populated)
log_info "Test 5/5: Verifying review-user associations..."
REVIEWS_WITH_USER=$(docker exec project-template-postgres psql -U app_user -d app_db -t -c \
    "SELECT COUNT(*) FROM reviews WHERE triggered_by IS NOT NULL;" 2>/dev/null | tr -d ' ')
TOTAL_REVIEWS=$(docker exec project-template-postgres psql -U app_user -d app_db -t -c \
    "SELECT COUNT(*) FROM reviews;" 2>/dev/null | tr -d ' ')

if [ -n "$TOTAL_REVIEWS" ] && [ "$TOTAL_REVIEWS" -gt 0 ]; then
    if [ -n "$REVIEWS_WITH_USER" ] && [ "$REVIEWS_WITH_USER" -gt 0 ]; then
        log_success "Reviews with user association: $REVIEWS_WITH_USER/$TOTAL_REVIEWS"
        save_test_result "review-user-assoc" "PASS" "$REVIEWS_WITH_USER/$TOTAL_REVIEWS reviews have triggered_by"
    else
        log_warning "No reviews have user associations (triggered_by is NULL for all)"
        save_test_result "review-user-assoc" "WARN"
    fi
else
    log_warning "No reviews to check for user associations"
    save_test_result "review-user-assoc" "WARN"
fi

print_summary
log_success "$TEST_NAME completed successfully"
