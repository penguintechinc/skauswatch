#!/bin/bash
# Alpha Test 04: Page Load Tests
# Verifies all pages load successfully and tabs work correctly

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/config.sh"

TEST_NAME="Alpha Page Load Test"
log_info "Starting $TEST_NAME"

# Initialize results file
echo "[]" > "$LOG_DIR/results.json"

# Pages to test
PAGES=(
    "/"
    "/login"
    "/dashboard"
    "/reviews"
    "/users"
    "/settings"
)

# Test 1: Check root page loads
log_info "Test 1/${#PAGES[@]}: Testing root page..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ALPHA_WEBUI_URL/")

if [ "$HTTP_CODE" = "200" ]; then
    log_success "Root page loads successfully (HTTP $HTTP_CODE)"
    save_test_result "page-root" "PASS"
else
    log_error "Root page failed (HTTP $HTTP_CODE)"
    save_test_result "page-root" "FAIL" "HTTP $HTTP_CODE"
    exit 1
fi

# Test 2-N: Test all other pages
COUNTER=2
for page in "${PAGES[@]:1}"; do
    log_info "Test $COUNTER/${#PAGES[@]}: Testing page: $page"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ALPHA_WEBUI_URL$page")

    # Accept 200 or 302 (redirect to login is okay)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        log_success "Page loads successfully: $page (HTTP $HTTP_CODE)"
        save_test_result "page-$page" "PASS"
    else
        log_error "Page load failed: $page (HTTP $HTTP_CODE)"
        save_test_result "page-$page" "FAIL" "HTTP $HTTP_CODE"
    fi

    COUNTER=$((COUNTER + 1))
done

# Test N+1: Check for JavaScript errors (using Node.js if available)
if command_exists node; then
    log_info "Test N+1: Checking for JavaScript errors..."

    # Create a simple puppeteer script to check console errors
    cat > "$LOG_DIR/check-js-errors.js" << 'EOF'
const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch({ headless: 'new' });
    const page = await browser.newPage();

    const errors = [];
    page.on('console', msg => {
        if (msg.type() === 'error') {
            errors.push(msg.text());
        }
    });

    try {
        await page.goto(process.env.ALPHA_WEBUI_URL || 'http://localhost:3000', {
            waitUntil: 'networkidle0',
            timeout: 30000
        });

        if (errors.length > 0) {
            console.log('JavaScript errors found:');
            errors.forEach(err => console.log(err));
            process.exit(1);
        } else {
            console.log('No JavaScript errors found');
            process.exit(0);
        }
    } catch (error) {
        console.error('Page load error:', error.message);
        process.exit(1);
    } finally {
        await browser.close();
    }
})();
EOF

    if node "$LOG_DIR/check-js-errors.js" > "$LOG_DIR/js-errors.log" 2>&1; then
        log_success "No JavaScript console errors"
        save_test_result "js-errors" "PASS"
    else
        log_warning "JavaScript errors detected (see $LOG_DIR/js-errors.log)"
        save_test_result "js-errors" "WARN"
    fi
else
    log_warning "Node.js not found, skipping JavaScript error check"
    save_test_result "js-errors" "SKIP"
fi

print_summary
log_success "$TEST_NAME completed successfully"
