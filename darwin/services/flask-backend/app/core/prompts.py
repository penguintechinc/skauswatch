"""Prompt templates for AI-powered code review."""

from dataclasses import dataclass
from typing import ClassVar


@dataclass(slots=True)
class PromptTemplate:
    """Template for AI review prompts."""

    category: str
    system_prompt: str
    user_template: str


class ReviewPrompts:
    """Collection of prompt templates for different review categories."""

    SECURITY: ClassVar[PromptTemplate] = PromptTemplate(
        category="security",
        system_prompt="""You are a security-focused code reviewer. Your task is to identify security vulnerabilities and risks in code.

Focus on:
- SQL injection, XSS, CSRF, and other injection vulnerabilities
- Authentication and authorization flaws
- Insecure cryptography and password storage
- Sensitive data exposure and hardcoded secrets
- Insecure dependencies and outdated libraries
- Input validation and sanitization issues
- Path traversal and file access vulnerabilities
- Command injection and unsafe deserialization
- Race conditions and concurrency issues

Provide specific, actionable feedback with severity ratings.""",
        user_template="""Review the following code changes for security vulnerabilities:

**File:** {file_path}
**Language:** {language}
**Framework:** {framework}

**Code Diff:**
```
{diff_content}
```

**Detected Technologies:**
{tech_stack}

Provide your review as a JSON array of findings:
[
  {{
    "line_start": <line_number>,
    "line_end": <line_number>,
    "severity": "critical|major|minor|suggestion",
    "title": "Brief title of the issue",
    "body": "Detailed explanation of the security vulnerability",
    "suggestion": "Concrete code suggestion to fix the issue (optional)"
  }}
]

Only include actual security issues. Return empty array [] if no issues found.""",
    )

    BEST_PRACTICES: ClassVar[PromptTemplate] = PromptTemplate(
        category="best_practices",
        system_prompt="""You are a code quality and best practices reviewer. Your task is to identify code quality issues and violations of best practices.

Focus on:
- Code readability and maintainability
- Proper error handling and logging
- Resource management (file handles, connections, etc.)
- Code duplication and DRY violations
- Function/method length and complexity
- Naming conventions and code organization
- Documentation and comments
- Testing and testability
- Performance anti-patterns
- Design patterns and SOLID principles

Provide constructive feedback that improves code quality.""",
        user_template="""Review the following code changes for best practices and code quality:

**File:** {file_path}
**Language:** {language}
**Framework:** {framework}

**Code Diff:**
```
{diff_content}
```

**Detected Technologies:**
{tech_stack}

Provide your review as a JSON array of findings:
[
  {{
    "line_start": <line_number>,
    "line_end": <line_number>,
    "severity": "critical|major|minor|suggestion",
    "title": "Brief title of the issue",
    "body": "Detailed explanation of the best practice violation",
    "suggestion": "Concrete code suggestion to improve (optional)"
  }}
]

Only include meaningful improvements. Return empty array [] if no issues found.""",
    )

    FRAMEWORK: ClassVar[PromptTemplate] = PromptTemplate(
        category="framework",
        system_prompt="""You are a framework-specific code reviewer. Your task is to identify violations of framework conventions and best practices.

Focus on:
- Framework-specific patterns and anti-patterns
- Proper use of framework features and APIs
- Configuration and setup issues
- Middleware and lifecycle hooks
- Database ORM patterns and query optimization
- Routing and URL patterns
- Template and view rendering
- State management and data flow
- Framework security features
- Performance optimizations specific to the framework

Provide framework-aware recommendations.""",
        user_template="""Review the following code changes for framework-specific issues:

**File:** {file_path}
**Language:** {language}
**Framework:** {framework}

**Code Diff:**
```
{diff_content}
```

**Detected Technologies:**
{tech_stack}

Provide your review as a JSON array of findings:
[
  {{
    "line_start": <line_number>,
    "line_end": <line_number>,
    "severity": "critical|major|minor|suggestion",
    "title": "Brief title of the issue",
    "body": "Detailed explanation of the framework issue",
    "suggestion": "Concrete code suggestion following framework conventions (optional)"
  }}
]

Focus on {framework}-specific issues. Return empty array [] if no issues found.""",
    )

    IAC: ClassVar[PromptTemplate] = PromptTemplate(
        category="iac",
        system_prompt="""You are an Infrastructure as Code (IaC) reviewer. Your task is to identify issues in infrastructure and deployment configurations.

Focus on:
- Security misconfigurations and hardcoded secrets
- Resource access control and permissions
- Network security and firewall rules
- Encryption and data protection
- High availability and disaster recovery
- Resource sizing and cost optimization
- Backup and retention policies
- Monitoring and alerting configuration
- Compliance and governance
- IaC best practices and modularity

Provide infrastructure-specific recommendations.""",
        user_template="""Review the following IaC changes:

**File:** {file_path}
**IaC Tool:** {iac_tool}

**Code Diff:**
```
{diff_content}
```

**Detected Technologies:**
{tech_stack}

Provide your review as a JSON array of findings:
[
  {{
    "line_start": <line_number>,
    "line_end": <line_number>,
    "severity": "critical|major|minor|suggestion",
    "title": "Brief title of the issue",
    "body": "Detailed explanation of the infrastructure issue",
    "suggestion": "Concrete configuration suggestion (optional)"
  }}
]

Focus on infrastructure security and best practices. Return empty array [] if no issues found.""",
    )

    @classmethod
    def get_template(cls, category: str) -> PromptTemplate | None:
        """Get prompt template by category.

        Args:
            category: Review category (security, best_practices, framework, iac)

        Returns:
            PromptTemplate or None if category not found
        """
        templates = {
            "security": cls.SECURITY,
            "best_practices": cls.BEST_PRACTICES,
            "framework": cls.FRAMEWORK,
            "iac": cls.IAC,
        }
        return templates.get(category)

    @classmethod
    def format_tech_stack(
        cls, languages: dict[str, float], frameworks: dict[str, float], iac_tools: list[str]
    ) -> str:
        """Format detected technologies for prompt.

        Args:
            languages: Detected languages with confidence
            frameworks: Detected frameworks with confidence
            iac_tools: Detected IaC tools

        Returns:
            Formatted string of detected technologies
        """
        parts = []

        if languages:
            lang_list = [f"{lang} ({conf:.0%})" for lang, conf in languages.items()]
            parts.append(f"Languages: {', '.join(lang_list)}")

        if frameworks:
            fw_list = [f"{fw} ({conf:.0%})" for fw, conf in frameworks.items()]
            parts.append(f"Frameworks: {', '.join(fw_list)}")

        if iac_tools:
            parts.append(f"IaC Tools: {', '.join(iac_tools)}")

        return "\n".join(parts) if parts else "No specific technologies detected"


class PlanPrompts:
    """Collection of prompt templates for AI plan generation from GitHub issues."""

    @staticmethod
    def get_system_prompt(issue_type: str) -> str:
        """Get system prompt based on issue type.

        Args:
            issue_type: Type of issue (bug, feature, enhancement)

        Returns:
            System prompt tailored to the issue type
        """
        prompts = {
            "bug": """You are an expert software engineer specializing in debugging and root cause analysis. Your task is to create a detailed implementation plan for fixing bugs.

Focus on:
- Root cause analysis and identification of the underlying issue
- Comprehensive fix approach that addresses the root cause, not just symptoms
- Regression prevention through testing and validation
- Impact analysis on related components and features
- Edge cases and error handling scenarios
- Backward compatibility considerations
- Clear reproduction steps and validation criteria

Provide a structured, step-by-step plan that ensures the bug is fixed thoroughly and won't reoccur.""",
            "feature": """You are an expert software architect specializing in feature design and implementation. Your task is to create a detailed implementation plan for new features.

Focus on:
- Architecture and design patterns that fit the existing codebase
- Integration points with existing features and services
- User experience and interface design considerations
- Data model and database schema changes
- API design and contract definitions
- Security, authentication, and authorization requirements
- Performance and scalability implications
- Testing strategy including unit, integration, and E2E tests
- Documentation and user-facing changes

Provide a structured, step-by-step plan that delivers a robust, well-integrated feature.""",
            "enhancement": """You are an expert software engineer specializing in code improvement and optimization. Your task is to create a detailed implementation plan for enhancements.

Focus on:
- Backward compatibility and non-breaking changes
- Performance improvements and optimization opportunities
- Code quality and maintainability enhancements
- Incremental implementation approach
- Refactoring strategy without changing external behavior
- Testing strategy to ensure no regressions
- Migration path for existing users/data if needed
- Metrics and measurements to validate improvements

Provide a structured, step-by-step plan that improves the codebase while maintaining stability.""",
        }
        return prompts.get(issue_type.lower(), prompts["feature"])

    @staticmethod
    def build_plan_prompt(
        issue_title: str, issue_body: str, repository: str, issue_type: str
    ) -> str:
        """Build the complete user prompt with issue data.

        Args:
            issue_title: Title of the GitHub issue
            issue_body: Body/description of the GitHub issue
            repository: Repository name (owner/repo format)
            issue_type: Type of issue (bug, feature, enhancement)

        Returns:
            Complete user prompt with issue context
        """
        return f"""Create an implementation plan for the following GitHub issue:

**Repository:** {repository}
**Issue Type:** {issue_type}
**Title:** {issue_title}

**Description:**
{issue_body}

---

Generate a comprehensive implementation plan in JSON format following the schema provided. The plan should:

1. **Overview**: Provide a concise summary (2-3 sentences) of what needs to be done
2. **Approach**: Describe the technical approach and strategy (4-6 sentences)
3. **Steps**: Break down the implementation into clear, actionable steps (aim for 5-10 steps)
   - Each step should be specific and implementable
   - Include what files need to be created/modified
   - Describe the changes needed in each step
4. **Critical Files**: List all files that will be created or modified (use realistic paths based on repository structure)
5. **Risks**: Identify potential risks, edge cases, and gotchas (3-5 items)
6. **Testing Strategy**: Describe how to test and validate the implementation
7. **Estimated Effort**: Provide a realistic time estimate (e.g., "2-4 hours", "1-2 days")
8. **Complexity**: Rate as Low, Medium, or High based on:
   - Low: Simple changes, minimal risk, well-defined scope
   - Medium: Multiple components, some uncertainty, moderate risk
   - High: Significant changes, high risk, architectural decisions needed

Make the plan specific, actionable, and ready for implementation by a developer.

{PlanPrompts.get_json_schema()}"""

    @staticmethod
    def get_json_schema() -> str:
        """Get the expected JSON response format specification.

        Returns:
            JSON schema description and example
        """
        return """**Required JSON Response Format:**

```json
{
  "overview": "Brief summary of what needs to be done (2-3 sentences)",
  "approach": "Technical approach and strategy (4-6 sentences describing how to implement)",
  "steps": [
    {
      "number": 1,
      "title": "Step title (concise, action-oriented)",
      "description": "Detailed description of what to do in this step, including specific files and changes"
    },
    {
      "number": 2,
      "title": "Next step title",
      "description": "What to do next"
    }
  ],
  "critical_files": [
    "path/to/file1.py",
    "path/to/file2.js",
    "path/to/file3.md"
  ],
  "risks": [
    "Risk description 1 - explain the potential issue",
    "Risk description 2 - explain another concern",
    "Risk description 3 - edge case to watch for"
  ],
  "testing_strategy": "Comprehensive description of how to test this implementation, including unit tests, integration tests, manual testing steps, and validation criteria",
  "estimated_effort": "2-4 hours",
  "complexity": "Medium"
}
```

**Example for a Bug Fix:**

```json
{
  "overview": "Fix authentication timeout issue where users are logged out prematurely due to incorrect session expiration calculation. The bug occurs when the server timezone differs from UTC.",
  "approach": "The root cause is in the session manager where datetime.now() is used instead of datetime.utcnow(). We'll update the session validation logic to use UTC timestamps consistently, add timezone-aware datetime handling, and implement comprehensive tests to prevent similar issues. The fix will be backward compatible with existing sessions.",
  "steps": [
    {
      "number": 1,
      "title": "Update session manager to use UTC timestamps",
      "description": "Modify services/flask-backend/app/auth/session_manager.py to replace all datetime.now() calls with datetime.utcnow(). Update the validate_session() method to use timezone-aware comparisons."
    },
    {
      "number": 2,
      "title": "Add timezone utility functions",
      "description": "Create services/flask-backend/app/utils/datetime_utils.py with helper functions for timezone-aware datetime operations: utc_now(), to_utc(), is_expired()."
    },
    {
      "number": 3,
      "title": "Update session expiration configuration",
      "description": "Modify config/auth.py to add SESSION_TIMEZONE='UTC' setting and update documentation to clarify all session times are in UTC."
    },
    {
      "number": 4,
      "title": "Add comprehensive unit tests",
      "description": "Create tests/unit/auth/test_session_timezone.py with tests covering different timezone scenarios, session expiration edge cases, and UTC/local time conversion."
    },
    {
      "number": 5,
      "title": "Add integration tests",
      "description": "Update tests/integration/test_auth_flow.py to test session timeout behavior in different timezone configurations and validate backward compatibility."
    },
    {
      "number": 6,
      "title": "Update documentation",
      "description": "Update docs/authentication.md to document the UTC requirement for sessions and add troubleshooting section for timezone-related issues."
    }
  ],
  "critical_files": [
    "services/flask-backend/app/auth/session_manager.py",
    "services/flask-backend/app/utils/datetime_utils.py",
    "config/auth.py",
    "tests/unit/auth/test_session_timezone.py",
    "tests/integration/test_auth_flow.py",
    "docs/authentication.md"
  ],
  "risks": [
    "Existing active sessions may have mixed timezone timestamps - implement migration logic or graceful fallback",
    "External services calling the API might be affected if they rely on session timing - verify API contract compatibility",
    "Edge case during daylight saving time transitions - ensure tests cover DST boundaries",
    "Database stored session timestamps may need migration if not already UTC - check database timezone configuration"
  ],
  "testing_strategy": "Unit tests will verify UTC timestamp handling in isolation with mocked datetime. Integration tests will simulate real authentication flows with different timezone configurations. Manual testing will involve logging in, waiting near expiration time, and verifying correct timeout behavior. Load test with concurrent sessions to ensure no race conditions. Verify existing sessions continue to work after deployment.",
  "estimated_effort": "3-5 hours",
  "complexity": "Medium"
}
```

**Example for a Feature:**

```json
{
  "overview": "Add API rate limiting to protect against abuse and ensure fair usage. Implement token bucket algorithm with configurable limits per user role and endpoint.",
  "approach": "Implement a flexible rate limiting middleware using Redis for distributed state management. Configure different limits based on user roles (anonymous, authenticated, premium) and endpoint sensitivity. Provide clear error responses with retry-after headers. Add metrics and monitoring for rate limit hits. Ensure the system gracefully handles Redis unavailability.",
  "steps": [
    {
      "number": 1,
      "title": "Create rate limiting middleware",
      "description": "Create services/flask-backend/app/middleware/rate_limiter.py implementing token bucket algorithm with Redis backend. Include methods for checking limits, consuming tokens, and resetting buckets."
    },
    {
      "number": 2,
      "title": "Define rate limit configuration",
      "description": "Add rate limiting config to config/rate_limits.py with limits per role (anonymous: 10/min, authenticated: 100/min, premium: 1000/min) and per endpoint overrides."
    },
    {
      "number": 3,
      "title": "Integrate middleware with Flask app",
      "description": "Update services/flask-backend/app/__init__.py to register rate limiting middleware before request handlers. Configure Redis connection for rate limit storage."
    },
    {
      "number": 4,
      "title": "Add rate limit decorators",
      "description": "Create decorator functions in app/middleware/rate_limiter.py for easy endpoint-specific rate limiting: @rate_limit('100/hour'), @rate_limit_by_role()."
    },
    {
      "number": 5,
      "title": "Implement error responses",
      "description": "Update app/api/errors.py to handle RateLimitExceeded exceptions with 429 status code and Retry-After headers. Include clear error messages."
    },
    {
      "number": 6,
      "title": "Add monitoring and metrics",
      "description": "Instrument rate limiter with Prometheus metrics: rate_limit_hits_total, rate_limit_exceeded_total, rate_limit_check_duration_seconds."
    },
    {
      "number": 7,
      "title": "Create management API endpoints",
      "description": "Add admin endpoints in app/api/v1/admin/rate_limits.py for viewing current limits, resetting user limits, and temporarily adjusting limits."
    },
    {
      "number": 8,
      "title": "Add comprehensive tests",
      "description": "Create tests/unit/middleware/test_rate_limiter.py for token bucket logic and tests/integration/test_rate_limiting.py for end-to-end rate limiting behavior."
    },
    {
      "number": 9,
      "title": "Update API documentation",
      "description": "Document rate limits in docs/api/rate-limiting.md including limits per tier, how to handle 429 responses, and header information."
    }
  ],
  "critical_files": [
    "services/flask-backend/app/middleware/rate_limiter.py",
    "config/rate_limits.py",
    "services/flask-backend/app/__init__.py",
    "services/flask-backend/app/api/errors.py",
    "services/flask-backend/app/api/v1/admin/rate_limits.py",
    "tests/unit/middleware/test_rate_limiter.py",
    "tests/integration/test_rate_limiting.py",
    "docs/api/rate-limiting.md"
  ],
  "risks": [
    "Redis unavailability could break the API - implement fallback to in-memory rate limiting or fail-open mode with logging",
    "Distributed deployments need consistent rate limiting across instances - ensure Redis is properly configured for cluster mode",
    "Clock skew between servers could cause inconsistent rate limiting - use Redis time or server-synchronized clocks",
    "Aggressive rate limits could impact legitimate users - start with generous limits and adjust based on metrics",
    "Rate limiting by IP could affect users behind NAT - consider alternative identifier strategies for fairness"
  ],
  "testing_strategy": "Unit tests will verify token bucket algorithm correctness with various scenarios. Integration tests will make rapid API requests and verify rate limiting kicks in correctly. Test different user roles and confirm different limits apply. Verify Retry-After headers are correct. Test Redis failure scenarios and confirm graceful degradation. Load test to ensure rate limiting doesn't become a bottleneck. Monitor metrics in staging environment before production rollout.",
  "estimated_effort": "1-2 days",
  "complexity": "High"
}
```

Ensure your response is valid JSON only, without any markdown code blocks or additional text."""
