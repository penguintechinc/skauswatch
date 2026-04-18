"""Common assertion helpers for SkausWatch tests.

Reduces boilerplate in API and integration tests by providing
reusable assertions for common response patterns.
"""

from typing import Any, Optional, Sequence


def assert_json_keys(response_json: dict, keys: Sequence[str]) -> None:
    """Assert that a JSON response contains all expected keys.

    Args:
        response_json: Parsed JSON response body.
        keys: Keys that must be present in the response.
    """
    missing = [k for k in keys if k not in response_json]
    assert not missing, f"Missing keys in response: {missing}. Got: {list(response_json.keys())}"


def assert_error(
    response: Any,
    status_code: int,
    error_key: str = "error",
) -> None:
    """Assert that an HTTP response is an error with the expected status code.

    Works with httpx.Response and similar objects that have .status_code and .json().

    Args:
        response: HTTP response object.
        status_code: Expected HTTP status code.
        error_key: Key that should be present in the error JSON body.
    """
    assert response.status_code == status_code, (
        f"Expected status {status_code}, got {response.status_code}: "
        f"{response.text[:200]}"
    )
    body = response.json()
    assert error_key in body, (
        f"Expected '{error_key}' key in error response. Got: {list(body.keys())}"
    )


def assert_pagination(
    response_json: dict,
    expected_keys: Optional[Sequence[str]] = None,
) -> None:
    """Assert that a JSON response contains standard pagination fields.

    Expected structure (manager-new convention):
    {
        "items": [...],
        "total": int,
        "page": int,
        "per_page": int,
        "pages": int
    }

    Args:
        response_json: Parsed JSON response body.
        expected_keys: Override default pagination keys.
    """
    keys = expected_keys or ["items", "total", "page", "per_page", "pages"]
    assert_json_keys(response_json, keys)
    assert isinstance(response_json["items"], list), "items must be a list"
    assert isinstance(response_json["total"], int), "total must be an int"
    assert response_json["total"] >= 0, "total must be non-negative"
    assert response_json["page"] >= 1, "page must be >= 1"
    assert response_json["per_page"] >= 1, "per_page must be >= 1"


def assert_success(response: Any, status_code: int = 200) -> dict:
    """Assert a successful response and return parsed JSON body.

    Args:
        response: HTTP response object.
        status_code: Expected HTTP status code (default 200).

    Returns:
        Parsed JSON response body.
    """
    assert response.status_code == status_code, (
        f"Expected status {status_code}, got {response.status_code}: "
        f"{response.text[:500]}"
    )
    return response.json()


def assert_created(response: Any) -> dict:
    """Assert a 201 Created response and return parsed JSON body."""
    return assert_success(response, 201)


def assert_no_content(response: Any) -> None:
    """Assert a 204 No Content response."""
    assert response.status_code == 204, (
        f"Expected status 204, got {response.status_code}: {response.text[:200]}"
    )
