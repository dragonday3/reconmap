"""Tests for GitHubCollector — GitHub code search for secrets."""
import httpx
import pytest
import respx

from reconmap.collectors.github import GitHubCollector, _redact

# ---------------------------------------------------------------------------
# Shared mock response helpers
# ---------------------------------------------------------------------------

GITHUB_RESPONSE = {
    "total_count": 1,
    "items": [
        {
            "repository": {"full_name": "someuser/somerepo"},
            "path": "config/settings.py",
            "html_url": "https://github.com/someuser/somerepo/blob/main/config/settings.py",
            "text_matches": [
                {"fragment": "api_key = 'AKIAIOSFODNN7EXAMPLE'"}
            ],
        }
    ],
}


def _make_response(fragment: str, path: str = "config/settings.py") -> dict:
    return {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "someuser/somerepo"},
                "path": path,
                "html_url": f"https://github.com/someuser/somerepo/blob/main/{path}",
                "text_matches": [{"fragment": fragment}],
            }
        ],
    }


def _empty_response() -> dict:
    return {"total_count": 0, "items": []}


# ---------------------------------------------------------------------------
# Test 1 — AWS key in text_matches → SecretLeak with secret_type="aws_key"
# ---------------------------------------------------------------------------

@respx.mock
async def test_aws_key_detected():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=GITHUB_RESPONSE)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    secret_types = {leak.secret_type for leak in snapshot.leaks}
    assert "aws_key" in secret_types


# ---------------------------------------------------------------------------
# Test 2 — JWT in text_matches → SecretLeak with secret_type="jwt"
# ---------------------------------------------------------------------------

@respx.mock
async def test_jwt_detected():
    jwt_fragment = "token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'"
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=_make_response(jwt_fragment))
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    secret_types = {leak.secret_type for leak in snapshot.leaks}
    assert "jwt" in secret_types


# ---------------------------------------------------------------------------
# Test 3 — raw_match is redacted (first 4 chars + ****, full secret absent)
# ---------------------------------------------------------------------------

@respx.mock
async def test_raw_match_is_redacted():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=GITHUB_RESPONSE)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    # Find the aws_key leak specifically to verify redaction
    aws_leak = next(l for l in snapshot.leaks if l.secret_type == "aws_key")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_leak.raw_match
    assert aws_leak.raw_match.endswith("****")
    # First 4 chars of the AWS key: "AKIA"
    assert aws_leak.raw_match.startswith("AKIA")


# ---------------------------------------------------------------------------
# Test 4 — 429 response → empty leaks, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_429_returns_empty_leaks():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(429)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 5 — 403 response → empty leaks, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_403_returns_empty_leaks():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(403)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 6 — Timeout → empty leaks, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_timeout_returns_empty_leaks():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        side_effect=httpx.TimeoutException("timeout")
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 7 — No text_matches in items → empty leaks
# ---------------------------------------------------------------------------

@respx.mock
async def test_no_text_matches_returns_empty_leaks():
    response_no_matches = {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "user/repo"},
                "path": "app.py",
                "html_url": "https://github.com/user/repo/blob/main/app.py",
                "text_matches": [],
            }
        ],
    }
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=response_no_matches)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 8 — Multiple secrets in one fragment → multiple SecretLeak objects
# ---------------------------------------------------------------------------

@respx.mock
async def test_multiple_secrets_in_one_fragment():
    # Fragment contains both an AWS key and a GitHub token
    fragment = "key=AKIAIOSFODNN7EXAMPLE token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=_make_response(fragment))
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 2
    secret_types = {leak.secret_type for leak in snapshot.leaks}
    assert "aws_key" in secret_types
    assert "github_token" in secret_types


# ---------------------------------------------------------------------------
# Test 9 — is_available() returns True (no token required)
# ---------------------------------------------------------------------------

def test_is_available_returns_true():
    collector = GitHubCollector()
    assert collector.is_available() is True


# ---------------------------------------------------------------------------
# Test 10 — requires_key is False
# ---------------------------------------------------------------------------

def test_requires_key_is_false():
    assert GitHubCollector.requires_key is False


# ---------------------------------------------------------------------------
# Test 11 — source field on SecretLeak is "github"
# ---------------------------------------------------------------------------

@respx.mock
async def test_source_field_is_github():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=GITHUB_RESPONSE)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    assert all(leak.source == "github" for leak in snapshot.leaks)


# ---------------------------------------------------------------------------
# Test 12 — 500 response → empty leaks, no exception
# ---------------------------------------------------------------------------

@respx.mock
async def test_500_returns_empty_leaks():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(500)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.target_domain == "example.com"
    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 13 — Empty items array → empty leaks
# ---------------------------------------------------------------------------

@respx.mock
async def test_empty_items_returns_empty_leaks():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=_empty_response())
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert snapshot.leaks == []


# ---------------------------------------------------------------------------
# Test 14 — target_domain set correctly on snapshot and leaks
# ---------------------------------------------------------------------------

@respx.mock
async def test_target_domain_set_correctly():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=GITHUB_RESPONSE)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("target.org")

    assert snapshot.target_domain == "target.org"
    assert snapshot.leaks[0].target_domain == "target.org"


# ---------------------------------------------------------------------------
# Test 15 — repo and file_path fields correctly extracted from response
# ---------------------------------------------------------------------------

@respx.mock
async def test_repo_and_file_path_extracted():
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=GITHUB_RESPONSE)
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    # All leaks from the same item share the same repo/path/url
    for leak in snapshot.leaks:
        assert leak.repo == "someuser/somerepo"
        assert leak.file_path == "config/settings.py"
        assert "github.com" in leak.html_url


# ---------------------------------------------------------------------------
# Test 16 — _redact helper: short string returns ****
# ---------------------------------------------------------------------------

def test_redact_short_string():
    assert _redact("abc") == "****"
    assert _redact("") == "****"
    assert _redact("1234") == "****"


# ---------------------------------------------------------------------------
# Test 17 — _redact helper: longer string returns first 4 chars + ****
# ---------------------------------------------------------------------------

def test_redact_longer_string():
    result = _redact("AKIAIOSFODNN7EXAMPLE")
    assert result == "AKIA****"
    assert len(result) == 8


# ---------------------------------------------------------------------------
# Test 18 — Token-authenticated collector sends Authorization header
# ---------------------------------------------------------------------------

@respx.mock
async def test_token_sets_authorization_header():
    route = respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=_empty_response())
    )
    collector = GitHubCollector(token="ghp_faketoken123456789012345678901234")
    await collector.collect("example.com")

    assert route.called
    request = route.calls.last.request
    assert "Authorization" in request.headers
    assert "ghp_faketoken123456789012345678901234" in request.headers["Authorization"]


# ---------------------------------------------------------------------------
# Test 19 — collector name class attribute is "github"
# ---------------------------------------------------------------------------

def test_collector_name():
    assert GitHubCollector.name == "github"


# ---------------------------------------------------------------------------
# Test 20 — private key pattern detected
# ---------------------------------------------------------------------------

@respx.mock
async def test_private_key_detected():
    fragment = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    respx.get(url__regex=r"https://api\.github\.com/search/code.*").mock(
        return_value=httpx.Response(200, json=_make_response(fragment))
    )
    collector = GitHubCollector()
    snapshot = await collector.collect("example.com")

    assert len(snapshot.leaks) >= 1
    secret_types = {leak.secret_type for leak in snapshot.leaks}
    assert "private_key" in secret_types
