"""Tests for fixproof.guard — localhost-only URL validation."""

import pytest
from fixproof.guard import validate_url, assert_localhost, GuardResult


class TestValidateUrl:
    """Ensure the guard correctly allows and blocks URLs."""

    # --- Allowed ---

    def test_localhost_http(self):
        r = validate_url("http://localhost:3000")
        assert r.allowed is True

    def test_localhost_https(self):
        r = validate_url("https://localhost:443")
        assert r.allowed is True

    def test_127_0_0_1(self):
        r = validate_url("http://127.0.0.1:8080")
        assert r.allowed is True

    def test_ipv6_loopback(self):
        r = validate_url("http://[::1]:5000")
        assert r.allowed is True

    def test_localhost_no_port(self):
        r = validate_url("http://localhost/path")
        assert r.allowed is True

    # --- Blocked ---

    def test_public_domain(self):
        r = validate_url("http://example.com")
        assert r.allowed is False

    def test_google(self):
        r = validate_url("https://google.com")
        assert r.allowed is False

    def test_lan_192_168(self):
        r = validate_url("http://192.168.1.1")
        assert r.allowed is False

    def test_lan_10(self):
        r = validate_url("http://10.0.0.1")
        assert r.allowed is False

    def test_lan_172_16(self):
        r = validate_url("http://172.16.0.1")
        assert r.allowed is False

    def test_ftp_scheme(self):
        r = validate_url("ftp://localhost:21")
        assert r.allowed is False

    def test_no_scheme(self):
        r = validate_url("localhost:3000")
        assert r.allowed is False

    def test_empty(self):
        r = validate_url("")
        assert r.allowed is False


class TestAssertLocalhost:
    """Test the raising variant."""

    def test_passes_for_localhost(self):
        assert_localhost("http://localhost:3000")  # Should not raise.

    def test_raises_for_public(self):
        with pytest.raises(ValueError, match="BLOCKED"):
            assert_localhost("http://example.com")

    def test_raises_for_lan(self):
        with pytest.raises(ValueError, match="BLOCKED"):
            assert_localhost("http://192.168.1.100:8080")
