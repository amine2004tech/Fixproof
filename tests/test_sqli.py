"""Tests for fixproof.checks.sqli — SQL injection comparison logic."""

from fixproof.checks.sqli import _has_sql_error, _boolean_compare


class TestHasSqlError:
    """Test SQL error fingerprint detection."""

    def test_mysql_error(self):
        text = "You have an error in your SQL syntax near 'foo'"
        assert _has_sql_error(text) is not None

    def test_sqlite_error(self):
        text = "sqlite3.OperationalError: unrecognized token"
        assert _has_sql_error(text) is not None

    def test_pg_error(self):
        text = "ERROR: pg_query() failed"
        assert _has_sql_error(text) is not None

    def test_clean_page(self):
        text = "<html><body>Welcome to our site!</body></html>"
        assert _has_sql_error(text) is None

    def test_partial_match(self):
        text = "SQLSTATE[HY000]: General error"
        assert _has_sql_error(text) is not None


class TestBooleanCompare:
    """Test the boolean comparison function."""

    def test_identical_responses(self):
        # Same content = no SQLi.
        assert _boolean_compare("Hello", "Hello") is False

    def test_different_responses(self):
        # Very different content = potential SQLi.
        resp_true = "Welcome back, admin! " * 10
        resp_false = "Error"
        assert _boolean_compare(resp_true, resp_false) is True

    def test_small_difference(self):
        # Minor differences < 5% threshold.
        resp_a = "x" * 1000
        resp_b = "x" * 1010
        assert _boolean_compare(resp_a, resp_b) is False

    def test_large_difference(self):
        resp_a = "x" * 100
        resp_b = "x" * 200
        assert _boolean_compare(resp_a, resp_b) is True
