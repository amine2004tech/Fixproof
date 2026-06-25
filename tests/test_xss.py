"""Tests for fixproof.checks.xss — XSS marker detection."""

from fixproof.checks.xss import _analyse_context, _MARKER, evaluate_xss_response


class TestAnalyseContext:
    """Test the XSS context analysis."""

    def test_html_body(self):
        html = f"<html><body><p>Hello {_MARKER} world</p></body></html>"
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "html_body" in ctxs

    def test_html_attribute(self):
        html = f'<html><body><div class="{_MARKER}"></div></body></html>'
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "html_attribute" in ctxs

    def test_input_value(self):
        html = f'<html><body><input type="text" value="{_MARKER}"></body></html>'
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "input_value" in ctxs

    def test_script_context(self):
        html = f"<html><script>var x = '{_MARKER}';</script></html>"
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "script_context" in ctxs

    def test_comment_context(self):
        html = f"<html><!-- {_MARKER} --></html>"
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "comment" in ctxs

    def test_json_context(self):
        html = f"<html><body><script>var data = {{ 'test': '{_MARKER}' }};</script></body></html>"
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "json_context" in ctxs
        assert "script_context" in ctxs

    def test_escaped_html(self):
        html = f"<html><body>&lt;script&gt;{_MARKER}&lt;/script&gt;</body></html>"
        payload = f"<script>{_MARKER}</script>"
        ctxs = _analyse_context(html, _MARKER, payload)
        assert "escaped_html" in ctxs

    def test_no_marker(self):
        html = "<html><body>Clean page</body></html>"
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert ctxs == []

    def test_multiple_contexts(self):
        html = (
            f"<html><body>{_MARKER}"
            f"<input value='{_MARKER}'>"
            f"</body></html>"
        )
        ctxs = _analyse_context(html, _MARKER, _MARKER)
        assert "html_body" in ctxs
        assert "input_value" in ctxs
        assert len(ctxs) == 2


class TestEvaluateXssResponse:
    def test_encoded_reflection_is_observation(self):
        html = f"<html><body>&lt;script&gt;{_MARKER}&lt;/script&gt;</body></html>"
        payload = f"<script>{_MARKER}</script>"
        result = evaluate_xss_response(html, payload)
        assert result["category"] == "observation"
        assert result["severity"] == "info"
        assert result["check_type"] == "xss_observation"
        assert result["retestable"] is False
        assert "escaped_html" in result["contexts"]

    def test_raw_unescaped_marker_is_attack(self):
        html = f"<html><body><script>{_MARKER}</script></body></html>"
        payload = f"<script>{_MARKER}</script>"
        result = evaluate_xss_response(html, payload)
        assert result["category"] == "attack"
        assert result["severity"] == "high"
        assert result["check_type"] == "xss"
        assert result["retestable"] is True
        assert "script_context" in result["contexts"]

    def test_input_reflection_is_observation(self):
        html = f"<html><body><input type='text' value='{_MARKER}'></body></html>"
        payload = _MARKER
        result = evaluate_xss_response(html, payload)
        assert result["category"] == "observation"
        assert result["severity"] == "info"
        assert result["check_type"] == "xss_observation"
        assert result["retestable"] is False
        assert "input_value" in result["contexts"]
