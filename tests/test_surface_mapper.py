"""Tests for fixproof.surface_mapper."""

from fixproof.surface_mapper import map_surface, AttackSurface


class TestMapSurface:
    """Test the surface mapper on crafted HTML."""

    def _page(self, url: str, html: str, links: list[str] | None = None) -> dict:
        return {"url": url, "html": html, "links": links or []}

    def test_extracts_form(self):
        html = '''
        <html><body>
        <form action="/login" method="POST">
          <input type="hidden" name="csrf" value="abc123">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Login</button>
        </form>
        </body></html>
        '''
        surface = map_surface([self._page("http://localhost:3000/login", html)])

        assert len(surface.forms) == 1
        form = surface.forms[0]
        assert form.method == "POST"
        assert form.action == "/login"
        assert len(form.fields) == 3

        hidden = [f for f in form.fields if f.is_hidden]
        assert len(hidden) == 1
        assert hidden[0].name == "csrf"
        assert hidden[0].value == "abc123"

    def test_extracts_get_params(self):
        surface = map_surface([
            self._page("http://localhost:3000/search?q=test&page=1", "")
        ])
        assert len(surface.parameters) == 1
        assert "q" in surface.parameters[0].params
        assert "page" in surface.parameters[0].params

    def test_extracts_api_hints_from_links(self):
        surface = map_surface([
            self._page(
                "http://localhost:3000",
                "<html></html>",
                links=["http://localhost:3000/api/v1/users"],
            )
        ])
        assert len(surface.api_hints) >= 1

    def test_extracts_textarea_and_select(self):
        html = '''
        <form action="/post" method="POST">
          <textarea name="body"></textarea>
          <select name="category"><option value="a">A</option></select>
          <input type="submit">
        </form>
        '''
        surface = map_surface([self._page("http://localhost:3000", html)])
        assert len(surface.forms) == 1
        names = {f.name for f in surface.forms[0].fields}
        assert "body" in names
        assert "category" in names

    def test_cookies(self):
        surface = map_surface(
            [self._page("http://localhost:3000", "")],
            response_cookies={"session": "abc", "theme": "dark"},
        )
        assert len(surface.cookies) == 1
        assert surface.cookies[0].cookies["session"] == "abc"

    def test_empty_pages(self):
        surface = map_surface([])
        assert isinstance(surface, AttackSurface)
        assert surface.forms == []
        assert surface.parameters == []
