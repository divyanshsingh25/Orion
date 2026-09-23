import pytest

try:
    from Wappalyzer import Wappalyzer, WebPage
except ImportError:
    pytestmark = pytest.mark.skip(reason="Wappalyzer is not installed")
    Wappalyzer = None
    WebPage = None

def test_wappalyzer():
    if not Wappalyzer:
        pytest.skip("Wappalyzer is not installed")
    w = Wappalyzer.latest()
    wp = WebPage("http://example.com", html="<html><body></body></html>", headers={"Server": "Apache/2.4.1"})
    res = w.analyze_with_versions_and_categories(wp)
    assert res is not None
