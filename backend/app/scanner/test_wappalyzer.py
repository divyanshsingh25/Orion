from Wappalyzer import Wappalyzer, WebPage
w = Wappalyzer.latest()
wp = WebPage("http://example.com", html="<html><body></body></html>", headers={"Server": "Apache/2.4.1"})
res = w.analyze_with_versions_and_categories(wp)
print(res)
