import http.client
import threading
import unittest
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

import demo


class HostedDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = demo.make_demo_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(5)
        cls.server.server_close()

    def setUp(self):
        self.cookies = CookieJar()
        self.browser = build_opener(HTTPCookieProcessor(self.cookies))
        self.get()

    def get(self, path="/"):
        with self.browser.open("http://127.0.0.1:%s%s" % (self.port, path), timeout=3) as response:
            return response.status, response.read(), response.headers

    def post(self, action, contact="+14155550100", message="demo message"):
        csrf = next(cookie.value for cookie in self.cookies if cookie.name == demo.COOKIE)
        body = urlencode({"action": action, "contact": contact, "message": message, "csrf": csrf}).encode()
        request = Request("http://127.0.0.1:%s/action" % self.port, data=body, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.browser.open(request, timeout=3) as response:
            return response.status, response.read()

    def test_healthz_and_banner(self):
        status, body, _ = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        status, body, headers = self.get()
        self.assertEqual(status, 200)
        self.assertIn(demo.BANNER.encode(), body)
        self.assertIn(b"in-memory database", body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        with self.assertRaises(HTTPError) as caught:
            self.get("/missing")
        self.assertEqual(caught.exception.code, 404)
        self.assertIn(demo.BANNER.encode(), caught.exception.read())

    def test_core_flow_over_http_and_html_escaping(self):
        self.assertIn(b"no_consent", self.post("send")[1])
        self.assertIn(b"Consent granted", self.post("grant")[1])
        hostile = "<script>alert('not real')</script>"
        body = self.post("send", message=hostile)[1]
        self.assertIn(b"Send result: sent", body)
        self.assertIn(b"&lt;script&gt;", body)
        self.assertNotIn(hostile.encode(), body)
        self.assertIn(b"STOP processed and routed: yes", self.post("stop")[1])
        self.assertIn(b"suppressed", self.post("send")[1])
        self.assertIn(b"START processed and routed: yes", self.post("start")[1])
        body = self.post("send")[1]
        self.assertIn(b"Send result: sent", body)
        self.assertIn(b"Audit chain: <strong>verified</strong>", body)
        self.assertIn(b"consent.granted", body)
        for _ in range(2):
            body = self.post("cap")[1]
            self.assertIn(b"second=cap_exceeded", body)
            self.assertIn(b"suspended_cap", body)

    def test_rejects_request_bodies_over_64_kb(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request("POST", "/action", body=b"x" * (demo.MAX_BODY + 1),
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
            response = connection.getresponse()
            self.assertEqual(response.status, 413)
            self.assertIn(demo.BANNER.encode(), response.read())
        finally:
            connection.close()

    def test_other_browser_cannot_see_deliveries_or_change_consent(self):
        self.post("grant", contact="+14155550987")
        self.post("send", contact="+14155550987", message="visitor-one-private-message")
        other = build_opener(HTTPCookieProcessor(CookieJar()))
        with other.open("http://127.0.0.1:%s/" % self.port, timeout=3) as response:
            page = response.read()
        self.assertNotIn(b"+14155550987", page)
        self.assertNotIn(b"visitor-one-private-message", page)
        self.assertIn(b"no_consent", page)
        self.post("stop", contact="+14155550987")
        with other.open("http://127.0.0.1:%s/" % self.port, timeout=3) as response:
            self.assertIn(b"no_consent", response.read())


if __name__ == "__main__":
    unittest.main()
