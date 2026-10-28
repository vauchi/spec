# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
# SPDX-License-Identifier: GPL-3.0-or-later

# The spec is served at vauchi.app/spec behind kamal-proxy's path prefix;
# this drives the real nginx.conf against a stand-in book and checks the
# prefix handling, the health check and the 404 page (vauchi/private#875).

import http.client
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


class SpecRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        public = root / "public"
        (public / "css").mkdir(parents=True)
        (public / "protocols").mkdir()
        (public / "vectors").mkdir()
        (public / "index.html").write_text(
            '<link rel="stylesheet" href="css/general.css">'
            '<script src="book.js"></script>'
        )
        (public / "css/general.css").write_text("body { color: purple; }")
        (public / "book.js").write_text("window.specLoaded = true;")
        (public / "protocols/relay.html").write_text("Relay chapter")
        (public / "vectors/vauchi-protocol-vectors-v1.json").write_text('{"v":1}')
        (public / "build-info.json").write_text('{"sha":"routing-test"}')
        (public / "404.html").write_text("Page not found")
        root.chmod(0o755)
        for path in public.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        public.chmod(0o755)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]

        source = Path(__file__).resolve().parents[2] / "nginx.conf"
        server = source.read_text().replace(
            "listen 80 default_server;",
            f"listen 127.0.0.1:{cls.port} default_server;",
        ).replace("/usr/share/nginx/html", str(public))
        config = root / "nginx.conf"
        temp_paths = "".join(
            f"{name}_temp_path {root}/{name};\n"
            for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
        )
        config.write_text(
            f"daemon off; pid {root}/nginx.pid; error_log stderr notice;\n"
            "events {}\nhttp { access_log off; "
            + temp_paths + "types { text/css css; application/javascript js; "
            "application/json json; }\n" + server + "\n}\n"
        )
        cls.nginx = subprocess.Popen(
            [
                "nginx", "-e", "stderr",
                "-p", str(root), "-c", str(config),
            ],
            stderr=subprocess.PIPE,
            text=True,
        )
        cls.addClassCleanup(cls.stop_nginx)
        messages = []
        for line in cls.nginx.stderr:
            messages.append(line)
            if "start worker process " in line:
                break
        else:
            raise RuntimeError("nginx did not start: " + "".join(messages))

    @classmethod
    def stop_nginx(cls):
        cls.nginx.terminate()
        cls.nginx.wait(timeout=5)
        cls.nginx.stderr.close()

    def request(self, path, method="GET"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_spec_redirects_to_trailing_slash(self):
        status, headers, _ = self.request("/spec")
        self.assertEqual(status, 301)
        self.assertEqual(headers["Location"], "/spec/")

    def test_spec_redirect_preserves_query(self):
        status, headers, _ = self.request("/spec?search=mailbox%20token")
        self.assertEqual(status, 301)
        self.assertEqual(headers["Location"], "/spec/?search=mailbox%20token")

    def test_spec_slash_serves_index_without_redirect(self):
        status, headers, body = self.request("/spec/")
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        self.assertEqual(
            body, b'<link rel="stylesheet" href="css/general.css">'
            b'<script src="book.js"></script>'
        )

    def test_spec_assets_load_with_correct_content_types(self):
        for path, content_type, content in [
            ("/spec/css/general.css", "text/css", b"body { color: purple; }"),
            ("/spec/book.js", "application/javascript", b"window.specLoaded = true;"),
            (
                "/spec/vectors/vauchi-protocol-vectors-v1.json",
                "application/json",
                b'{"v":1}',
            ),
        ]:
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], content_type)
                self.assertEqual(body, content)

    def test_nested_chapter_loads(self):
        status, _, body = self.request("/spec/protocols/relay.html")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"Relay chapter")

    def test_missing_page_returns_404(self):
        status, _, body = self.request("/spec/missing-page")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"Page not found")

    def test_health_check_reads_build_provenance(self):
        status, _, body = self.request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"sha":"routing-test"}')

    def test_prefix_stripped_requests_work_too(self):
        status, _, body = self.request("/css/general.css")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"body { color: purple; }")


if __name__ == "__main__":
    unittest.main()
