"""Real boundaries for tests: a local HTTP server and Wazuh's unix datagram queue."""
import importlib.util
import json
import os
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.join(os.path.dirname(__file__), '..')


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), os.path.join(ROOT, 'integrations', f'{name}.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeAPI:
    """routes: {path_without_query: (status, json_body)}; records every request."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []
        api = self

        class H(BaseHTTPRequestHandler):
            def handle_one(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                api.requests.append({'method': self.command, 'path': self.path,
                                     'headers': dict(self.headers), 'body': json.loads(body) if body else None})
                status, out = api.routes.get(self.path.split('?')[0], (404, {'error': 'Not found'}))
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = handle_one

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.srv.server_port}'
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class FakeQueue:
    """Stands in for /var/ossec/queue/sockets/queue."""

    def __init__(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'queue')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.path)
        self.sock.setblocking(False)

    def messages(self):
        out = []
        while True:
            try:
                out.append(self.sock.recv(65536).decode())
            except BlockingIOError:
                return out

    def events(self):
        return [json.loads(m.split('mlab:', 1)[1]) for m in self.messages()]

    def close(self):
        self.sock.close()
