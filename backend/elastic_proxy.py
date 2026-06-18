from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request, ssl, json

ELASTIC_URL = "http://localhost:9200"
ELASTIC_USER = "elastic"
ELASTIC_PASS = "YOUR_PASSWORD_HERE"

class Proxy(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self): self.proxy()
    def do_POST(self): self.proxy()

    def proxy(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            body = None
            if self.command == 'POST':
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length) if length else None

            req = urllib.request.Request(ELASTIC_URL + self.path, data=body, method=self.command)
            import base64
            creds = base64.b64encode(f"{ELASTIC_USER}:{ELASTIC_PASS}".encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
            req.add_header('Content-Type', 'application/json')

            with urllib.request.urlopen(req, context=ctx) as r:
                data = r.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(data)
        except Exception as e:
            self.send_response(500)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, *args): pass

print("Elastic Proxy running on port 9202...")
HTTPServer(('0.0.0.0', 9202), Proxy).serve_forever()
