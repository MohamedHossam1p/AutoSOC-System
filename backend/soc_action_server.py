from http.server import HTTPServer, BaseHTTPRequestHandler
import json, subprocess, re, logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

API_TOKEN = "soc-secret-2025-autosoc"

def is_valid_ip(ip):
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip or ''))

def run_iptables(*args):
    result = subprocess.run(
        ['iptables'] + list(args),
        capture_output=True, text=True
    )
    return result.returncode, result.stdout, result.stderr

class SOCHandler(BaseHTTPRequestHandler):

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def verify_token(self):
        return self.headers.get('Authorization') == f'Bearer {API_TOKEN}'

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_POST(self):
        if not self.verify_token():
            self.send_json(401, {'error': 'Unauthorized'})
            return

        body = self.read_body()
        ip   = body.get('ip', '').strip()

        # ── /block ────────────────────────────────────────────────────
        if self.path == '/block':
            if not is_valid_ip(ip):
                self.send_json(400, {'error': f'Invalid IP: {ip}'})
                return
            run_iptables('-A', 'INPUT',   '-s', ip, '-j', 'DROP')
            run_iptables('-A', 'FORWARD', '-s', ip, '-j', 'DROP')
            logging.info(f'BLOCKED: {ip}')
            self.send_json(200, {'action': 'blocked', 'ip': ip})

        # ── /unblock ──────────────────────────────────────────────────
        elif self.path == '/unblock':
            if not is_valid_ip(ip):
                self.send_json(400, {'error': f'Invalid IP: {ip}'})
                return
            run_iptables('-D', 'INPUT',   '-s', ip, '-j', 'DROP')
            run_iptables('-D', 'FORWARD', '-s', ip, '-j', 'DROP')
            logging.info(f'UNBLOCKED: {ip}')
            self.send_json(200, {'action': 'unblocked', 'ip': ip})

        # ── /check ────────────────────────────────────────────────────
        elif self.path == '/check':
            if not is_valid_ip(ip):
                self.send_json(400, {'error': f'Invalid IP: {ip}'})
                return
            code, _, _ = run_iptables('-C', 'INPUT', '-s', ip, '-j', 'DROP')
            is_blocked  = (code == 0)
            logging.info(f'CHECK: {ip} → {"BLOCKED" if is_blocked else "NOT BLOCKED"}')
            self.send_json(200, {'ip': ip, 'is_blocked': is_blocked})

        # ── /list-blocked ─────────────────────────────────────────────
        elif self.path == '/list-blocked':
            _, output, _ = run_iptables('-L', 'INPUT', '-n', '--line-numbers')
            # استخرج بس الـ DROP rules
            lines = [
                line for line in output.splitlines()
                if 'DROP' in line
            ]
            # استخرج الـ IPs
            blocked_ips = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    blocked_ips.append(parts[3])  # source IP column
            logging.info(f'LIST-BLOCKED: {len(blocked_ips)} IPs')
            self.send_json(200, {
                'count':       len(blocked_ips),
                'blocked_ips': blocked_ips
            })

        # ── /flush ────────────────────────────────────────────────────
        elif self.path == '/flush':
            run_iptables('-F', 'INPUT')
            run_iptables('-F', 'FORWARD')
            logging.info('FLUSH: All iptables rules cleared')
            self.send_json(200, {
                'action':  'flushed',
                'message': 'All firewall rules cleared'
            })

        else:
            self.send_json(404, {'error': f'Unknown endpoint: {self.path}'})

    def log_message(self, format, *args):
        pass  # suppress default HTTP access log


print("=" * 45)
print("  SOC Action Server — port 9204")
print("  Endpoints: /block /unblock /check")
print("             /list-blocked /flush")
print("=" * 45)
HTTPServer(('0.0.0.0', 9204), SOCHandler).serve_forever()
