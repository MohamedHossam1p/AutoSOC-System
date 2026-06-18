from http.server import HTTPServer, BaseHTTPRequestHandler
from pymongo import MongoClient
import json, logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
client = MongoClient('mongodb://localhost:27017/')
cases = client['autosoc']['cases']

def fix(doc):
    doc['_id'] = str(doc['_id'])
    return doc

class H(BaseHTTPRequestHandler):
    def j(self, code, data):
        b = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(b)
    def body(self):
        n = int(self.headers.get('Content-Length', 0))
        return json.loads(self.rfile.read(n)) if n else {}
    def do_OPTIONS(self): self.j(200, {})
    def do_GET(self):
        if self.path == '/cases':
            self.j(200, [fix(c) for c in cases.find().sort('created', -1)])
        else:
            self.j(404, {'error': 'not found'})
    def do_POST(self):
        if self.path == '/cases':
            b = self.body()
            cid = 'CASE-' + str(int(datetime.now(timezone.utc).timestamp() * 1000))[-6:]
            doc = {'case_id': cid, 'title': b.get('title',''), 'ip': b.get('ip',''), 'priority': b.get('priority','Medium'), 'status': b.get('status','Open'), 'analyst': b.get('analyst',''), 'created': datetime.now(timezone.utc).isoformat(), 'notes': b.get('notes',[])}
            r = cases.insert_one(doc)
            doc['_id'] = str(r.inserted_id)
            self.j(201, doc)
        elif '/notes' in self.path:
            cid = self.path.split('/')[2]
            b = self.body()
            note = {'text': b.get('text',''), 'author': b.get('author','Analyst'), 'time': datetime.now(timezone.utc).isoformat()}
            cases.update_one({'case_id': cid}, {'$push': {'notes': note}})
            self.j(200, {'note': note})
        else:
            self.j(404, {'error': 'not found'})
    def do_PUT(self):
        cid = self.path.split('/')[-1]
        b = self.body()
        allowed = ['title', 'ip', 'priority', 'status', 'analyst']
        cases.update_one({'case_id': cid}, {'$set': {k: v for k, v in b.items() if k in allowed}})
        doc = cases.find_one({'case_id': cid})
        self.j(200, fix(doc)) if doc else self.j(404, {'error': 'not found'})
    def do_DELETE(self):
        cid = self.path.split('/')[-1]
        cases.delete_one({'case_id': cid})
        self.j(200, {'message': 'deleted'})
    def log_message(self, *a): pass

print("Cases API on port 9205...")
HTTPServer(('0.0.0.0', 9205), H).serve_forever()
