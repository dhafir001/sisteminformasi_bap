#!/usr/bin/env python3
"""
Simple backend server for the BAP management system (modernized).

- Tidak lagi menggunakan modul `cgi` (karena sudah dihapus di Python 3.11+).
- Upload file diproses dengan modul `email` dari stdlib.
- Semua API tetap sama dengan versi lama.

Menjalankan server:
    python server.py

Default port: 8000
"""

import http.server
import json
import os
import urllib.parse
import uuid
import datetime
import csv
import io
import shutil
import random
import string
import email
from email import policy

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data.json')
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')

ADMIN_USER = 'admin'
ADMIN_PASS = '12345'


def load_data():
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_data(data):
    tmp = DATA_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)


def secure_filename(filename):
    keep = string.ascii_letters + string.digits + '._-'
    cleaned = ''.join(c for c in filename if c in keep)
    return cleaned or 'upload'


class BAPHandler(http.server.SimpleHTTPRequestHandler):
    server_version = 'BAPServer/0.2'

    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path_parts = parsed.path.strip('/').split('/')

        if parsed.path.startswith('/api/'):
            if parsed.path == '/api/requests':
                self._handle_list_requests()
                return
            if parsed.path == '/api/requests/check':
                query = urllib.parse.parse_qs(parsed.query)
                term = query.get('query', [''])[0].strip()
                self._handle_search_requests(term)
                return
            if parsed.path == '/api/export':
                self._handle_export()
                return
            if len(path_parts) == 4 and path_parts[1] == 'api' and path_parts[2] == 'requests':
                req_id = path_parts[3]
                self._handle_get_request(req_id)
                return
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not Found'}).encode('utf-8'))
            return

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/api/login':
            self._handle_login()
            return
        if parsed.path == '/api/requests':
            self._handle_create_request()
            return
        self._set_headers(404)
        self.wfile.write(json.dumps({'error': 'Not Found'}).encode('utf-8'))

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) == 4 and path_parts[1] == 'api' and path_parts[2] == 'requests':
            req_id = path_parts[3]
            self._handle_update_request(req_id)
            return
        self._set_headers(404)
        self.wfile.write(json.dumps({'error': 'Not Found'}).encode('utf-8'))

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) == 4 and path_parts[1] == 'api' and path_parts[2] == 'requests':
            req_id = path_parts[3]
            self._handle_delete_request(req_id)
            return
        self._set_headers(404)
        self.wfile.write(json.dumps({'error': 'Not Found'}).encode('utf-8'))

    # ===============================
    # API implementations
    # ===============================

    def _handle_login(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data = json.loads(body.decode('utf-8'))
        except Exception:
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode('utf-8'))
            return
        user = data.get('username', '')
        pw = data.get('password', '')
        if user == ADMIN_USER and pw == ADMIN_PASS:
            self._set_headers(200)
            self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
        else:
            self._set_headers(401)
            self.wfile.write(json.dumps({'success': False, 'error': 'Invalid credentials'}).encode('utf-8'))

    def _handle_create_request(self):
        ctype = self.headers.get('Content-Type', '')
        if not ctype.startswith('multipart/form-data'):
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Content-Type must be multipart/form-data'}).encode('utf-8'))
            return

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        msg = email.message_from_bytes(
            b"Content-Type: " + ctype.encode() + b"\n\n" + body,
            policy=policy.default
        )

        fields = {}
        file_path = None
        filename = None

        for part in msg.iter_parts():
            if part.get_content_disposition() == 'form-data':
                name = part.get_param('name', header='content-disposition')
                filename = part.get_filename()
                if filename:
                    os.makedirs(UPLOAD_DIR, exist_ok=True)
                    safe_name = secure_filename(filename)
                    file_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4()}_{safe_name}")
                    with open(file_path, 'wb') as f:
                        f.write(part.get_payload(decode=True))
                else:
                    fields[name] = part.get_content().strip()

        required = ['nama', 'tanggal_lahir', 'nomor_hp', 'paspor', 'tujuan']
        if not all(fields.get(r) for r in required) or not file_path:
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Missing required fields'}).encode('utf-8'))
            return

        req_id = str(uuid.uuid4())
        year = datetime.datetime.now().year
        random_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        nomor_permohonan = f'BAP-{year}-{random_code}'

        now_iso = datetime.datetime.utcnow().isoformat()
        obj = {
            'id': req_id,
            'nomor_permohonan': nomor_permohonan,
            'nama': fields['nama'],
            'tanggal_lahir': fields['tanggal_lahir'],
            'nomor_hp': fields['nomor_hp'],
            'email': fields.get('email', ''),
            'paspor': fields['paspor'],
            'tujuan': fields['tujuan'],
            'lampiran': filename,
            'file_path': file_path,
            'status': 'pending',
            'catatan_admin': '',
            'schedule': {},
            'created_at': now_iso,
            'updated_at': now_iso
        }

        data = load_data()
        data.append(obj)
        save_data(data)

        self._set_headers(201)
        self.wfile.write(json.dumps({
            'success': True,
            'id': req_id,
            'nomor_permohonan': nomor_permohonan
        }).encode('utf-8'))

    def _handle_list_requests(self):
        data = load_data()
        filtered = [self._filter_obj(x) for x in data]
        self._set_headers(200)
        self.wfile.write(json.dumps(filtered).encode('utf-8'))

    def _handle_get_request(self, req_id: str):
        data = load_data()
        obj = next((x for x in data if x['id'] == req_id), None)
        if not obj:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
            return
        self._set_headers(200)
        self.wfile.write(json.dumps(self._filter_obj(obj)).encode('utf-8'))

    def _handle_update_request(self, req_id: str):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data_in = json.loads(body.decode('utf-8'))
        except Exception:
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode('utf-8'))
            return
        data = load_data()
        idx = next((i for i, x in enumerate(data) if x['id'] == req_id), None)
        if idx is None:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
            return
        obj = data[idx]
        if 'status' in data_in:
            obj['status'] = data_in['status']
        if 'catatan_admin' in data_in:
            obj['catatan_admin'] = data_in['catatan_admin']
        if 'schedule' in data_in and isinstance(data_in['schedule'], dict):
            obj['schedule'] = {
                'tanggal': data_in['schedule'].get('tanggal', ''),
                'jam_mulai': data_in['schedule'].get('jam_mulai', ''),
                'jam_selesai': data_in['schedule'].get('jam_selesai', ''),
                'lokasi': data_in['schedule'].get('lokasi', ''),
                'petugas': data_in['schedule'].get('petugas', ''),
            }
        obj['updated_at'] = datetime.datetime.utcnow().isoformat()
        data[idx] = obj
        save_data(data)
        self._set_headers(200)
        self.wfile.write(json.dumps({'success': True}).encode('utf-8'))

    def _handle_delete_request(self, req_id: str):
        data = load_data()
        idx = next((i for i, x in enumerate(data) if x['id'] == req_id), None)
        if idx is None:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
            return
        obj = data.pop(idx)
        file_path = obj.get('file_path')
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        save_data(data)
        self._set_headers(200)
        self.wfile.write(json.dumps({'success': True}).encode('utf-8'))

    def _handle_search_requests(self, term: str):
        term_lower = term.lower()
        data = load_data()
        matches = [
            self._filter_obj(x) for x in data
            if x['nomor_permohonan'].lower() == term_lower or x['paspor'].lower() == term_lower
        ]
        self._set_headers(200)
        self.wfile.write(json.dumps(matches).encode('utf-8'))

    def _handle_export(self):
        data = load_data()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Nomor Permohonan', 'Nama', 'Tanggal Lahir', 'Nomor HP',
                         'Email', 'Paspor', 'Tujuan', 'Lampiran', 'Status', 'Created At'])
        for x in data:
            writer.writerow([
                x['nomor_permohonan'], x['nama'], x['tanggal_lahir'],
                x['nomor_hp'], x['email'], x['paspor'], x['tujuan'],
                x.get('lampiran', ''), x['status'], x['created_at']
            ])
        csv_bytes = output.getvalue().encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="pengajuan_BAP.csv"')
        self.send_header('Content-Length', str(len(csv_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(csv_bytes)

    def _filter_obj(self, obj):
        filtered = obj.copy()
        filtered.pop('file_path', None)
        return filtered


def run(server_class=http.server.ThreadingHTTPServer, handler_class=BAPHandler):
    port = int(os.environ.get('PORT', '8000'))
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting BAP server on port {port}...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print('Server stopped.')


if __name__ == '__main__':
    run()
