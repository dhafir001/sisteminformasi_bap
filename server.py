#!/usr/bin/env python3
"""
Simple backend server for the BAP management system (MySQL version).

- Tidak lagi pakai file JSON/SQLite.
- Data disimpan langsung ke MySQL (contoh untuk Railway).
- Semua API tetap sama.

Menjalankan server:
    python server.py
"""

import http.server
import json
import os
import urllib.parse
import uuid
import datetime
import csv
import io
import random
import string
import email
from email import policy
import mysql.connector

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')

ADMIN_USER = 'admin'
ADMIN_PASS = '12345'

# koneksi MySQL (pakai env dari Railway)
def get_db():
    return mysql.connector.connect(
        host=os.environ.get("MYSQLHOST", "localhost"),
        user=os.environ.get("MYSQLUSER", "root"),
        password=os.environ.get("MYSQLPASSWORD", ""),
        database=os.environ.get("MYSQLDATABASE", "bap"),
        port=os.environ.get("MYSQLPORT", 3306)
    )

# buat tabel kalau belum ada
def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id VARCHAR(64) PRIMARY KEY,
        nomor_permohonan VARCHAR(50),
        nama VARCHAR(100),
        tanggal_lahir VARCHAR(20),
        nomor_hp VARCHAR(20),
        email VARCHAR(100),
        paspor VARCHAR(50),
        tujuan TEXT,
        lampiran VARCHAR(200),
        file_path VARCHAR(255),
        status VARCHAR(20),
        catatan_admin TEXT,
        schedule JSON,
        created_at TIMESTAMP,
        updated_at TIMESTAMP
    )
    """)
    conn.commit()
    cur.close()
    conn.close()

def secure_filename(filename):
    keep = string.ascii_letters + string.digits + '._-'
    cleaned = ''.join(c for c in filename if c in keep)
    return cleaned or 'upload'


class BAPHandler(http.server.SimpleHTTPRequestHandler):
    server_version = 'BAPServer/0.3'

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

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO requests 
            (id, nomor_permohonan, nama, tanggal_lahir, nomor_hp, email, paspor, tujuan,
             lampiran, file_path, status, catatan_admin, schedule, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            req_id, nomor_permohonan, fields['nama'], fields['tanggal_lahir'], fields['nomor_hp'],
            fields.get('email', ''), fields['paspor'], fields['tujuan'],
            filename, file_path, 'pending', '', json.dumps({}), now_iso, now_iso
        ))
        conn.commit()
        cur.close()
        conn.close()

        self._set_headers(201)
        self.wfile.write(json.dumps({
            'success': True,
            'id': req_id,
            'nomor_permohonan': nomor_permohonan
        }).encode('utf-8'))

    def _handle_list_requests(self):
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM requests")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        self._set_headers(200)
        self.wfile.write(json.dumps(rows).encode('utf-8'))

    def _handle_get_request(self, req_id: str):
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM requests WHERE id=%s", (req_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
            return
        self._set_headers(200)
        self.wfile.write(json.dumps(row).encode('utf-8'))

    def _handle_update_request(self, req_id: str):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        try:
            data_in = json.loads(body.decode('utf-8'))
        except Exception:
            self._set_headers(400)
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode('utf-8'))
            return

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM requests WHERE id=%s", (req_id,))
        if not cur.fetchone():
            self._set_headers(404)
            self.wfile.write(json.dumps({'error': 'Not found'}).encode('utf-8'))
            return

        cur.execute("""
            UPDATE requests SET status=%s, catatan_admin=%s, schedule=%s, updated_at=%s WHERE id=%s
        """, (
            data_in.get('status', 'pending'),
            data_in.get('catatan_admin', ''),
            json.dumps(data_in.get('schedule', {})),
            datetime.datetime.utcnow().isoformat(),
            req_id
        ))
        conn.commit()
        cur.close()
        conn.close()
        self._set_headers(200)
        self.wfile.write(json.dumps({'success': True}).encode('utf-8'))

    def _handle_delete_request(self, req_id: str):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM requests WHERE id=%s", (req_id,))
        conn.commit()
        cur.close()
        conn.close()
        self._set_headers(200)
        self.wfile.write(json.dumps({'success': True}).encode('utf-8'))

    def _handle_search_requests(self, term: str):
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM requests WHERE nomor_permohonan=%s OR paspor=%s", (term, term))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        self._set_headers(200)
        self.wfile.write(json.dumps(rows).encode('utf-8'))

    def _handle_export(self):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT nomor_permohonan,nama,tanggal_lahir,nomor_hp,email,paspor,tujuan,lampiran,status,created_at FROM requests")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Nomor Permohonan','Nama','Tanggal Lahir','Nomor HP','Email','Paspor','Tujuan','Lampiran','Status','Created At'])
        for row in rows:
            writer.writerow(row)
        csv_bytes = output.getvalue().encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="pengajuan_BAP.csv"')
        self.send_header('Content-Length', str(len(csv_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(csv_bytes)


def run(server_class=http.server.ThreadingHTTPServer, handler_class=BAPHandler):
    port = int(os.environ.get('PORT', '8000'))
    server_address = ('', port)
    init_db()
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
