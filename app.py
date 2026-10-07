# app.py - Backend REST API con JWT y Zero Trust
import http.server
import socketserver
import json
import base64
import hmac
import hashlib
import time

PORT = 3000
SECRET_KEY = "mi_secreto_super_seguro_jwt_2026"

def b64_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def generate_jwt(user):
    header = b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64_encode(json.dumps({"user": user, "exp": int(time.time()) + 3600}).encode())
    signature_input = f"{header}.{payload}".encode()
    signature = b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"

def verify_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        header, payload, signature = parts
        signature_input = f"{header}.{payload}".encode()
        expected_sig = b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected_sig):
            return False
        
        # Verificar expiración
        payload_decoded = json.loads(base64.urlsafe_b64decode(payload + '==').decode())
        if payload_decoded.get('exp', 0) < time.time():
            return False
        return True
    except Exception:
        return False

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/login':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                if data.get('usuario') == 'eloisa' and data.get('password') == '123456':
                    token = generate_jwt('eloisa')
                    response = {"status": "success", "token": token, "mensaje": "Autenticacion exitosa"}
                    self.send_response(200)
                else:
                    response = {"status": "error", "mensaje": "Credenciales invalidas"}
                    self.send_response(401)
            except Exception:
                response = {"status": "error", "mensaje": "Formato JSON invalido"}
                self.send_response(400)
            
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        if self.path == '/api/dashboard':
            auth_header = self.headers.get('Authorization', '')
            token = auth_header.replace('Bearer ', '').strip() if auth_header.startswith('Bearer ') else None
            
            if token and verify_jwt(token):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "mensaje": "Bienvenida al Dashboard protegido, Eloisa",
                    "data": "Informacion confidencial resguardada bajo arquitectura Zero Trust"
                }).encode())
            else:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No autorizado, Token JWT ausente o invalido"}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.end_headers()

with socketserver.TCPServer(('0.0.0.0', PORT), Handler) as httpd:
    print(f"Servidor Backend listo en puerto {PORT}")
    httpd.serve_forever()