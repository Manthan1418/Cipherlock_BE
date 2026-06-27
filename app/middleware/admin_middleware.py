from functools import wraps
from flask import request, jsonify
from app.config import Config
import secrets
import time
import requests
from threading import Lock
from app.extensions.firebase import get_google_auth_url

_admin_sessions = {}
_admin_sessions_lock = Lock()
ADMIN_SESSION_TTL = 86400
_http = requests.Session()


def create_admin_session():
    token = secrets.token_urlsafe(32)
    with _admin_sessions_lock:
        _admin_sessions[token] = time.time() + ADMIN_SESSION_TTL
    return token


def validate_admin_session(token):
    with _admin_sessions_lock:
        entry = _admin_sessions.get(token)
        if not entry:
            return False
        if time.time() > entry:
            _admin_sessions.pop(token, None)
            return False
        return True


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        admin_token = request.headers.get('X-Admin-Token')

        # Method 1: Admin session token
        if admin_token and validate_admin_session(admin_token):
            request.uid = 'admin'
            request.email = 'admin@cipherlock'
            return f(*args, **kwargs)

        # Method 2: Firebase auth with admin email
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            try:
                url = get_google_auth_url()
                response = _http.post(url, json={'idToken': token}, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'users' in data and data['users']:
                        user_data = data['users'][0]
                        email = user_data.get('email', '')
                        if email in Config.ADMIN_EMAILS:
                            request.uid = user_data['localId']
                            request.email = email
                            request.token = token
                            return f(*args, **kwargs)
            except Exception:
                pass

        return jsonify({'error': 'Admin access required'}), 403
    return decorated_function
