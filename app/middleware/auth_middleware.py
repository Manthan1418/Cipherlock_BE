from functools import wraps
from flask import request, jsonify
import requests
import time
from threading import Lock
from app.extensions.firebase import get_google_auth_url
from app.extensions.firebase import get_firestore_base_url
from app.extensions.twofactor_session import validate_twofactor_session

AUTH_CACHE_TTL_SECONDS = 60
_auth_cache = {}
_auth_cache_lock = Lock()
_http = requests.Session()

USER_2FA_CACHE_TTL_SECONDS = 60
_user_2fa_cache = {}
_user_2fa_cache_lock = Lock()


def _is_twofactor_enabled(uid, token):
    now = time.time()
    cache_key = f"{uid}:{token[:16]}"

    with _user_2fa_cache_lock:
        cached = _user_2fa_cache.get(cache_key)
        if cached and cached['expires_at'] > now:
            return cached['enabled']
        if cached:
            _user_2fa_cache.pop(cache_key, None)

    url = f"{get_firestore_base_url()}/users/{uid}"
    headers = {"Authorization": f"Bearer {token}"}
    response = _http.get(url, headers=headers, timeout=10)

    enabled = False
    if response.status_code == 200:
        data = response.json()
        fields = data.get('fields', {})
        enabled = fields.get('twoFactorEnabled', {}).get('booleanValue', False)

    with _user_2fa_cache_lock:
        _user_2fa_cache[cache_key] = {
            'enabled': enabled,
            'expires_at': now + USER_2FA_CACHE_TTL_SECONDS,
        }

    return enabled

def verify_firebase_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No Authorization header provided'}), 401

        try:
            parts = auth_header.split(" ", 1)
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({'error': 'Invalid Authorization header format'}), 401

            token = parts[1]

            cached = None
            now = time.time()
            with _auth_cache_lock:
                cached = _auth_cache.get(token)
                if cached and cached['expires_at'] > now:
                    request.uid = cached['uid']
                    request.email = cached.get('email')
                    request.token = token
                    return f(*args, **kwargs)
                if cached:
                    _auth_cache.pop(token, None)
            
            # Verify token using Google Identity Toolkit REST API
            # This avoids needing the Admin SDK and Private Key
            url = get_google_auth_url()
            response = _http.post(url, json={'idToken': token}, timeout=10)
            
            if response.status_code != 200:
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            data = response.json()
            # The response contains 'users' list. The first one is our user.
            if 'users' not in data or not data['users']:
                 return jsonify({'error': 'Token verification failed'}), 401
                 
            user_data = data['users'][0]
            request.uid = user_data['localId']
            request.email = user_data.get('email')
            request.token = token # Store token to forward to Firestore

            with _auth_cache_lock:
                _auth_cache[token] = {
                    'uid': request.uid,
                    'email': request.email,
                    'expires_at': now + AUTH_CACHE_TTL_SECONDS,
                }
            
        except Exception as e:
            return jsonify({'error': 'Token validation error'}), 401

        return f(*args, **kwargs)
    return decorated_function


def require_twofactor_verification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        uid = getattr(request, 'uid', None)
        token = getattr(request, 'token', None)

        if not uid or not token:
            return jsonify({'error': 'Unauthorized'}), 401

        try:
            if not _is_twofactor_enabled(uid, token):
                return f(*args, **kwargs)

            session_id = request.headers.get('X-2FA-Session')
            if not validate_twofactor_session(uid, session_id, token=token):
                return jsonify({'error': '2FA verification required'}), 403

            return f(*args, **kwargs)
        except Exception:
            return jsonify({'error': '2FA verification failed'}), 403

    return decorated_function
