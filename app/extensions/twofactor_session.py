import secrets
import time
import hashlib
from threading import Lock

_sessions = {}
_lock = Lock()


def _hash_token(token):
    if not token:
        return None
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_twofactor_session(uid, token=None, ttl_seconds=12 * 60 * 60):
    session_id = secrets.token_urlsafe(32)
    record = {
        'uid': uid,
        'token_hash': _hash_token(token),
        'expires_at': time.time() + ttl_seconds,
    }
    with _lock:
        _sessions[session_id] = record
    return session_id


def validate_twofactor_session(uid, session_id, token=None):
    if not session_id:
        return False

    now = time.time()
    with _lock:
        record = _sessions.get(session_id)
        if not record:
            return False
        if record['expires_at'] <= now:
            _sessions.pop(session_id, None)
            return False
        if record['uid'] != uid:
            return False

        expected_token_hash = record.get('token_hash')
        if expected_token_hash and _hash_token(token) != expected_token_hash:
            return False

        return True


def revoke_twofactor_session(session_id):
    if not session_id:
        return
    with _lock:
        _sessions.pop(session_id, None)
