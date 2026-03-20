import secrets
import time
import hashlib
from firebase_admin import firestore

def _hash_token(token):
    if not token:
        return None
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _get_db():
    """Lazily get Firestore client to ensure Firebase is initialized first."""
    return firestore.client()


def create_twofactor_session(uid, token=None, ttl_seconds=12 * 60 * 60):
    session_id = secrets.token_urlsafe(32)
    record = {
        'uid': uid,
        'token_hash': _hash_token(token),
        'expires_at': time.time() + ttl_seconds,
    }
    _get_db().collection('twofactor_sessions').document(session_id).set(record)
    return session_id


def validate_twofactor_session(uid, session_id, token=None):
    if not session_id:
        return False

    now = time.time()
    doc_ref = _get_db().collection('twofactor_sessions').document(session_id)
    doc = doc_ref.get()
    
    if not doc.exists:
        return False
        
    record = doc.to_dict()
    if record['expires_at'] <= now:
        doc_ref.delete()
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
    _get_db().collection('twofactor_sessions').document(session_id).delete()
