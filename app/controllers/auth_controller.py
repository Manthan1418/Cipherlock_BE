from flask import request, jsonify, current_app
import pyotp
import requests
import secrets
from app.extensions.firebase import get_firestore_base_url
from app.extensions.twofactor_session import create_twofactor_session

_http = requests.Session()
REQUEST_TIMEOUT = 10

# Firestore Helpers
def get_user_doc(uid, token):
    url = f"{get_firestore_base_url()}/users/{uid}"
    headers = {"Authorization": f"Bearer {token}"}
    response = _http.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def update_user_doc(uid, token, fields, field_paths=None):
    field_paths = field_paths or list(fields.keys())
    update_mask = '&'.join([f"updateMask.fieldPaths={field}" for field in field_paths])
    url = f"{get_firestore_base_url()}/users/{uid}?{update_mask}"
    headers = {"Authorization": f"Bearer {token}"}
    
    # Firestore REST requires specific format
    data = {"fields": fields}
    
    # We use PATCH to update specific fields
    response = _http.patch(url, json=data, headers=headers, timeout=REQUEST_TIMEOUT)
    return response

def generate_2fa_secret():
    # 1. Generate a random secret
    secret = pyotp.random_base32()
    
    # 2. Create a provisioning URI for QR codes
    # Issuer = PassMan, User = current user's email (we'd need to fetch it, but for now generic is ok or we can pass it)
    # Let's try to get email from request if available, otherwise just use "User"
    email = getattr(request, 'email', None) or 'User'
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="Cipherlock")
    
    return jsonify({
        "secret": secret,
        "uri": uri
    }), 200

def enable_2fa():
    uid = request.uid
    token = request.token
    data = request.get_json(silent=True) or {}
    
    secret = data.get('secret')
    code = data.get('code')
    
    if not secret or not code:
        return jsonify({'error': 'Secret and code are required'}), 400
        
    # Verify the code against the secret BEFORE saving
    totp = pyotp.TOTP(secret)
    # Allow 1 step window (30s) for time drift
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid 2FA code'}), 400
        
    # Save to Firestore
    fields = {
        "twoFactorSecret": {"stringValue": secret},
        "twoFactorEnabled": {"booleanValue": True}
    }
    
    response = update_user_doc(uid, token, fields, field_paths=['twoFactorSecret', 'twoFactorEnabled'])
    
    if response.status_code != 200:
        current_app.logger.error(f"Failed to save 2FA status: {response.status_code} {response.text}")
        return jsonify({'error': 'Failed to save 2FA status'}), 500
        
    return jsonify({'message': '2FA enabled successfully'}), 200

def disable_2fa():
    uid = request.uid
    token = request.token
    
    # We just explicitly set enabled to False and maybe clear secret
    fields = {
        "twoFactorEnabled": {"booleanValue": False},
        "twoFactorSecret": {"stringValue": ""} 
    }
    
    response = update_user_doc(uid, token, fields, field_paths=['twoFactorSecret', 'twoFactorEnabled'])
    
    if response.status_code != 200:
        current_app.logger.error(f"Failed to disable 2FA: {response.status_code} {response.text}")
        return jsonify({'error': 'Failed to disable 2FA'}), 500
        
    return jsonify({'message': '2FA disabled successfully'}), 200

def verify_2fa_login():
    # This endpoint checks if the code provided matches the stored secret
    # It assumes the user is already authenticated with Firebase (to get UID/Token)
    # In a real flow, this might happen differently, but for this MVP:
    # Client login -> Get Firebase Token -> Call this to "Unlock" 
    
    uid = request.uid
    token = request.token
    data = request.get_json(silent=True) or {}
    code = data.get('code')
    
    if not code:
        return jsonify({'error': 'Code is required'}), 400
        
    # Fetch User Secret
    response = get_user_doc(uid, token)
    if response.status_code != 200:
         return jsonify({'error': 'Failed to fetch user profile'}), 500
         
    user_data = response.json()
    fields = user_data.get('fields', {})
    
    enabled = fields.get('twoFactorEnabled', {}).get('booleanValue', False)
    
    # If not enabled, verification is trivially true (or we can say "not enabled")
    # But usually this endpoint is called ONLY if enabled.
    if not enabled:
        return jsonify({'message': '2FA is not enabled'}), 200
        
    secret = fields.get('twoFactorSecret', {}).get('stringValue')
    if not secret:
        return jsonify({'error': '2FA is enabled but no secret found'}), 500
        
    totp = pyotp.TOTP(secret)
    # Allow 1 step window (30s) for time drift
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Invalid 2FA code'}), 401

    twofactor_session = create_twofactor_session(uid, token=token)
    return jsonify({'message': 'verified', 'twoFactorSession': twofactor_session}), 200

def get_2fa_status():
    uid = request.uid
    token = request.token
    
    response = get_user_doc(uid, token)
    
    # If user doc doesn't exist yet, it's fine, 2FA is false
    if response.status_code == 404:
        return jsonify({'enabled': False}), 200
        
    if response.status_code != 200:
        current_app.logger.error(f"Failed to fetch 2FA status: {response.status_code} {response.text}")
        return jsonify({'error': 'Failed to fetch status'}), 500
        
    user_data = response.json()
    fields = user_data.get('fields', {})
    enabled = fields.get('twoFactorEnabled', {}).get('booleanValue', False)
    
    return jsonify({'enabled': enabled}), 200


def get_or_create_kdf_salt():
    uid = request.uid
    token = request.token

    response = get_user_doc(uid, token)
    if response.status_code == 200:
        user_data = response.json()
        fields = user_data.get('fields', {})
        existing_salt = fields.get('kdfSalt', {}).get('stringValue')
        if existing_salt:
            return jsonify({'salt': existing_salt}), 200

    salt = secrets.token_hex(16)
    fields = {
        'kdfSalt': {'stringValue': salt}
    }
    update_response = update_user_doc(uid, token, fields, field_paths=['kdfSalt'])

    if update_response.status_code != 200:
        current_app.logger.error(f"Failed to persist KDF salt: {update_response.status_code} {update_response.text}")
        return jsonify({'error': 'Failed to initialize key salt'}), 500

    return jsonify({'salt': salt}), 200

# ==========================================
# WEBAUTHN CONTROLLER METHODS
# ==========================================

from app.services.webauthn_service import WebAuthnService

def webauthn_register_options():
    try:
        uid = request.uid
        # Fallback if email is missing (e.g. phone auth)
        email = getattr(request, 'email', None) or f"user-{uid[:8]}@passman.local"
        
        options = WebAuthnService.generate_registration_options(uid, email)
        return current_app.response_class(options, mimetype='application/json'), 200
    except Exception as e:
        current_app.logger.exception(f"WebAuthn Options Error: {str(e)}")
        return jsonify({'error': 'Failed to generate WebAuthn options'}), 500

def webauthn_register_verify():
    uid = request.uid
    token = request.token
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({'error': 'Invalid request body'}), 400
    
    try:
        result = WebAuthnService.verify_registration_response(uid, data, token)
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.exception(f"WebAuthn Reg Error: {str(e)}")
        return jsonify({'error': 'Failed to verify registration response'}), 500

def webauthn_login_options():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email')
        uid = None
        
        if getattr(request, 'uid', None):
            uid = request.uid
        elif data.get('uid'):
            uid = data.get('uid')
        
        options = WebAuthnService.generate_login_options(uid)
        return jsonify(options), 200
    except Exception as e:
        current_app.logger.exception(f"WebAuthn login options error: {str(e)}")
        return jsonify({'error': 'Failed to generate login options'}), 400

def webauthn_login_verify():
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400
        uid = data.get('uid')
        session_id = data.get('sessionId')
        
        if not session_id:
            return jsonify({'error': 'sessionId is required for verification'}), 400

        # Remove 'uid' and 'sessionId' from data so it doesn't confuse WebAuthn parser if it's strict
        data_for_service = data.copy()
        for key in ['uid', 'sessionId']:
            if key in data_for_service:
                del data_for_service[key]

        result = WebAuthnService.verify_login_response(session_id, data_for_service, user_id=uid)
        actual_uid = result.get('uid')
        
        if not actual_uid:
             return jsonify({'error': 'Could not determine user ID from credentials'}), 400
        
        from firebase_admin import auth
        custom_token = auth.create_custom_token(actual_uid)
        twofactor_session = create_twofactor_session(actual_uid)
        
        return jsonify({
            'verified': True,
            'token': custom_token.decode('utf-8') if isinstance(custom_token, bytes) else custom_token,
            'sign_count': result.get('new_sign_count'),
            'twoFactorSession': twofactor_session,
        }), 200
        
    except Exception as e:
        current_app.logger.exception(f"WebAuthn Login Error: {str(e)}")
        return jsonify({'error': 'WebAuthn login verification failed'}), 500
