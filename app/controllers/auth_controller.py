from flask import request, jsonify, current_app
import pyotp
import requests
from app.extensions.firebase import get_firestore_base_url
from datetime import datetime

# Firestore Helpers
def get_user_doc(uid, token):
    url = f"{get_firestore_base_url()}/users/{uid}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    return response

def update_user_doc(uid, token, fields):
    url = f"{get_firestore_base_url()}/users/{uid}?updateMask.fieldPaths=twoFactorSecret&updateMask.fieldPaths=twoFactorEnabled"
    headers = {"Authorization": f"Bearer {token}"}
    
    # Firestore REST requires specific format
    data = {"fields": fields}
    
    # We use PATCH to update specific fields
    response = requests.patch(url, json=data, headers=headers)
    return response

def generate_2fa_secret():
    # 1. Generate a random secret
    secret = pyotp.random_base32()
    
    # 2. Create a provisioning URI for QR codes
    # Issuer = PassMan, User = current user's email (we'd need to fetch it, but for now generic is ok or we can pass it)
    # Let's try to get email from request if available, otherwise just use "User"
    email = request.args.get('email', 'User')
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PassMan")
    
    return jsonify({
        "secret": secret,
        "uri": uri
    }), 200

def enable_2fa():
    uid = request.uid
    token = request.token
    data = request.json
    
    secret = data.get('secret')
    code = data.get('code')
    
    if not secret or not code:
        return jsonify({'error': 'Secret and code are required'}), 400
        
    # Verify the code against the secret BEFORE saving
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        return jsonify({'error': 'Invalid 2FA code'}), 400
        
    # Save to Firestore
    fields = {
        "twoFactorSecret": {"stringValue": secret},
        "twoFactorEnabled": {"booleanValue": True}
    }
    
    response = update_user_doc(uid, token, fields)
    
    if response.status_code != 200:
        return jsonify({'error': 'Failed to save 2FA status', 'details': response.text}), 500
        
    return jsonify({'message': '2FA enabled successfully'}), 200

def disable_2fa():
    uid = request.uid
    token = request.token
    
    # We just explicitly set enabled to False and maybe clear secret
    fields = {
        "twoFactorEnabled": {"booleanValue": False},
        "twoFactorSecret": {"stringValue": ""} 
    }
    
    response = update_user_doc(uid, token, fields)
    
    if response.status_code != 200:
        return jsonify({'error': 'Failed to disable 2FA', 'details': response.text}), 500
        
    return jsonify({'message': '2FA disabled successfully'}), 200

def verify_2fa_login():
    # This endpoint checks if the code provided matches the stored secret
    # It assumes the user is already authenticated with Firebase (to get UID/Token)
    # In a real flow, this might happen differently, but for this MVP:
    # Client login -> Get Firebase Token -> Call this to "Unlock" 
    
    uid = request.uid
    token = request.token
    data = request.json
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
    if not totp.verify(code):
        return jsonify({'error': 'Invalid 2FA code'}), 401
        
    return jsonify({'message': 'verified'}), 200

def get_2fa_status():
    uid = request.uid
    token = request.token
    
    response = get_user_doc(uid, token)
    
    # If user doc doesn't exist yet, it's fine, 2FA is false
    if response.status_code == 404:
        return jsonify({'enabled': False}), 200
        
    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch status', 'details': response.text}), 500
        
    user_data = response.json()
    fields = user_data.get('fields', {})
    enabled = fields.get('twoFactorEnabled', {}).get('booleanValue', False)
    
    return jsonify({'enabled': enabled}), 200
