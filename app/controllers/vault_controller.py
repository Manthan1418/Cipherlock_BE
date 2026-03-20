from flask import request, jsonify, current_app
import requests
from datetime import datetime
from app.extensions.firebase import get_firestore_base_url

_http = requests.Session()
REQUEST_TIMEOUT = 10


def _firestore_headers(token):
    return {"Authorization": f"Bearer {token}"}


def _string_field(fields, key, default=''):
    return fields.get(key, {}).get('stringValue', default)


def _doc_to_item(doc):
    fields = doc.get('fields', {})
    return {
        'id': doc['name'].split('/')[-1],
        'site': _string_field(fields, 'site'),
        'username': _string_field(fields, 'username'),
        'encryptedPassword': _string_field(fields, 'encryptedPassword'),
        'iv': _string_field(fields, 'iv'),
        'category': _string_field(fields, 'category') or 'General',
    }


def _validate_text_field(data, key, max_len, required=True):
    value = data.get(key)
    if value is None:
        if required:
            raise ValueError(f'{key} is required')
        return ''
    if not isinstance(value, str):
        raise ValueError(f'{key} must be a string')
    stripped = value.strip()
    if required and not stripped:
        raise ValueError(f'{key} cannot be empty')
    if len(value) > max_len:
        raise ValueError(f'{key} exceeds max length')
    return value


def _validate_vault_payload(data):
    _validate_text_field(data, 'site', 255)
    _validate_text_field(data, 'username', 255)
    _validate_text_field(data, 'encryptedPassword', 12000)
    iv = _validate_text_field(data, 'iv', 64)
    if len(iv) % 2 != 0:
        raise ValueError('iv must be valid hex')
    try:
        bytes.fromhex(iv)
    except ValueError as exc:
        raise ValueError('iv must be valid hex') from exc
    category = data.get('category', 'General')
    if category is not None:
        _validate_text_field({'category': category}, 'category', 60)

def add_password():
    uid = request.uid
    token = request.token
    data = request.get_json(silent=True) or {}
    
    required_fields = ['site', 'username', 'encryptedPassword', 'iv']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        _validate_vault_payload(data)
    except ValueError as err:
        return jsonify({'error': str(err)}), 400

    url = f"{get_firestore_base_url()}/users/{uid}/vault"
    
    firestore_data = {
        "fields": {
            "site": {"stringValue": data['site']},
            "username": {"stringValue": data['username']},
            "encryptedPassword": {"stringValue": data['encryptedPassword']},
            "iv": {"stringValue": data['iv']},
            "category": {"stringValue": data.get('category', 'General') or 'General'},
            "createdAt": {"timestampValue": datetime.utcnow().isoformat() + "Z"},
            "updatedAt": {"timestampValue": datetime.utcnow().isoformat() + "Z"}
        }
    }
    
    response = _http.post(url, json=firestore_data, headers=_firestore_headers(token), timeout=REQUEST_TIMEOUT)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Create Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Database operation failed'}), 500
        
    doc_id = response.json()['name'].split('/')[-1]
    return jsonify({'id': doc_id, 'message': 'Password stored successfully'}), 201

def get_password(entry_id):
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault/{entry_id}"
    response = _http.get(url, headers=_firestore_headers(token), timeout=REQUEST_TIMEOUT)
    
    if response.status_code == 404:
        return jsonify({'error': 'Password entry not found'}), 404
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Get Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Database operation failed'}), 500
        
    doc = response.json()
    item = _doc_to_item(doc)
    return jsonify(item), 200

def get_passwords():
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault"
    response = _http.get(url, headers=_firestore_headers(token), timeout=REQUEST_TIMEOUT)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore List Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Database operation failed'}), 500
        
    data = response.json()
    results = []
    
    if 'documents' in data:
        for doc in data['documents']:
            results.append(_doc_to_item(doc))
            
    return jsonify(results), 200

def delete_password(entry_id):
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault/{entry_id}"
    response = _http.delete(url, headers=_firestore_headers(token), timeout=REQUEST_TIMEOUT)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Delete Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Database operation failed'}), 500
    
    return jsonify({'message': 'Password deleted'}), 200

def update_password(entry_id):
    uid = request.uid
    token = request.token
    data = request.get_json(silent=True) or {}
    
    required_fields = ['site', 'username', 'encryptedPassword', 'iv']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        _validate_vault_payload(data)
    except ValueError as err:
        return jsonify({'error': str(err)}), 400

    url = f"{get_firestore_base_url()}/users/{uid}/vault/{entry_id}"
    
    firestore_data = {
        "fields": {
            "site": {"stringValue": data['site']},
            "username": {"stringValue": data['username']},
            "encryptedPassword": {"stringValue": data['encryptedPassword']},
            "iv": {"stringValue": data['iv']},
            "category": {"stringValue": data.get('category', 'General') or 'General'},
            "updatedAt": {"timestampValue": datetime.utcnow().isoformat() + "Z"}
        }
    }
    
    response = _http.patch(url, json=firestore_data, headers=_firestore_headers(token), timeout=REQUEST_TIMEOUT)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Update Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Database operation failed'}), 500
        
    return jsonify({'id': entry_id, 'message': 'Password updated successfully'}), 200
