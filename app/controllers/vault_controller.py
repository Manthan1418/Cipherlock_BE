from flask import request, jsonify, current_app
import requests
import json
from datetime import datetime
from app.extensions.firebase import get_firestore_base_url

def add_password():
    uid = request.uid
    token = request.token
    data = request.json
    
    required_fields = ['site', 'username', 'encryptedPassword', 'iv']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

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
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(url, json=firestore_data, headers=headers)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Create Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Firestore Error', 'details': response.text}), response.status_code
        
    doc_id = response.json()['name'].split('/')[-1]
    return jsonify({'id': doc_id, 'message': 'Password stored successfully'}), 201

def get_password(entry_id):
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 404:
        return jsonify({'error': 'Password entry not found'}), 404
    if response.status_code != 200:
        return jsonify({'error': 'Firestore Error', 'details': response.text}), response.status_code
        
    doc = response.json()
    fields = doc.get('fields', {})
    item = {
        'id': doc['name'].split('/')[-1],
        'site': fields.get('site', {}).get('stringValue', ''),
        'username': fields.get('username', {}).get('stringValue', ''),
        'encryptedPassword': fields.get('encryptedPassword', {}).get('stringValue', ''),
        'iv': fields.get('iv', {}).get('stringValue', ''),
        'category': fields.get('category', {}).get('stringValue', '') or 'General',
    }
    return jsonify(item), 200

def get_passwords():
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore List Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Firestore Error', 'details': response.text}), response.status_code
        
    data = response.json()
    results = []
    
    if 'documents' in data:
        for doc in data['documents']:
            fields = doc.get('fields', {})
            item = {
                'id': doc['name'].split('/')[-1],
                'site': fields.get('site', {}).get('stringValue', ''),
                'username': fields.get('username', {}).get('stringValue', ''),
                'encryptedPassword': fields.get('encryptedPassword', {}).get('stringValue', ''),
                'iv': fields.get('iv', {}).get('stringValue', ''),
                'category': fields.get('category', {}).get('stringValue', '') or 'General',
            }
            results.append(item)
            
    return jsonify(results), 200

def delete_password(entry_id):
    uid = request.uid
    token = request.token
    
    url = f"{get_firestore_base_url()}/users/{uid}/vault/{entry_id}"
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.delete(url, headers=headers)
    
    if response.status_code != 200:
        return jsonify({'error': 'Firestore Error', 'details': response.text}), response.status_code
    
    return jsonify({'message': 'Password deleted'}), 200

def update_password(entry_id):
    uid = request.uid
    token = request.token
    data = request.json
    
    required_fields = ['site', 'username', 'encryptedPassword', 'iv']
    if not all(k in data for k in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

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
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.patch(url, json=firestore_data, headers=headers)
    
    if response.status_code != 200:
        current_app.logger.error(f"Firestore Update Error: {response.status_code} {response.text}")
        return jsonify({'error': 'Firestore Error', 'details': response.text}), response.status_code
        
    return jsonify({'id': entry_id, 'message': 'Password updated successfully'}), 200
