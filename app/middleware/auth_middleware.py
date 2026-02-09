from functools import wraps
from flask import request, jsonify
import requests
from app.extensions.firebase import get_google_auth_url

def verify_firebase_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No Authorization header provided'}), 401

        try:
            token = auth_header.split(" ")[1]
            
            # Verify token using Google Identity Toolkit REST API
            # This avoids needing the Admin SDK and Private Key
            url = get_google_auth_url()
            response = requests.post(url, json={'idToken': token})
            
            if response.status_code != 200:
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            data = response.json()
            # The response contains 'users' list. The first one is our user.
            if 'users' not in data or not data['users']:
                 return jsonify({'error': 'Token verification failed'}), 401
                 
            user_data = data['users'][0]
            request.uid = user_data['localId']
            request.token = token # Store token to forward to Firestore
            
        except Exception as e:
            return jsonify({'error': 'Token validation error', 'details': str(e)}), 401

        return f(*args, **kwargs)
    return decorated_function
