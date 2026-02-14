import requests
from flask import current_app
import firebase_admin
from firebase_admin import credentials

# We no longer use firebase_admin here because of the private key issues on the user's machine.
# Instead, we will helpers to interact with the REST APIs.

def init_firebase(app):
    try:
        if not firebase_admin._apps:
            # Construct certificate dict
            cert = {
                "type": "service_account",
                "project_id": app.config['FIREBASE_PROJECT_ID'],
                "private_key": app.config['FIREBASE_PRIVATE_KEY'].replace('\\n', '\n').replace('\\\\n', '\n').strip('"'),
                "client_email": app.config['FIREBASE_CLIENT_EMAIL'],
                "token_uri": "https://oauth2.googleapis.com/token",
            }
            cred = credentials.Certificate(cert)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK Initialized Successfully")
    except Exception as e:
        print(f"Failed to initialize Firebase Admin SDK: {e}")

def get_google_auth_url():
    api_key = current_app.config['FIREBASE_API_KEY']
    return f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"

def get_firestore_base_url():
    project_id = current_app.config['FIREBASE_PROJECT_ID']
    return f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
