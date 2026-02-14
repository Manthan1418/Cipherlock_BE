import requests
from flask import current_app
import firebase_admin
from firebase_admin import credentials

# We no longer use firebase_admin here because of the private key issues on the user's machine.
# Instead, we will helpers to interact with the REST APIs.

# Global to store init error for debugging
INIT_ERROR = None

def init_firebase(app):
    global INIT_ERROR
    try:
            # Clean up the private key
            raw_key = app.config['FIREBASE_PRIVATE_KEY']
            # Handle Vercel's double escaping, newlines, and potential wrapping quotes (single or double)
            private_key = raw_key.replace('\\n', '\n').replace('\\\\n', '\n').strip('"').strip("'")
            
            cert = {
                "type": "service_account",
                "project_id": app.config['FIREBASE_PROJECT_ID'],
                "private_key": private_key,
                "client_email": app.config['FIREBASE_CLIENT_EMAIL'],
                "token_uri": "https://oauth2.googleapis.com/token",
            }
            cred = credentials.Certificate(cert)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK Initialized Successfully")
    except Exception as e:
        import traceback
        raw_key_preview = repr(app.config.get('FIREBASE_PRIVATE_KEY', ''))[:100]
        INIT_ERROR = f"Error: {str(e)}\nRaw Key repr(): {raw_key_preview}...\nTrace:\n{traceback.format_exc()}"
        print(f"Failed to initialize Firebase Admin SDK: {e}")

def get_google_auth_url():
    api_key = current_app.config['FIREBASE_API_KEY']
    return f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"

def get_firestore_base_url():
    project_id = current_app.config['FIREBASE_PROJECT_ID']
    return f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
