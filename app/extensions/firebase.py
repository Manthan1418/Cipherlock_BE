import requests
from flask import current_app

# We no longer use firebase_admin here because of the private key issues on the user's machine.
# Instead, we will helpers to interact with the REST APIs.

def init_firebase(app):
    # No initialization needed for REST API approaches that don't use the Admin SDK instance.
    pass

def get_google_auth_url():
    api_key = current_app.config['FIREBASE_API_KEY']
    return f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"

def get_firestore_base_url():
    project_id = current_app.config['FIREBASE_PROJECT_ID']
    return f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
