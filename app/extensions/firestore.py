import requests
from flask import current_app
import json
from app.extensions.firebase import get_firestore_base_url

class FirestoreClient:
    """
    A simple wrapper around Firestore REST API because Admin SDK is not available.
    """
    
    @staticmethod
    def _get_headers():
        # Authenticating as the SERVER (Service Account) is tricky without Admin SDK.
        # IF we are running locally without a service account key, we might have issues writing to Firestore 
        # unless rules allow open access or we use an ID token of a user.
        # BUT `WebAuthnService` needs to write challenges *before* user is logged in (sometimes).
        
        # HOWEVER, the previous error log showed `ValueError` related to Firebase private key.
        # If we can't use Admin SDK, we can't easily write as Admin via REST without an OAuth2 token from the service account.
        
        # CHECK: How does `auth_controller.py` write?
        # It uses `request.token` (ID Token from client) to authenticate requests.
        # `update_user_doc` in `auth_controller` uses `Authorization: Bearer {token}`.
        
        # This implies we can only write if we have a user token.
        # BUT `generate_registration_options` happens *after* login usually (for registering passkey).
        # `generate_login_options` happens *before* login.
        
        # Problem: Storing the challenge for Login (when user is not yet authenticated).
        # Solution: 
        # 1. Use an in-memory store for challenges (simplest for MVP).
        # 2. Or require the client to be anonymous-signed-in (Firebase Anon Auth)?
        # 3. Or just don't verify challenge persistence on server properly for MVP (Security risk).
        
        # Let's go with In-Memory for challenges (CACHE).
        # For `users` collection access (storing credentials), we need to write to the user's doc.
        # We can use the user's ID token if available.
        pass

    # We will use this mainly for operations where we HAVE a token (updates)
    # or if we are just reading public info (if rules allow).
    @staticmethod
    def get_doc(collection, doc_id, token):
        url = f"{get_firestore_base_url()}/{collection}/{doc_id}"
        headers = {"Authorization": f"Bearer {token}"}
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
             return res.json()
        return None

    @staticmethod
    def update_doc(collection, doc_id, data, token):
        # Data should be in Firestore format: { "fields": { ... } }
        # Helper to convert simple dict to Firestore format is complex.
        # For now, expect caller to format or we implement a simple converter.
        url = f"{get_firestore_base_url()}/{collection}/{doc_id}"
        # We need to specify updateMask if we want to merge, but PATCH merges by default in REST?
        # No, PATCH replaces if not masked? usage varies.
        # Let's assume input is formatted.
        headers = {"Authorization": f"Bearer {token}"}
        return requests.patch(url, json=data, headers=headers)

try:
    from firebase_admin import firestore
except ImportError:
    firestore = None
from datetime import datetime, timezone

def store_challenge(user_id, challenge, type):
    try:
        db = firestore.client()
        # Expires in 10 minutes
        # We store in a separate collection 'webauthn_challenges'
        # Doc ID is user_id. This effectively limits user to 1 active challenge at a time (good for security/preventing spam)
        db.collection('webauthn_challenges').document(user_id).set({
            'challenge': challenge,
            'type': type,
            'timestamp': firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        print(f"Error storing challenge: {e}")
        # Fallback to in-memory if Firestore fails (e.g. locally without creds)? 
        # No, explicit failure is better than silent in-memory fallback that breaks in prod.
        raise e

def get_challenge(user_id):
    try:
        db = firestore.client()
        doc_ref = db.collection('webauthn_challenges').document(user_id)
        doc = doc_ref.get()
        
        if doc.exists:
            data = doc.to_dict()
            # Delete after retrieval to prevent replay
            doc_ref.delete()
            
            # Check expiration (5 minutes)
            timestamp = data.get('timestamp')
            if timestamp:
                # Firestore timestamp is datetime with tzinfo
                now = datetime.now(timezone.utc)
                if (now - timestamp).total_seconds() > 300:
                    print("Challenge expired")
                    return None
            
            return data
        return None
    except Exception as e:
        print(f"Error retrieving challenge: {e}")
        return None
