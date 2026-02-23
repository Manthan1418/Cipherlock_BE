from firebase_admin import firestore
from datetime import datetime, timezone, timedelta
from flask import current_app

class FirestoreClient:
    """
    Wrapper around Firestore Admin SDK.
    """
    
    @staticmethod
    def get_db():
        try:
            return firestore.client()
        except Exception as e:
            print(f"Error getting Firestore client: {e}")
            return None

    @staticmethod
    def get_doc(collection, doc_id):
        db = FirestoreClient.get_db()
        if not db: return None
        
        try:
            doc_ref = db.collection(collection).document(doc_id)
            doc = doc_ref.get()
            if doc.exists:
                return doc.to_dict()
            return None
        except Exception as e:
            print(f"Error reading doc {collection}/{doc_id}: {e}")
            return None

    @staticmethod
    def update_doc(collection, doc_id, data):
        db = FirestoreClient.get_db()
        if not db: return False
        
        try:
            doc_ref = db.collection(collection).document(doc_id)
            doc_ref.set(data, merge=True)
            return True
        except Exception as e:
            print(f"Error updating doc {collection}/{doc_id}: {e}")
            return False

    @staticmethod
    def list_docs(collection):
        """List all documents in a collection/subcollection path."""
        db = FirestoreClient.get_db()
        if not db: return []
        
        try:
            docs = db.collection(collection).stream()
            return [doc.to_dict() for doc in docs]
        except Exception as e:
            print(f"Error listing docs in {collection}: {e}")
            return []

# Challenge Storage (No In-Memory Logic)
def store_challenge(user_id, challenge, type):
    db = FirestoreClient.get_db()
    if not db:
        raise Exception("Firestore not initialized, cannot store challenge")

    try:
        # Store in 'webauthn_challenges' collection
        # Expires in 5 minutes
        db.collection('webauthn_challenges').document(user_id).set({
            'challenge': challenge,
            'type': type,
            'created_at': firestore.SERVER_TIMESTAMP,
            'expires_at': datetime.now(timezone.utc) + timedelta(minutes=5)
        })
        print(f"Stored challenge for {user_id} in Firestore.")
    except Exception as e:
        print(f"Error storing challenge: {e}")
        raise e

def get_challenge(user_id):
    db = FirestoreClient.get_db()
    if not db:
        print("Firestore not initialized, cannot get challenge")
        return None

    try:
        doc_ref = db.collection('webauthn_challenges').document(user_id)
        doc = doc_ref.get()
        
        if not doc.exists:
            print(f"Challenge not found for {user_id}")
            return None
            
        data = doc.to_dict()
        
        # Verify expiration
        expires_at = data.get('expires_at')
        if expires_at:
            # Firestore returns datetime with timezone
            now = datetime.now(timezone.utc)
            if now > expires_at:
                print("Challenge expired")
                doc_ref.delete()
                return None
        
        # Delete after use to prevent replay
        doc_ref.delete()
        
        return data
    except Exception as e:
        print(f"Error retrieving challenge: {e}")
        return None
