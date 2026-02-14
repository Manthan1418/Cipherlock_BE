import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass # python-dotenv not installed, skipping (e.g. Vercel)

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'dev-key-please-change'
    FIREBASE_PROJECT_ID = os.environ.get('FIREBASE_PROJECT_ID')
    FIREBASE_CLIENT_EMAIL = os.environ.get('FIREBASE_CLIENT_EMAIL')
    FIREBASE_PRIVATE_KEY = os.environ.get('FIREBASE_PRIVATE_KEY')
    FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY')
    
    # WebAuthn Configuration
    RP_ID = os.environ.get('RP_ID') or 'localhost'
    RP_NAME = os.environ.get('RP_NAME') or 'Cipherlock Vault'
    ORIGIN = os.environ.get('ORIGIN') or 'http://localhost:5173'
