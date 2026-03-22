import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Config:
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development').lower()
    IS_DEV = FLASK_ENV in ('development', 'dev', 'local', 'test')
    IS_PRODUCTION = bool(os.environ.get('RENDER')) or os.environ.get('VERCEL_ENV') == 'production' or FLASK_ENV == 'production'

    _secret = os.environ.get('FLASK_SECRET_KEY')
    if not _secret and IS_PRODUCTION:
        raise RuntimeError('FLASK_SECRET_KEY must be set in non-development environments')
    SECRET_KEY = _secret or os.urandom(32).hex()
    
    # Firebase Configuration
    FIREBASE_PROJECT_ID = os.environ.get('FIREBASE_PROJECT_ID')
    FIREBASE_CLIENT_EMAIL = os.environ.get('FIREBASE_CLIENT_EMAIL')
    FIREBASE_PRIVATE_KEY = os.environ.get('FIREBASE_PRIVATE_KEY')
    FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY')
    
    # WebAuthn Configuration
    # CRITICAL: RP_ID must be the effective domain (hostname) of the application.
    # It CANNOT include protocol (https://) or port.
    # On Render/Vercel, we must set RP_ID env var to the deployment domain (e.g., my-app.onrender.com)
    RP_ID = os.environ.get('RP_ID', 'localhost')
    RP_NAME = os.environ.get('RP_NAME', 'Cipherlock Vault')
    
    # Origin for CORS and WebAuthn verification
    # This should be the full URL of the frontend (e.g. https://my-app.vercel.app)
    ORIGIN = os.environ.get('ORIGIN', 'http://localhost:5173')

    # Optional comma-separated overrides for strict CORS and WebAuthn origin checks.
    CORS_ORIGINS = [o.strip() for o in os.environ.get('CORS_ORIGINS', ORIGIN).split(',') if o.strip()]
    WEBAUTHN_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('WEBAUTHN_ALLOWED_ORIGINS', ORIGIN).split(',') if o.strip()]
