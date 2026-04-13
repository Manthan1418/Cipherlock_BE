import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / '.env')
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
    _cors_env = os.environ.get('CORS_ORIGINS', '').strip()
    if _cors_env:
        CORS_ORIGINS = [o.strip() for o in _cors_env.split(',') if o.strip()]
    elif IS_DEV:
        CORS_ORIGINS = [
            'http://localhost:5173',
            'http://localhost:5174',
            'http://127.0.0.1:5173',
            'http://127.0.0.1:5174',
            ORIGIN,
        ]
    else:
        CORS_ORIGINS = [ORIGIN]

    _webauthn_env = os.environ.get('WEBAUTHN_ALLOWED_ORIGINS', '').strip()
    if _webauthn_env:
        WEBAUTHN_ALLOWED_ORIGINS = [o.strip() for o in _webauthn_env.split(',') if o.strip()]
    elif IS_DEV:
        WEBAUTHN_ALLOWED_ORIGINS = [
            'http://localhost:5173',
            'http://localhost:5174',
            'http://127.0.0.1:5173',
            'http://127.0.0.1:5174',
            ORIGIN,
        ]
    else:
        WEBAUTHN_ALLOWED_ORIGINS = [ORIGIN]
