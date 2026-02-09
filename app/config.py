import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'dev-key-please-change'
    FIREBASE_PROJECT_ID = os.environ.get('FIREBASE_PROJECT_ID')
    FIREBASE_CLIENT_EMAIL = os.environ.get('FIREBASE_CLIENT_EMAIL')
    FIREBASE_PRIVATE_KEY = os.environ.get('FIREBASE_PRIVATE_KEY')
    FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY')
