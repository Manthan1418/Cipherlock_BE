from flask import Blueprint
from app.middleware.auth_middleware import verify_firebase_token
from app.controllers.auth_controller import generate_2fa_secret, enable_2fa, disable_2fa, verify_2fa_login, get_2fa_status

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/2fa/generate', methods=['POST'])
@verify_firebase_token
def generate():
    return generate_2fa_secret()

@auth_bp.route('/2fa/enable', methods=['POST'])
@verify_firebase_token
def enable():
    return enable_2fa()

@auth_bp.route('/2fa/disable', methods=['POST'])
@verify_firebase_token
def disable():
    return disable_2fa()

@auth_bp.route('/2fa/verify', methods=['POST'])
@verify_firebase_token
def verify():
    return verify_2fa_login()

@auth_bp.route('/2fa/status', methods=['GET'])
@verify_firebase_token
def status():
    return get_2fa_status()
