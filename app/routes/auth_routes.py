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

@auth_bp.route('/webauthn/register/options', methods=['POST'])
@verify_firebase_token
def webauthn_reg_options():
    from app.controllers.auth_controller import webauthn_register_options
    return webauthn_register_options()

@auth_bp.route('/webauthn/register/verify', methods=['POST'])
@verify_firebase_token
def webauthn_reg_verify():
    from app.controllers.auth_controller import webauthn_register_verify
    return webauthn_register_verify()

@auth_bp.route('/webauthn/login/options', methods=['POST'])
def webauthn_log_options():
    from app.controllers.auth_controller import webauthn_login_options
    return webauthn_login_options()

@auth_bp.route('/webauthn/login/verify', methods=['POST'])
def webauthn_log_verify():
    from app.controllers.auth_controller import webauthn_login_verify
    return webauthn_login_verify()

@auth_bp.route('/firebase-status', methods=['GET'])
def firebase_status():
    from flask import jsonify
    try:
        from firebase_admin import firestore
        import firebase_admin
        from app.extensions.firebase import INIT_ERROR
        
        if not firebase_admin._apps:
             return jsonify({
                 'status': 'Failed', 
                 'error': 'Firebase App not initialized',
                 'init_err': INIT_ERROR
             }), 500
             
        db = firestore.client()
        
        # TEST DB CONNECTION
        db_status = "Connected"
        try:
            test_ref = db.collection('system_checks').document('connection_test')
            test_ref.set({'last_check': firestore.SERVER_TIMESTAMP})
            test_ref.get()
            db_status = "Read/Write Successful"
        except Exception as db_e:
            db_status = f"Read/Write Failed: {str(db_e)}"

        # Check WebAuthn Config too
        from flask import current_app
        config_status = {
            "status": "Firebase Admin SDK initialized successfully",
            "firestore_io": db_status,
            "webauthn_config": {
                "RP_ID": current_app.config.get('RP_ID'),
                "RP_NAME": current_app.config.get('RP_NAME'),
                "ORIGIN": current_app.config.get('ORIGIN')
            }
        }
        return jsonify(config_status), 200
    except Exception as e:
        import traceback
        return jsonify({'status': 'Failed', 'error': str(e), 'trace': traceback.format_exc()}), 500
