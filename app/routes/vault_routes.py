from flask import Blueprint
from app.middleware.auth_middleware import verify_firebase_token
from app.controllers.vault_controller import add_password, get_passwords, delete_password, get_password

vault_bp = Blueprint('vault', __name__)

@vault_bp.route('', methods=['POST'])
@verify_firebase_token
def add():
    return add_password()

@vault_bp.route('', methods=['GET'])
@verify_firebase_token
def list_all():
    return get_passwords()

@vault_bp.route('/<entry_id>', methods=['GET'])
@verify_firebase_token
def get_one(entry_id):
    return get_password(entry_id)

@vault_bp.route('/<entry_id>', methods=['DELETE'])
@verify_firebase_token
def delete(entry_id):
    return delete_password(entry_id)

@vault_bp.route('/<entry_id>', methods=['PUT'])
@verify_firebase_token
def update(entry_id):
    from app.controllers.vault_controller import update_password
    return update_password(entry_id)
