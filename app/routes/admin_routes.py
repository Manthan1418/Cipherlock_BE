from flask import Blueprint, jsonify, request
from app.config import Config
from app.middleware.admin_middleware import require_admin, create_admin_session
from app.controllers.admin_controller import (
    get_all_users,
    grant_user_access,
    revoke_user_access,
    get_pending_requests,
    approve_request,
)

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if (username == Config.ADMIN_USERNAME or username in Config.ADMIN_EMAILS) and password == Config.ADMIN_PASSWORD:
        token = create_admin_session()
        return jsonify({'token': token, 'message': 'Admin login successful'})

    return jsonify({'error': 'Invalid admin credentials'}), 401


@admin_bp.route('/users', methods=['GET'])
@require_admin
def list_users():
    users = get_all_users()
    return jsonify({'users': users})


@admin_bp.route('/users/<uid>/grant', methods=['POST'])
@require_admin
def grant_access(uid):
    data = request.get_json() or {}
    plan_id = data.get('planId', 'basic')
    result = grant_user_access(request.uid, uid, plan_id)
    if result:
        return jsonify({'message': 'Access granted successfully', 'subscription': result})
    return jsonify({'error': 'Failed to grant access'}), 500


@admin_bp.route('/users/<uid>/revoke', methods=['POST'])
@require_admin
def revoke_access(uid):
    result = revoke_user_access(uid)
    if result:
        return jsonify({'message': 'Access revoked successfully'})
    return jsonify({'error': 'Failed to revoke access'}), 500


@admin_bp.route('/requests', methods=['GET'])
@require_admin
def list_requests():
    requests = get_pending_requests()
    return jsonify({'requests': requests})


@admin_bp.route('/requests/<request_id>/approve', methods=['POST'])
@require_admin
def approve(request_id):
    data = request.get_json() or {}
    plan_id = data.get('planId', 'basic')
    result = approve_request(request_id, request.uid)
    if result:
        return jsonify({'message': 'Request approved', 'subscription': result})
    return jsonify({'error': 'Failed to approve request'}), 500
