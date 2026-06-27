import time
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
from app.middleware.auth_middleware import verify_firebase_token
from app.config import Config
from app.controllers.subscription_controller import (
    get_plans,
    get_plan,
    get_user_subscription,
    check_subscription_limit,
    get_days_remaining,
)
from app.extensions.firestore import FirestoreClient

subscription_bp = Blueprint('subscription', __name__)


@subscription_bp.route('/plans', methods=['GET'])
def list_plans():
    return jsonify({'plans': get_plans()})


@subscription_bp.route('/my', methods=['GET'])
@verify_firebase_token
def my_subscription():
    sub = get_user_subscription(request.uid)
    limit = check_subscription_limit(request.uid)
    days_remaining = get_days_remaining(request.uid)
    return jsonify({
        'subscription': sub,
        'limit': limit,
        'daysRemaining': days_remaining,
    })


@subscription_bp.route('/subscribe', methods=['POST'])
@verify_firebase_token
def request_subscription():
    data = request.get_json() or {}
    plan_id = data.get('planId')

    if not plan_id or plan_id not in Config.PLANS:
        return jsonify({'error': 'Invalid plan'}), 400

    plan = get_plan(plan_id)
    if not plan:
        return jsonify({'error': 'Plan not found'}), 404

    request_id = f"{request.uid}_{int(time.time())}"
    success = FirestoreClient.update_doc('subscription_requests', request_id, {
        'uid': request.uid,
        'email': request.email,
        'planId': plan_id,
        'planName': plan['name'],
        'status': 'pending',
        'requestedAt': datetime.now(timezone.utc).isoformat(),
    })

    if success:
        return jsonify({
            'message': 'Your subscription request has been submitted. An admin will grant you access shortly.',
            'requestId': request_id,
        })
    return jsonify({'error': 'Failed to submit request'}), 500


@subscription_bp.route('/check-limit', methods=['GET'])
@verify_firebase_token
def check_limit():
    limit = check_subscription_limit(request.uid)
    return jsonify(limit)
