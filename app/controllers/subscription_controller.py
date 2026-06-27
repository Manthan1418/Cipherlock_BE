from app.extensions.firestore import FirestoreClient
from app.config import Config
from datetime import datetime, timezone, timedelta


def get_plans():
    return list(Config.PLANS.values())


def get_plan(plan_id):
    return Config.PLANS.get(plan_id)


def get_user_subscription(uid):
    sub = FirestoreClient.get_doc('subscriptions', uid)
    if not sub:
        return {
            'planId': 'free',
            'status': 'none',
        }
    return sub


def get_password_count(uid):
    db = FirestoreClient.get_db()
    if not db:
        return 0
    try:
        docs = db.collection('users').document(uid).collection('vault').stream()
        return len(list(docs))
    except Exception:
        return 0


def check_subscription_limit(uid):
    sub = get_user_subscription(uid)
    plan_id = sub.get('planId', 'free')
    plan = Config.PLANS.get(plan_id, Config.PLANS['free'])
    max_passwords = plan['max_passwords']

    if max_passwords == -1:
        return {'allowed': True, 'max': None, 'current': 0}

    current = get_password_count(uid)
    return {
        'allowed': current < max_passwords,
        'max': max_passwords,
        'current': current,
    }


def create_subscription(uid, plan_id, granted_by):
    plan = Config.PLANS.get(plan_id)
    if not plan:
        return None

    now = datetime.now(timezone.utc)
    end_date = now + timedelta(days=30)

    data = {
        'planId': plan_id,
        'status': 'active',
        'startDate': now.isoformat(),
        'endDate': end_date.isoformat(),
        'grantedBy': granted_by,
        'grantedAt': now.isoformat(),
    }

    success = FirestoreClient.update_doc('subscriptions', uid, data)
    if success:
        return data
    return None


def cancel_subscription(uid):
    sub = get_user_subscription(uid)
    if not sub:
        return False
    return FirestoreClient.update_doc('subscriptions', uid, {'status': 'cancelled'})


def get_days_remaining(uid):
    sub = get_user_subscription(uid)
    if sub.get('status') != 'active':
        return 0

    end_date_str = sub.get('endDate')
    if not end_date_str:
        return 0

    try:
        end_date = datetime.fromisoformat(end_date_str)
        now = datetime.now(timezone.utc)
        remaining = (end_date - now).days
        return max(0, remaining)
    except Exception:
        return 0
