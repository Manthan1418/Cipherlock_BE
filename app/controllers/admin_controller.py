from firebase_admin import auth as firebase_auth
from app.extensions.firestore import FirestoreClient
from app.controllers.subscription_controller import get_user_subscription, get_password_count


def get_all_users():
    db = FirestoreClient.get_db()
    if not db:
        return []

    users = []
    try:
        docs = db.collection('users').stream()
        for doc in docs:
            data = doc.to_dict()
            uid = doc.id
            email = data.get('email', '')
            if not email or email == 'unknown':
                try:
                    user_record = firebase_auth.get_user(uid)
                    email = user_record.email or uid
                except Exception:
                    email = uid
                if email != uid:
                    FirestoreClient.update_doc('users', uid, {'email': email})
            role = data.get('role', 'user')

            sub = get_user_subscription(uid)
            password_count = get_password_count(uid)

            days_remaining = 0
            if sub.get('status') == 'active':
                from app.controllers.subscription_controller import get_days_remaining
                days_remaining = get_days_remaining(uid)

            users.append({
                'uid': uid,
                'email': email,
                'role': role,
                'subscription': sub,
                'passwordCount': password_count,
                'daysRemaining': days_remaining,
            })
    except Exception as e:
        print(f"Error listing users: {e}")

    return users


def grant_user_access(admin_uid, user_uid, plan_id):
    from app.controllers.subscription_controller import create_subscription
    result = create_subscription(user_uid, plan_id, admin_uid)
    if result:
        FirestoreClient.update_doc('users', user_uid, {'role': 'user'})
    return result


def revoke_user_access(user_uid):
    from app.controllers.subscription_controller import cancel_subscription
    return cancel_subscription(user_uid)


def get_pending_requests():
    db = FirestoreClient.get_db()
    if not db:
        return []

    requests = []
    try:
        docs = db.collection('subscription_requests').where('status', '==', 'pending').stream()
        for doc in docs:
            data = doc.to_dict()
            data['id'] = doc.id
            requests.append(data)
    except Exception as e:
        print(f"Error listing pending requests: {e}")

    return requests


def approve_request(request_id, admin_uid):
    db = FirestoreClient.get_db()
    if not db:
        return None

    try:
        doc_ref = db.collection('subscription_requests').document(request_id)
        doc = doc_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        uid = data.get('uid')
        plan_id = data.get('planId')

        result = grant_user_access(admin_uid, uid, plan_id)
        if result:
            doc_ref.update({'status': 'approved', 'approvedBy': admin_uid})
            return result
    except Exception as e:
        print(f"Error approving request: {e}")

    return None
