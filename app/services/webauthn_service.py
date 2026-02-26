from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
    generate_authentication_options,
    verify_authentication_response,
)
import sys
from webauthn.helpers import (
    bytes_to_base64url,
    parse_registration_credential_json,
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorTransport,
)
from flask import current_app, request
from datetime import datetime, timezone
from app.extensions.firestore import FirestoreClient, store_challenge, get_challenge

class WebAuthnService:
    @staticmethod
    def _get_config():
        # Enforce unified root domain RP ID from environment
        rp_id = current_app.config.get('RP_ID', 'localhost')
        
        # Valid origins must include the web platform and the Android App Link origin.
        # Ensure we always accept localhost in dev environments if configured.
        config_origin = current_app.config.get('ORIGIN', 'http://localhost:5173')
        
        # For Android, production will use the actual APK key hash in verifying assertions
        # If the backend is validating a native passkey via Android Credential Manager, 
        # the origin is sent as android:apk-key-hash:<hash>.
        android_origin_hash = current_app.config.get('ANDROID_APK_KEY_HASH', '')
        android_origin = f"android:apk-key-hash:{android_origin_hash}" if android_origin_hash else None

        expected_origins = [
            f"https://{rp_id}",
            config_origin
        ]
        if android_origin:
            expected_origins.append(android_origin)
            
        return {
            'rp_id': rp_id,
            'rp_name': current_app.config.get('RP_NAME', 'Cipherlock Vault'),
            'expected_origins': list(set(expected_origins)) # Deduplicate and return as list
        }

    @staticmethod


    @staticmethod
    def generate_registration_options(user_id, user_email):
        config = WebAuthnService._get_config()
        
        options = generate_registration_options(
            rp_id=config['rp_id'],
            rp_name=config['rp_name'],
            user_id=user_id.encode('utf-8'),
            user_name=user_email,
            user_display_name=user_email,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
                authenticator_attachment=AuthenticatorAttachment.PLATFORM, 
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
        )
        
        store_challenge(user_id, bytes_to_base64url(options.challenge), 'registration')
        return options_to_json(options)

    @staticmethod
    def verify_registration_response(user_id, response_body, token):
        config = WebAuthnService._get_config()
        
        challenge_data = get_challenge(user_id)
        if not challenge_data or challenge_data['type'] != 'registration':
            raise ValueError("Challenge not found or expired")
            
        expected_challenge = base64url_to_bytes(challenge_data['challenge'])
        
        try:
            credential = parse_registration_credential_json(response_body)
            
            # Dynamically allow Android native App Link origins
            import json
            client_data_json = base64url_to_bytes(response_body['response']['clientDataJSON'])
            client_data = json.loads(client_data_json.decode('utf-8'))
            client_origin = client_data.get('origin', '')
            
            if client_origin.startswith('android:apk-key-hash:') and client_origin not in config['expected_origins']:
                config['expected_origins'].append(client_origin)

            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_origin=config['expected_origins'],
                expected_rp_id=config['rp_id'],
                require_user_verification=True,
            )
            
            cred_id = bytes_to_base64url(verification.credential_id)
            now_iso = str(datetime.now(timezone.utc))
            
            new_cred = {
                 "userId": user_id,
                 "credentialId": cred_id,
                 "publicKey": bytes_to_base64url(verification.credential_public_key),
                 "counter": verification.sign_count,
                 "transports": credential.response.transports or ["internal"],
                 "createdAt": now_iso,
                 "lastUsedAt": now_iso
            }
            
            # Store credential in subcollection using standardized field names
            FirestoreClient.update_doc(f"users/{user_id}/webauthn_credentials", cred_id, new_cred)
            
            return {
                'verified': True,
                'credential_id': cred_id
            }
            
        except Exception as e:
            raise e

    @staticmethod
    def generate_login_options(user_id=None):
        config = WebAuthnService._get_config()
        import secrets
        import json
        
        # Look up stored credentials for this user to populate allowCredentials.
        # This lets the browser find the right passkey even if it wasn't stored as discoverable.
        allow_credentials = None
        if user_id:
            creds = FirestoreClient.list_docs(f"users/{user_id}/webauthn_credentials")
            if creds:
                allow_credentials = []
                for c in creds:
                    transports = None
                    raw_transports = c.get('transports', [])
                    if raw_transports:
                        transports = [AuthenticatorTransport(t) for t in raw_transports]
                    allow_credentials.append(
                        PublicKeyCredentialDescriptor(
                            id=base64url_to_bytes(c.get('credentialId', c.get('id'))),
                            transports=transports,
                        )
                    )
        
        options = generate_authentication_options(
            rp_id=config['rp_id'],
            allow_credentials=allow_credentials or [],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        session_id = secrets.token_urlsafe(32)
        store_challenge(session_id, bytes_to_base64url(options.challenge), 'login')
        
        options_dict = json.loads(options_to_json(options))
        options_dict['sessionId'] = session_id
        
        return options_dict

    @staticmethod
    def verify_login_response(session_id, response_body, user_id=None):
        config = WebAuthnService._get_config()
        
        # 1. Get Challenge using session_id
        challenge_data = get_challenge(session_id)
        if not challenge_data or challenge_data['type'] != 'login':
             raise ValueError("Challenge not found or expired")
        
        expected_challenge = base64url_to_bytes(challenge_data['challenge'])
        
        # 2. Parse Credential
        try:
            credential = parse_authentication_credential_json(response_body)
        except Exception as e:
            raise ValueError(f"Failed to parse credential: {str(e)}")

        # 2b. Extract user_id from discoverable credential if not provided
        if not user_id:
            if not credential.response.user_handle:
                raise ValueError("No userHandle returned by authenticator, and no internal UID provided.")
            user_id = credential.response.user_handle.decode('utf-8')

        # 3. Get User's Public Key from Firestore
        cred_id = credential.id
        cred_doc = FirestoreClient.get_doc(f"users/{user_id}/webauthn_credentials", cred_id)
        
        if not cred_doc:
            raise ValueError("Credential not registered for this user")
            
        # Support migration from old snake_case format to new camelCase standard
        public_key_b64 = cred_doc.get('publicKey', cred_doc.get('public_key'))
        if not public_key_b64:
            raise ValueError("Invalid credential format in store")
            
        public_key = base64url_to_bytes(public_key_b64)
        current_sign_count = cred_doc.get('counter', cred_doc.get('sign_count', 0))

        # Dynamically allow Android native App Link origins
        import json
        client_data_json = base64url_to_bytes(response_body['response']['clientDataJSON'])
        client_data = json.loads(client_data_json.decode('utf-8'))
        client_origin = client_data.get('origin', '')
        
        if client_origin.startswith('android:apk-key-hash:') and client_origin not in config['expected_origins']:
            config['expected_origins'].append(client_origin)

        # 4. Verify
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=config['rp_id'],
            expected_origin=config['expected_origins'],
            credential_public_key=public_key,
            credential_current_sign_count=current_sign_count,
            require_user_verification=False,
        )
        
        # 5. Update Sign Count and Last Used At
        FirestoreClient.update_doc(f"users/{user_id}/webauthn_credentials", cred_id, {
            "counter": verification.new_sign_count,
            "lastUsedAt": str(datetime.now(timezone.utc))
        })

        return {
            'verified': True,
            'new_sign_count': verification.new_sign_count,
            'uid': user_id
        }
        
