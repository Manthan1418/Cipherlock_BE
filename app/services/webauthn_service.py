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
        # Dynamic origin handling for Vercel/Render
        # We trust the Host/Origin header if it matches our deployment domain patterns
        origin = request.headers.get('Origin')
        rp_id = current_app.config['RP_ID']
        
        # If config is localhost but request is from Vercel/Render, we might have a mismatch if not configured via ENV.
        # But per requirements, we expect ENV to be set. 
        # Fallback: If origin includes vercel.app, trust it as RP_ID to support preview deployments
        if origin and ('vercel.app' in origin or 'onrender.com' in origin):
             try:
                 from urllib.parse import urlparse
                 hostname = urlparse(origin).hostname
                 if hostname:
                     rp_id = hostname
             except Exception:
                 pass

        return {
            'rp_id': rp_id,
            'rp_name': current_app.config['RP_NAME'],
            'origin': origin or current_app.config['ORIGIN']
        }

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
            
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_origin=config['origin'],
                expected_rp_id=config['rp_id'],
                require_user_verification=True,
            )
            
            cred_id = bytes_to_base64url(verification.credential_id)
            new_cred = {
                 "id": cred_id,
                 "public_key": bytes_to_base64url(verification.credential_public_key),
                 "sign_count": verification.sign_count,
                 "transports": credential.response.transports or [],
                 "created_at": str(datetime.now(timezone.utc))
            }
            
            # Store credential in subcollection
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
                            id=base64url_to_bytes(c['id']),
                            transports=transports,
                        )
                    )
        
        options = generate_authentication_options(
            rp_id=config['rp_id'],
            allow_credentials=allow_credentials or [],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        if user_id:
             store_challenge(user_id, bytes_to_base64url(options.challenge), 'login')
        
        return options_to_json(options)

    @staticmethod
    def verify_login_response(user_id, response_body):
        config = WebAuthnService._get_config()
        
        # 1. Get Challenge
        challenge_data = get_challenge(user_id)
        if not challenge_data or challenge_data['type'] != 'login':
             raise ValueError("Challenge not found or expired")
        
        expected_challenge = base64url_to_bytes(challenge_data['challenge'])
        
        # 2. Parse Credential
        try:
            credential = parse_authentication_credential_json(response_body)
        except Exception as e:
            raise ValueError(f"Failed to parse credential: {str(e)}")

        # 3. Get User's Public Key from Firestore
        cred_id = credential.id
        cred_doc = FirestoreClient.get_doc(f"users/{user_id}/webauthn_credentials", cred_id)
        
        if not cred_doc or 'public_key' not in cred_doc:
            raise ValueError("Credential not registered for this user")
            
        public_key = base64url_to_bytes(cred_doc['public_key'])
        current_sign_count = cred_doc.get('sign_count', 0)

        # 4. Verify
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=config['rp_id'],
            expected_origin=config['origin'],
            credential_public_key=public_key,
            credential_current_sign_count=current_sign_count,
            require_user_verification=True,
        )
        
        # 5. Update Sign Count
        FirestoreClient.update_doc(f"users/{user_id}/webauthn_credentials", cred_id, {
            "sign_count": verification.new_sign_count
        })

        return {
            'verified': True,
            'new_sign_count': verification.new_sign_count
        }
        
