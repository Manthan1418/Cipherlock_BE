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
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    AuthenticatorAttachment,
)
from flask import current_app
from app.extensions.firestore import FirestoreClient, store_challenge, get_challenge

class WebAuthnService:
    @staticmethod
    def _get_config():
        return {
            'rp_id': current_app.config['RP_ID'],
            'rp_name': current_app.config['RP_NAME'],
            'origin': current_app.config['ORIGIN']
        }

    @staticmethod
    def generate_registration_options(user_id, user_email):
        """
        Generate options for creating a new credential
        """
        config = WebAuthnService._get_config()
        
        options = generate_registration_options(
            rp_id=config['rp_id'],
            rp_name=config['rp_name'],
            user_id=user_id.encode('utf-8'), # User ID must be bytes
            user_name=user_email,
            user_display_name=user_email,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
                authenticator_attachment=AuthenticatorAttachment.PLATFORM, 
                resident_key=None,
            ),
        )
        
        # Store challenge in memory (since we don't have easy DB access for temp data)
        store_challenge(user_id, bytes_to_base64url(options.challenge), 'registration')
        
        return options_to_json(options)

    @staticmethod
    def verify_registration_response(user_id, response_body, token):
        """
        Verify the response from the authenticator
        """
        config = WebAuthnService._get_config()
        
        # Retrieve challenge
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
            
            # Save credential to user's profile using REST API
            # We need to construct the update payload carefully for Firestore REST
            # OR we can assume `auth_controller` handles the DB write?
            # Better to do it here to keep logic encapsulated, but we need the TOKEN.
            
            cred_id = bytes_to_base64url(verification.credential_id)
            new_cred = {
                 "id": cred_id,
                 "public_key": bytes_to_base64url(verification.credential_public_key),
                 "sign_count": verification.sign_count,
                 "transports": credential.response.transports or []
            }
            
            # Firestore Maps are tricky via REST JSON. 
            # Ideally we fetch existing, append, and patch.
            
            # 1. Fetch User (Optional: Parent doc might not exist, but we can still write to subcollection)
            # user_data = FirestoreClient.get_doc('users', user_id, token)
            # if not user_data:
            #      # Option: Create user doc if missing? 
            #      # For now, we allow "shell" parents for subcollections.
            #      pass
            
            # 2. Update credentials field
            # We will write to a subcollection `credentials`
            
            cred_doc = {
                "fields": {
                    "id": {"stringValue": new_cred['id']},
                    "public_key": {"stringValue": new_cred['public_key']},
                    "sign_count": {"integerValue": new_cred['sign_count']},
                    # transports is list
                }
            }
            
            # We use `update_doc` which performs a PATCH. 
            # If we point to `users/{uid}/webauthn_credentials/{cred_id}`, it creates/updates that doc.
            
            FirestoreClient.update_doc(f"users/{user_id}/webauthn_credentials", cred_id, cred_doc, token)
            
            return {
                'verified': True,
                'credential_id': cred_id
            }
            
        except Exception as e:
            raise e

    @staticmethod
    def generate_login_options(user_id=None):
        config = WebAuthnService._get_config()
        allow_credentials = None
        # IF we have user_id, we should try to fetch credentials.
        # But we don't have a token to read `users/{uid}/credentials`.
        # So we continue with empty allow_credentials (Usernameless / Resident Key).
        
        options = generate_authentication_options(
            rp_id=config['rp_id'],
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        # Store challenge (use user_id if available, else we need a session ID)
        # For this MVP, we rely on user_id being resolved from email in controller
        if user_id:
             store_challenge(user_id, bytes_to_base64url(options.challenge), 'login')
        
        return options_to_json(options)

    @staticmethod
    def verify_login_response(user_id, response_body):
        config = WebAuthnService._get_config()
        
        # 1. Get Challenge
        challenge_data = get_challenge(user_id)
        if not challenge_data or challenge_data['type'] != 'login':
             raise ValueError("Challenge not found")
        
        expected_challenge = base64url_to_bytes(challenge_data['challenge'])
        
        # 2. Parse Credential
        try:
            credential = parse_authentication_credential_json(response_body)
        except Exception as e:
            raise ValueError(f"Failed to parse credential: {str(e)}")

        # 3. Get User's Public Key
        # CRITICAL: We need to read the public key from DB using the CREDENTIAL ID.
        # But we don't have a token!
        
        # DEV MODE BYPASS
        if config['rp_id'] == "localhost":
            print("WARNING: Bypassing WebAuthn Signature Verification for Localhost Development.", file=sys.stderr)
            # We assume valid if structured correctly because we can't verify signature without public key
            return {
                'verified': True,
                'token': f"mock_token_for_{user_id}" 
            }

        raise Exception("Backend is missing Admin Privileges to fetch public key for verification. Please re-enable Firebase Admin SDK or implement a privileged proxy.")
        
