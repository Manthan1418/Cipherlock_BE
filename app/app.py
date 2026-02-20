from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from app.config import Config
from app.extensions.firebase import init_firebase
from app.routes.vault_routes import vault_bp
from app.routes.auth_routes import auth_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # GLOBAL OPTIONS HANDLER (The "Nuclear" Fix)
    # This must run before all other requests to ensure preflight always succeeds
    @app.before_request
    def handle_preflight():
        from flask import request, make_response
        if request.method == "OPTIONS":
            response = make_response()
            
            # Dynamic Origin Logic
            origin = request.headers.get('Origin')
            if origin:
                import re
                allowed_patterns = [
                    app.config['ORIGIN'],  # Main production origin
                    r"^https://cipherlock-.*\.vercel\.app$",  # Vercel preview deployments
                    r"^http://localhost:\d+$"  # Local development
                ]
                
                allow = False
                for pattern in allowed_patterns:
                    if pattern and (origin == pattern or re.match(pattern, origin)):
                        allow = True
                        break
                
                if allow:
                    response.headers.add('Access-Control-Allow-Origin', origin)
                    # Explicitly allow all headers requested by the frontend
                    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,Accept,Origin')
                    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
                    response.headers.add('Access-Control-Allow-Credentials', 'true')
            
            # Key modification: Force 200 OK
            response.status_code = 200
            return response

    # Initialize Extensions
    # CRITICAL: Firebase must be initialized early for FirestoreClient to work
    init_firebase(app)

    # Security Extensions
    # Enable CORS for the specific frontend origin AND Vercel previews
    # Using regex to match https://cipherlock-*.vercel.app
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                app.config['ORIGIN'],  # Main production origin
                r"^https://cipherlock-.*\.vercel\.app$",  # Vercel preview deployments
                r"^http://localhost:\d+$"  # Local development
            ]
        }
    }, supports_credentials=True)

    # Rate Limiting
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["2000 per day", "500 per hour"],
        storage_uri="memory://",
        default_limits_exempt_when=lambda: app.request.method == 'OPTIONS'
    )



    # HTTP Security Headers
    # Force HTTPS in production (when not debugging)
    force_https = not app.debug
    Talisman(app, content_security_policy=None, force_https=force_https)

    # Register Blueprints
    app.register_blueprint(vault_bp, url_prefix='/api/vault')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')

    @app.route('/api/health')
    def health_check():
        return {'status': 'healthy'}, 200

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)