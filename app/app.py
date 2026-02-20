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



    # Initialize Extensions
    # CRITICAL: Firebase must be initialized early for FirestoreClient to work
    init_firebase(app)

    # Security Extensions
    # CORS: Allow all since we are behind a proxy (Same-Origin)
    CORS(app, resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"]
        }
    })

    # Rate Limiting
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["2000 per day", "500 per hour"],
        storage_uri="memory://"
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