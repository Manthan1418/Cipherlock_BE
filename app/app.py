from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from app.config import Config
from app.extensions.firebase import init_firebase
from app.routes.vault_routes import vault_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Extensions
    CORS(app) # Enable CORS for all routes
    init_firebase(app)

    # Security Extensions
    # Rate Limiting: 200 requests per day, 50 per hour by default
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # HTTP Security Headers (Force HTTPS is FALSE for local dev)
    Talisman(app, content_security_policy=None, force_https=False)

    # Register Blueprints
    app.register_blueprint(vault_bp, url_prefix='/api/vault')

    @app.route('/api/health')
    def health_check():
        return {'status': 'healthy'}, 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000)
