import os
import logging
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

def configure_logging():
    logging.basicConfig(level=logging.DEBUG)

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_key_123")

    # Setup rate limiting
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[os.environ.get("RATE_LIMITS", "100 per day, 10 per hour")],
        storage_uri="memory://"
    )

    with app.app_context():
        # Import routes after app initialization to avoid circular imports
        from routes import main as main_blueprint
        app.register_blueprint(main_blueprint)

    return app

app = create_app()
configure_logging()

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="ratelimit exceeded", message=str(e.description)), 429

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)