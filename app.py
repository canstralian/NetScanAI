import os
import logging
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_key_123")

# Setup rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "10 per hour"],
    storage_uri="memory://"
)

# Import routes after app initialization to avoid circular imports
from routes import *

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
