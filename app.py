"""INOUTX Flask backend retained for static serving and health checks."""

import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "dist")
STATIC_DIR = DIST_DIR if os.path.isdir(DIST_DIR) else BASE_DIR
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="")
CORS(app)


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "INOUTX Backend Portal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "smtp_configured": False,
        "smtp_host": "",
        "receiver_email": ""
    }), 200


@app.route("/api/contact", methods=["POST"])
def retired_contact_endpoint():
    return jsonify({
        "success": False,
        "error": "Contact form delivery is handled by EmailJS. This endpoint is retired."
    }), 410


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:path>")
def static_proxy(path):
    if os.path.exists(os.path.join(STATIC_DIR, path)):
        return send_from_directory(STATIC_DIR, path)
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
