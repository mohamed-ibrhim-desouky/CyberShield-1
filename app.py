 
"""
CyberShield - Secure Python Application
Demonstrates secure coding practices for DevSecOps pipeline.
"""

from flask import Flask, jsonify, request
import hashlib
import os

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")


def hash_data(data: str) -> str:
    """Hash input data using SHA-256 (secure)."""
    return hashlib.sha256(data.encode()).hexdigest()


def validate_input(data: str) -> bool:
    """Validate input to prevent injection attacks."""
    if not data or len(data) > 256:
        return False
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-")
    return all(c in allowed_chars for c in data)


@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "healthy", "service": "CyberShield API", "version": "1.0.0"})


@app.route("/hash", methods=["POST"])
def hash_endpoint():
    body = request.get_json()
    if not body or "data" not in body:
        return jsonify({"error": "Missing 'data' field"}), 400
    data = str(body["data"])
    if not validate_input(data):
        return jsonify({"error": "Invalid input"}), 422
    return jsonify({"input": data, "sha256": hash_data(data)})


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "pong"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False) #nosec B104