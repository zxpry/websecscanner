from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan
import os

app = Flask(__name__)
CORS(app)

@app.route("/")
@app.route("/admin")
def admin():
    secret = request.args.get("key")
    if secret != os.environ.get("ADMIN_KEY"):
        return jsonify({"error": "Unauthorized"}), 403
    return send_from_directory('.', 'index.html')

@app.route("/admin-scan", methods=["GET"])
def admin_scan():
    secret = request.args.get("key")
    if secret != os.environ.get("ADMIN_KEY"):
        return jsonify({"error": "Unauthorized"}), 403
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = scan(url)
    return jsonify(result)
def index():
    return send_from_directory('.', 'index.html')

@app.route("/scan", methods=["GET"])
def scan_url():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = scan(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)