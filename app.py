from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from scanner import scan
import os

app = Flask(__name__)
CORS(app)

@app.route("/")
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