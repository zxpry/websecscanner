from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import scan

app = Flask(__name__)
CORS(app)

@app.route("/scan", methods=["GET"])
def scan_url():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = scan(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)