"""
Minimal Flask service used as the scan target for the container security pipeline.
This app is intentionally simple — the point of the project is the pipeline
around it (build -> scan -> compliance map -> gate), not the app itself.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "service": "compliance-demo-app",
        "status": "ok"
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


if __name__ == "__main__":
    # Bound to 0.0.0.0 deliberately for container networking;
    # in production this sits behind a load balancer / reverse proxy.
    app.run(host="0.0.0.0", port=5000)
