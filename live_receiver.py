
from flask import Flask, request, jsonify
from pathlib import Path
from datetime import datetime
import json
import os

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

EVENT_FILE = DATA_DIR / "live_login_events.jsonl"
API_TOKEN = os.environ.get("IDENTITYSHIELD_TOKEN", "")


@app.post("/events")
def receive_event():
    if not API_TOKEN:
        return jsonify({"error": "Receiver token is not configured"}), 503

    token = request.headers.get("X-IdentityShield-Token", "")
    if token != API_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return jsonify({"error": "Expected JSON event"}), 400

    required = {"timestamp", "username", "event_type", "source_ip"}
    if not required.issubset(event):
        return jsonify({"error": "Missing event fields"}), 400

    if event["event_type"] not in {"FAILED_LOGIN", "SUCCESS_LOGIN"}:
        return jsonify({"error": "Unsupported event type"}), 400

    # Keep each received event on a separate line.
    event["received_at"] = datetime.now().isoformat(timespec="seconds")

    with EVENT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    return jsonify({"status": "received"}), 201


@app.get("/health")
def health():
    return jsonify({"status": "running"})


if __name__ == "__main__":
    # Listen on the local network so the Kali VM can reach this receiver.
    app.run(host="0.0.0.0", port=8765, debug=False)
