from flask import Flask, request, jsonify
from flask_cors import CORS
import json, time, hmac, hashlib, os

app = Flask(__name__)
CORS(app)  # allow frontend JS requests

LOG_FILE = "secure_log.json"
SECRET_KEY = b"super_secret_key_123"


# ---------- Helpers ----------
def generate_hmac(msg):
    return hmac.new(SECRET_KEY, msg.encode(), hashlib.sha256).hexdigest()

def load_logs():
    return json.load(open(LOG_FILE)) if os.path.exists(LOG_FILE) else []

def save_logs(logs):
    json.dump(logs, open(LOG_FILE, "w"), indent=4)


# ---------- API: Add Event ----------
@app.route("/api/add_event", methods=["POST"])
def api_add_event():
    data = request.json

    event_type = data.get("type")
    source = data.get("source")
    details = data.get("details")
    priority = data.get("priority", "normal")

    logs = load_logs()
    prev_hmac = logs[-1]["hmac"] if logs else "0"

    event = {
        "seq": len(logs) + 1,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "source": source,
        "data": details,
        "priority": priority,
        "prev_hmac": prev_hmac,
    }

    event_string = json.dumps(event, sort_keys=True)
    event["hmac"] = generate_hmac(event_string)

    logs.append(event)
    save_logs(logs)

    return jsonify({"success": True, "event": event})


# ---------- API: Get Logs ----------
@app.route("/api/get_logs", methods=["GET"])
def api_get_logs():
    return jsonify(load_logs())


# ---------- API: Verify Integrity ----------
@app.route("/api/verify", methods=["GET"])
def api_verify():
    logs = load_logs()

    for i in range(1, len(logs)):
        if logs[i]["prev_hmac"] != logs[i - 1]["hmac"]:
            return jsonify({"tampered": True, "at": logs[i]["seq"]})

    return jsonify({"tampered": False})


# ---------- Run server ----------
if __name__ == "__main__":
    app.run(port=5000, debug=True)
