import csv
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import jwt
from datetime import timedelta, datetime
import sqlite3
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpass")

# Flask setup
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Constants
DB_FILE = 'activity_logs.db'
SCREENSHOT_DIR = 'screenshots'
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Global command storage
command_categories = {
    "malicious": set(),
    "merged": set(),
    "rm": set()
}
all_commands = set()  # Combined commands for quick lookup

# Dynamic ignore globals
# Instead of a set, we now use a dictionary mapping the ignored common prefix
# to the list of log paths (the "trigger logs")
dynamic_ignored = {}  
recent_log_paths = []          # Sliding window for the last three log paths
MIN_COMMON_SPLITS = 3          # Minimum directory splits required for ignoring

def send_email_alert(subject, body, to_email):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "email"  # Replace with your email
    smtp_password = "your-app-password-here"  # Replace with your app password

    message = MIMEMultipart()
    message["From"] = smtp_username
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(smtp_username, to_email, message.as_string())
        print("✅ Email sent successfully.")
    except Exception as e:
        print("❌ Failed to send email:", e)

def load_malicious_commands():
    global command_categories, all_commands
    for category in command_categories:
        command_categories[category].clear()
    all_commands.clear()

    file_config = {
        "malicious": {"filename": "command_injection.csv", "has_header": True},
        "merged": {"filename": "merged_malicious_commands.csv", "has_header": True},
        "rm": {"filename": "rm_commands.csv", "has_header": False}
    }

    for category, config in file_config.items():
        filename = config["filename"]
        try:
            with open(filename, 'r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                if config["has_header"]:
                    next(reader)
                commands = set()
                for row in reader:
                    if row and row[0].strip():
                        command = row[0].strip().lower()
                        commands.add(command)
                command_categories[category] = commands
                all_commands.update(commands)
                print(f"Loaded {len(commands)} commands into '{category}' from {filename}")
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    print(f"Total combined malicious commands: {len(all_commands)}")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT,
                        event_type TEXT,
                        data TEXT,
                        timestamp TEXT
                    )''')
    conn.commit()
    conn.close()

def find_common_path(paths):
    """
    Given a list of paths, return the longest common directory prefix.
    Splits each path by os.sep and compares corresponding parts.
    """
    if not paths:
        return ""

    split_paths = [path.split(os.sep) for path in paths]
    common_parts = []

    # Compare each part of the split paths
    for parts in zip(*split_paths):
        if len(set(parts)) == 1:
            common_parts.append(parts[0])
        else:
            break

    if common_parts:
        return os.sep.join(common_parts) + os.sep
    else:
        return ""

def process_log(log_path):
    """
    Process an incoming log's file path.
    1. Check if the log's path starts with any dynamically ignored common prefix.
    2. Maintain a sliding window of the last three log paths.
    3. If three logs share a common prefix with at least MIN_COMMON_SPLITS parts,
       store that common prefix along with the triggering log paths in dynamic_ignored.
    """
    global dynamic_ignored, recent_log_paths

    # Check against existing dynamic ignores
    for ignore in dynamic_ignored:
        if log_path.startswith(ignore):
            print(f"Ignoring log from dynamically ignored path: {ignore}")
            return False  # Skip this log

    # Add current log path to the sliding window
    recent_log_paths.append(log_path)
    if len(recent_log_paths) > 3:
        recent_log_paths.pop(0)

    # When three logs are available, determine common prefix
    if len(recent_log_paths) == 3:
        common_prefix = find_common_path(recent_log_paths)
        if common_prefix.count(os.sep) >= MIN_COMMON_SPLITS:
            # Store the common prefix and the logs that triggered it
            dynamic_ignored[common_prefix] = list(recent_log_paths)
            print(f"Dynamic ignore added for common path: {common_prefix} with logs {recent_log_paths}")
            recent_log_paths.clear()  # Reset sliding window after adding
            return False

    return True

@app.route('/log', methods=['POST'])
def log_activity():
    data = request.json
    if not data or not all(key in data for key in ('user', 'event_type', 'data')):
        return jsonify({"message": "Invalid request"}), 400

    user = data['user']
    original_event_type = data['event_type']
    raw_data = data['data'].strip().lower()  # Assuming this is a file path
    timestamp = data.get('timestamp', datetime.utcnow().isoformat())

    # Check for malicious command (static check)
    is_malicious = False
    category = None
    for cat, commands in command_categories.items():
        if raw_data in commands:
            is_malicious = True
            category = cat
            break

    # Adjust event_type if a malicious command is detected
    event_type = f"Malicious Command {category.capitalize()}" if is_malicious else original_event_type

    # Apply dynamic filtering based on file path analysis
    if not process_log(raw_data):
        return jsonify({"message": "Log ignored dynamically"}), 200

    # Save log to database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (user, event_type, data, timestamp) VALUES (?, ?, ?, ?)",
                   (user, event_type, raw_data, timestamp))
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()

    log_entry = {
        "id": last_id,
        "user": user,
        "event_type": event_type,
        "data": raw_data,
        "timestamp": timestamp
    }

    # Emit SocketIO events
    socketio.emit('new_log', log_entry)
    if is_malicious:
        socketio.emit('malicious_command_alert', log_entry)
        alert_body = f"Malicious command detected!\nUser: {user}\nCategory: {category.capitalize()}\nCommand: {raw_data}\nTimestamp: {timestamp}"
        send_email_alert("Alert: Malicious Command Detected", alert_body, "................")

    return jsonify({"message": "Log saved successfully"}), 200

# Endpoint to get ignored paths along with the logs that triggered them
@app.route('/ignored', methods=['GET'])
def get_ignored_paths():
    # Return a list of dictionaries, each with a 'ignored_path' and the 'trigger_logs'
    ignored_list = [{"ignored_path": key, "trigger_logs": value} for key, value in dynamic_ignored.items()]
    return jsonify({"ignored_paths": ignored_list}), 200

# Command category endpoints
@app.route('/malicious', methods=['GET'])
def get_malicious():
    return jsonify({"commands": list(command_categories["malicious"])}), 200

@app.route('/merged', methods=['GET'])
def get_merged():
    return jsonify({"commands": list(command_categories["merged"])}), 200

@app.route('/rm', methods=['GET'])
def get_rm():
    return jsonify({"commands": list(command_categories["rm"])}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    event_type = request.args.get('event_type')
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if event_type:
        cursor.execute("SELECT * FROM logs WHERE event_type = ?", (event_type,))
    else:
        cursor.execute("SELECT * FROM logs")
    rows = cursor.fetchall()
    conn.close()

    logs = [{
        "id": row[0],
        "user": row[1],
        "event_type": row[2],
        "data": row[3],
        "timestamp": row[4]
    } for row in rows]

    return jsonify({"logs": logs}), 200

@app.route('/logs/file', methods=['GET'])
def get_file_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE LOWER(event_type) LIKE '%file%'")
    rows = cursor.fetchall()
    conn.close()

    logs = [{
        "id": row[0],
        "user": row[1],
        "event_type": row[2],
        "data": row[3],
        "timestamp": row[4]
    } for row in rows]

    return jsonify({"logs": logs}), 200

@app.route('/logs/malicious', methods=['GET'])
def get_malicious_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE event_type = 'Malicious Command Alert'")
    rows = cursor.fetchall()
    conn.close()

    logs = [{
        "id": row[0],
        "user": row[1],
        "event_type": row[2],
        "data": row[3],
        "timestamp": row[4]
    } for row in rows]

    return jsonify({"logs": logs}), 200

@app.route('/logs/clear', methods=['DELETE'])
def clear_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
    return jsonify({"message": "Logs cleared successfully"}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Invalid request"}), 400

    username = data['username']
    password = data['password']

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = jwt.encode({
            "username": username,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"token": token})

    return jsonify({"message": "Invalid credentials"}), 401

if __name__ == '__main__':
    init_db()
    load_malicious_commands()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
