import json
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "riftbound.db")

# -------------------------------------------------------------------
# Flask app
# -------------------------------------------------------------------
app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")


# -------------------------------------------------------------------
# DB helpers
# -------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
        """
    )

    # Events table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            your_deck TEXT,
            link_url TEXT,
            comments TEXT,
            event_date TEXT,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    # Rounds table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            round_number INTEGER NOT NULL,
            opp_deck TEXT,
            die_roll_won INTEGER DEFAULT 0,
            match_result TEXT,
            games_json TEXT,
            comments TEXT,
            FOREIGN KEY(event_id) REFERENCES events(id)
        )
        """
    )

    # Password reset tokens table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            approved INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


# -------------------------------------------------------------------
# Auth helpers
# -------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)

    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not authenticated"}), 401

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],))
        row = cur.fetchone()
        conn.close()

        if row is None or not row["is_admin"]:
            return jsonify({"error": "Admin access required"}), 403

        return f(*args, **kwargs)

    return wrapper


def get_or_create_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(16)
        session["csrf_token"] = token
    return token


@app.before_request
def enforce_csrf():
    # Only enforce for state-changing requests
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # Skip CSRF check for auth-less endpoints
    path = request.path or ""
    csrf_exempt_paths = {
        "/api/login",
        "/api/register",
        "/api/password-reset/request",
        "/api/password-reset/confirm",
    }
    if path in csrf_exempt_paths:
        return

    sent_token = request.headers.get("X-CSRF-Token")
    session_token = session.get("csrf_token")
    if not sent_token or not session_token or sent_token != session_token:
        return jsonify({"error": "Invalid or missing CSRF token"}), 403


def compute_match_result(games):
    wins = sum(1 for g in games if g.get("result") == "W")
    losses = sum(1 for g in games if g.get("result") == "L")
    if wins > losses:
        return "Win"
    if losses > wins:
        return "Loss"
    return "Draw"


def compute_record_for_event(event_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT match_result FROM rounds WHERE event_id = ?",
        (event_id,),
    )
    rows = cur.fetchall()
    conn.close()

    w = l = d = 0
    for r in rows:
        res = r["match_result"]
        if res == "Win":
            w += 1
        elif res == "Loss":
            l += 1
        elif res == "Draw":
            d += 1

    return f"{w}-{l}-{d}" if d else f"{w}-{l}"


def round_row_to_obj(row):
    return {
        "id": row["id"],
        "eventId": row["event_id"],
        "roundNumber": row["round_number"],
        "oppDeck": row["opp_deck"],
        "dieRollWon": bool(row["die_roll_won"]),
        "matchResult": row["match_result"],
        "games": json.loads(row["games_json"]) if row["games_json"] else [],
        "comments": row["comments"] or "",
    }


# -------------------------------------------------------------------
# Auth routes
# -------------------------------------------------------------------
@app.post("/api/register")
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Check if this is the first user (make them admin)
    cur.execute("SELECT COUNT(*) as count FROM users")
    count = cur.fetchone()["count"]
    is_admin = 1 if count == 0 else 0

    try:
        pw_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, pw_hash, is_admin),
        )
        user_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already taken"}), 409
    except Exception as e:
        conn.close()
        print("Register error:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    session["user_id"] = user_id
    csrf_token = get_or_create_csrf_token()
    return jsonify({"id": user_id, "username": username, "isAdmin": bool(is_admin), "csrfToken": csrf_token})


@app.post("/api/login")
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    session["user_id"] = row["id"]
    csrf_token = get_or_create_csrf_token()
    return jsonify({"id": row["id"], "username": row["username"], "isAdmin": bool(row["is_admin"]), "csrfToken": csrf_token})


@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"user": None})

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return jsonify({"user": None})

    csrf_token = get_or_create_csrf_token()
    return jsonify({"user": {"id": row["id"], "username": row["username"], "isAdmin": bool(row["is_admin"])}, "csrfToken": csrf_token})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.post("/api/password-reset/request")
def request_password_reset():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Check if user exists
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if row is None:
        conn.close()
        return jsonify({"error": "Username not found"}), 404

    user_id = row["id"]

    # Generate secure token
    token = secrets.token_urlsafe(32)
    created_at = datetime.utcnow().isoformat()
    expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()

    try:
        cur.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, used)
            VALUES (?, ?, ?, ?, 0)
            """,
            (user_id, token, created_at, expires_at),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error creating reset token:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()

    return jsonify({"token": token, "username": username, "expiresAt": expires_at})


@app.post("/api/password-reset/confirm")
def confirm_password_reset():
    data = request.get_json() or {}
    token = (data.get("token") or "").strip()
    new_password = data.get("newPassword") or ""

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Find valid token
    cur.execute(
        """
        SELECT id, user_id, expires_at, used, approved
        FROM password_reset_tokens
        WHERE token = ?
        """,
        (token,),
    )
    row = cur.fetchone()

    if row is None:
        conn.close()
        return jsonify({"error": "Invalid token"}), 400

    if row["used"]:
        conn.close()
        return jsonify({"error": "Token has already been used"}), 400

    if not row["approved"]:
        conn.close()
        return jsonify({"error": "Token has not been approved by an admin yet"}), 403

    # Check if expired
    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        conn.close()
        return jsonify({"error": "Token has expired"}), 400

    user_id = row["user_id"]
    token_id = row["id"]

    # Update password
    pw_hash = generate_password_hash(new_password)
    try:
        cur.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (pw_hash, user_id),
        )
        # Mark token as used
        cur.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
            (token_id,),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error resetting password:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    return jsonify({"ok": True})


# -------------------------------------------------------------------
# Admin routes (password reset management)
# -------------------------------------------------------------------
@app.get("/api/admin/password-reset-requests")
@admin_required
def list_password_reset_requests():
    conn = get_db()
    cur = conn.cursor()

    # Get pending requests (not approved, not used, not expired)
    cur.execute(
        """
        SELECT
            prt.id,
            prt.token,
            prt.created_at,
            prt.expires_at,
            u.username
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        WHERE prt.approved = 0
          AND prt.used = 0
          AND datetime(prt.expires_at) > datetime('now')
        ORDER BY prt.created_at DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    requests = []
    for row in rows:
        requests.append({
            "id": row["id"],
            "username": row["username"],
            "token": row["token"],
            "createdAt": row["created_at"],
            "expiresAt": row["expires_at"],
        })

    return jsonify(requests)


@app.post("/api/admin/password-reset-requests/<int:request_id>/approve")
@admin_required
def approve_password_reset_request(request_id):
    conn = get_db()
    cur = conn.cursor()

    # Check if request exists and is valid
    cur.execute(
        """
        SELECT id, approved, used, expires_at
        FROM password_reset_tokens
        WHERE id = ?
        """,
        (request_id,),
    )
    row = cur.fetchone()

    if row is None:
        conn.close()
        return jsonify({"error": "Request not found"}), 404

    if row["approved"]:
        conn.close()
        return jsonify({"error": "Request already approved"}), 400

    if row["used"]:
        conn.close()
        return jsonify({"error": "Token already used"}), 400

    # Check if expired
    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        conn.close()
        return jsonify({"error": "Token has expired"}), 400

    # Approve the request
    try:
        cur.execute(
            "UPDATE password_reset_tokens SET approved = 1 WHERE id = ?",
            (request_id,),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error approving request:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    return jsonify({"ok": True})


@app.post("/api/admin/password-reset-requests/<int:request_id>/deny")
@admin_required
def deny_password_reset_request(request_id):
    conn = get_db()
    cur = conn.cursor()

    # Check if request exists
    cur.execute(
        "SELECT id FROM password_reset_tokens WHERE id = ?",
        (request_id,),
    )
    row = cur.fetchone()

    if row is None:
        conn.close()
        return jsonify({"error": "Request not found"}), 404

    # Delete the request
    try:
        cur.execute(
            "DELETE FROM password_reset_tokens WHERE id = ?",
            (request_id,),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error denying request:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    return jsonify({"ok": True})


@app.get("/api/admin/users")
@admin_required
def list_users():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, username, is_admin
        FROM users
        ORDER BY id ASC
        """
    )
    rows = cur.fetchall()
    conn.close()

    users = []
    for row in rows:
        users.append({
            "id": row["id"],
            "username": row["username"],
            "isAdmin": bool(row["is_admin"]),
        })

    return jsonify(users)


@app.post("/api/admin/users/<int:user_id>/set-admin")
@admin_required
def set_user_admin(user_id):
    data = request.get_json() or {}
    is_admin = data.get("isAdmin", False)

    conn = get_db()
    cur = conn.cursor()

    # Check if user exists
    cur.execute("SELECT id, is_admin FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()

    if row is None:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # Prevent revoking admin from the last admin account
    if not is_admin and row["is_admin"]:
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE is_admin = 1")
        admin_count = cur.fetchone()["cnt"]
        if admin_count <= 1:
            conn.close()
            return jsonify({"error": "Cannot revoke admin from the last admin user."}), 400

    # Update admin status
    try:
        cur.execute(
            "UPDATE users SET is_admin = ? WHERE id = ?",
            (1 if is_admin else 0, user_id),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error updating user role:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    return jsonify({"ok": True})


@app.delete("/api/admin/users/<int:user_id>")
@admin_required
def delete_user(user_id):
    # Prevent admins from deleting themselves to avoid lockouts
    if session.get("user_id") == user_id:
        return jsonify({"error": "You cannot delete your own account."}), 400

    conn = get_db()
    cur = conn.cursor()

    # Ensure user exists
    cur.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    try:
        # Gather events to remove related rounds
        cur.execute("SELECT id FROM events WHERE user_id = ?", (user_id,))
        event_ids = [r["id"] for r in cur.fetchall()]

        if event_ids:
            placeholders = ",".join("?" for _ in event_ids)
            cur.execute(f"DELETE FROM rounds WHERE event_id IN ({placeholders})", event_ids)
            cur.execute(f"DELETE FROM events WHERE id IN ({placeholders})", event_ids)

        # Remove password reset tokens
        cur.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))

        # Finally remove the user
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    except Exception as e:
        conn.close()
        print("Error deleting user:", e)
        return jsonify({"error": "Server error"}), 500

    conn.close()
    return jsonify({"ok": True})


# -------------------------------------------------------------------
# Event routes
# -------------------------------------------------------------------
@app.get("/api/events")
@login_required
def list_events():
    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM events WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()

    events = []
    for row in rows:
        record = compute_record_for_event(row["id"])
        events.append(
            {
                "id": row["id"],
                "name": row["name"],
                "yourDeck": row["your_deck"],
                "linkUrl": row["link_url"],
                "comments": row["comments"] or "",
                "eventDate": row["event_date"] or "",
                "record": record,
            }
        )
    return jsonify(events)


@app.post("/api/events")
@login_required
def create_event():
    user_id = session["user_id"]
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    your_deck = (data.get("yourDeck") or "").strip()
    link_url = (data.get("linkUrl") or "").strip() or None
    event_date = (data.get("eventDate") or "").strip() or None

    if not name or not your_deck:
        return jsonify({"error": "Name and yourDeck are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (name, your_deck, link_url, comments, event_date, user_id)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, your_deck, link_url, None, event_date, user_id),
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()

    event_obj = {
        "id": event_id,
        "name": name,
        "yourDeck": your_deck,
        "linkUrl": link_url,
        "comments": "",
        "eventDate": event_date or "",
        "record": "0-0",
    }
    return jsonify(event_obj)


@app.patch("/api/events/<int:event_id>")
@login_required
def update_event(event_id):
    user_id = session["user_id"]
    data = request.get_json() or {}

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM events WHERE id = ? AND user_id = ?",
        (event_id, user_id),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Event not found"}), 404

    new_name = data.get("name", row["name"])
    new_deck = data.get("yourDeck", row["your_deck"])
    new_link = data.get("linkUrl", row["link_url"])
    new_comments = data.get("comments", row["comments"])
    new_date = data.get("eventDate", row["event_date"])

    cur.execute(
        """
        UPDATE events
        SET name = ?, your_deck = ?, link_url = ?, comments = ?, event_date = ?
        WHERE id = ?
        """,
        (new_name, new_deck, new_link, new_comments, new_date, event_id),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@app.delete("/api/events/<int:event_id>")
@login_required
def delete_event(event_id):
    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM events WHERE id = ? AND user_id = ?",
        (event_id, user_id),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Event not found"}), 404

    cur.execute("DELETE FROM rounds WHERE event_id = ?", (event_id,))
    cur.execute("DELETE FROM events WHERE id = ?", (event_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# -------------------------------------------------------------------
# Round routes
# -------------------------------------------------------------------
@app.get("/api/rounds")
@login_required
def list_rounds():
    user_id = session["user_id"]
    event_id = request.args.get("event_id", type=int)
    if not event_id:
        return jsonify({"error": "event_id is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Ensure event belongs to user
    cur.execute(
        "SELECT id FROM events WHERE id = ? AND user_id = ?",
        (event_id, user_id),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Event not found"}), 404

    cur.execute(
        """
        SELECT * FROM rounds
        WHERE event_id = ?
        ORDER BY round_number ASC
        """,
        (event_id,),
    )
    rows = cur.fetchall()
    conn.close()

    rounds = [round_row_to_obj(r) for r in rows]
    return jsonify(rounds)


@app.post("/api/rounds")
@login_required
def create_round():
    user_id = session["user_id"]
    data = request.get_json() or {}

    event_id = data.get("eventId")
    round_number = data.get("roundNumber")
    opp_deck = (data.get("oppDeck") or "").strip()
    games = data.get("games") or []
    die_roll_won = bool(data.get("dieRollWon"))
    comments = data.get("comments") or None

    if not event_id or not round_number or not opp_deck or not isinstance(games, list):
        return jsonify({"error": "eventId, roundNumber, oppDeck, games required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # Ensure event belongs to user
    cur.execute(
        "SELECT id FROM events WHERE id = ? AND user_id = ?",
        (event_id, user_id),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({"error": "Event not found"}), 404

    match_result = compute_match_result(games)
    games_json = json.dumps(games)

    cur.execute(
        """
        INSERT INTO rounds
          (event_id, round_number, opp_deck, die_roll_won, match_result, games_json, comments)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, round_number, opp_deck, int(die_roll_won), match_result, games_json, comments),
    )
    round_id = cur.lastrowid
    conn.commit()

    cur.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
    row = cur.fetchone()
    conn.close()

    return jsonify(round_row_to_obj(row))


@app.patch("/api/rounds/<int:round_id>")
@login_required
def update_round(round_id):
    user_id = session["user_id"]
    data = request.get_json() or {}

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
    round_row = cur.fetchone()
    if round_row is None:
        conn.close()
        return jsonify({"error": "Round not found"}), 404

    # ensure event belongs to current user
    cur.execute(
        "SELECT id, user_id FROM events WHERE id = ?",
        (round_row["event_id"],),
    )
    event_row = cur.fetchone()
    if event_row is None or event_row["user_id"] != user_id:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403

    new_round_number = data.get("roundNumber", round_row["round_number"])
    new_opp_deck = data.get("oppDeck", round_row["opp_deck"])
    new_die_roll_won = data.get("dieRollWon")
    if new_die_roll_won is None:
        new_die_roll_won = round_row["die_roll_won"]
    else:
        new_die_roll_won = int(bool(new_die_roll_won))

    new_comments = data.get("comments", round_row["comments"])

    games = data.get("games")
    if games is not None:
        games_json = json.dumps(games)
        match_result = compute_match_result(games)
    else:
        games_json = round_row["games_json"]
        match_result = round_row["match_result"]

    cur.execute(
        """
        UPDATE rounds
        SET round_number = ?, opp_deck = ?, die_roll_won = ?, match_result = ?, games_json = ?, comments = ?
        WHERE id = ?
        """,
        (
            new_round_number,
            new_opp_deck,
            new_die_roll_won,
            match_result,
            games_json,
            new_comments,
            round_id,
        ),
    )
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@app.delete("/api/rounds/<int:round_id>")
@login_required
def delete_round(round_id):
    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
    round_row = cur.fetchone()
    if round_row is None:
        conn.close()
        return jsonify({"error": "Round not found"}), 404

    cur.execute(
        "SELECT id, user_id FROM events WHERE id = ?",
        (round_row["event_id"],),
    )
    event_row = cur.fetchone()
    if event_row is None or event_row["user_id"] != user_id:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403

    cur.execute("DELETE FROM rounds WHERE id = ?", (round_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# -------------------------------------------------------------------
# Stats routes
# -------------------------------------------------------------------
@app.get("/api/stats")
@login_required
def get_stats():
    user_id = session["user_id"]
    start_date = request.args.get("startDate")
    end_date = request.args.get("endDate")

    conn = get_db()
    cur = conn.cursor()

    # Build query with optional date filtering
    query = """
        SELECT e.id, e.your_deck, r.opp_deck, r.match_result, r.games_json
        FROM events e
        JOIN rounds r ON e.id = r.event_id
        WHERE e.user_id = ?
    """
    params = [user_id]

    if start_date:
        query += " AND e.event_date >= ?"
        params.append(start_date)

    if end_date:
        query += " AND e.event_date <= ?"
        params.append(end_date)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    # Build matchup statistics for both matches and games
    match_stats = {}
    game_stats = {}
    all_decks = set()

    for row in rows:
        your_deck = row["your_deck"]
        opp_deck = row["opp_deck"]
        match_result = row["match_result"]
        games_json = row["games_json"]

        all_decks.add(your_deck)
        all_decks.add(opp_deck)

        # Match statistics
        if your_deck not in match_stats:
            match_stats[your_deck] = {}
        if opp_deck not in match_stats[your_deck]:
            match_stats[your_deck][opp_deck] = {"wins": 0, "losses": 0, "draws": 0}

        if match_result == "Win":
            match_stats[your_deck][opp_deck]["wins"] += 1
        elif match_result == "Loss":
            match_stats[your_deck][opp_deck]["losses"] += 1
        elif match_result == "Draw":
            match_stats[your_deck][opp_deck]["draws"] += 1

        # Game statistics
        if games_json:
            games = json.loads(games_json)
            if your_deck not in game_stats:
                game_stats[your_deck] = {}
            if opp_deck not in game_stats[your_deck]:
                game_stats[your_deck][opp_deck] = {"wins": 0, "losses": 0, "draws": 0}

            for game in games:
                game_result = game.get("result")
                if game_result == "W":
                    game_stats[your_deck][opp_deck]["wins"] += 1
                elif game_result == "L":
                    game_stats[your_deck][opp_deck]["losses"] += 1
                elif game_result == "T":
                    game_stats[your_deck][opp_deck]["draws"] += 1

    # Calculate win rates for matches
    match_winrates = []
    for your_deck in match_stats:
        for opp_deck in match_stats[your_deck]:
            data = match_stats[your_deck][opp_deck]
            wins = data["wins"]
            losses = data["losses"]
            draws = data["draws"]
            total = wins + losses + draws

            if wins + losses > 0:
                win_rate = wins / (wins + losses)
            else:
                win_rate = 0.5

            match_winrates.append({
                "yourDeck": your_deck,
                "oppDeck": opp_deck,
                "wins": wins,
                "losses": losses,
                "draws": draws,
                "total": total,
                "winRate": win_rate
            })

    # Calculate win rates for games
    game_winrates = []
    for your_deck in game_stats:
        for opp_deck in game_stats[your_deck]:
            data = game_stats[your_deck][opp_deck]
            wins = data["wins"]
            losses = data["losses"]
            draws = data["draws"]
            total = wins + losses + draws

            if wins + losses > 0:
                win_rate = wins / (wins + losses)
            else:
                win_rate = 0.5

            game_winrates.append({
                "yourDeck": your_deck,
                "oppDeck": opp_deck,
                "wins": wins,
                "losses": losses,
                "draws": draws,
                "total": total,
                "winRate": win_rate
            })

    return jsonify({
        "matchStats": match_winrates,
        "gameStats": game_winrates,
        "allDecks": sorted(list(all_decks))
    })


# -------------------------------------------------------------------
# Frontend
# -------------------------------------------------------------------
@app.route("/")
def index():
    # serve index.html from this folder
    return send_from_directory(app.static_folder, "index.html")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5050)
