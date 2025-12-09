import json
import sqlite3
from functools import wraps

from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "riftbound.db"

# -------------------------------------------------------------------
# Flask app
# -------------------------------------------------------------------
app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = "CHANGE_THIS_SECRET_KEY"  # replace for real use


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
            password_hash TEXT NOT NULL
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

    try:
        pw_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
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
    return jsonify({"id": user_id, "username": username})


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
    return jsonify({"id": row["id"], "username": row["username"]})


@app.get("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"user": None})

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return jsonify({"user": None})

    return jsonify({"user": {"id": row["id"], "username": row["username"]}})


@app.post("/api/logout")
def logout():
    session.clear()
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

    if not name or not your_deck:
        return jsonify({"error": "Name and yourDeck are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO events (name, your_deck, link_url, comments, user_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (name, your_deck, link_url, None, user_id),
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

    cur.execute(
        """
        UPDATE events
        SET name = ?, your_deck = ?, link_url = ?, comments = ?
        WHERE id = ?
        """,
        (new_name, new_deck, new_link, new_comments, event_id),
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
    app.run(host="0.0.0.0", port=5000, debug=True)
