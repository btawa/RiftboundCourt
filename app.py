from flask import Flask, jsonify, request, send_from_directory
import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "riftbound.db")

app = Flask(__name__, static_folder=".", static_url_path="")

# ---------- DB helpers ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    # events table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            your_deck TEXT,
            link_url  TEXT,
            comments  TEXT
        )
    """)

    # ensure new columns exist on older DBs
    cur.execute("PRAGMA table_info(events)")
    e_cols = [row["name"] for row in cur.fetchall()]
    if "your_deck" not in e_cols:
        cur.execute("ALTER TABLE events ADD COLUMN your_deck TEXT")
    if "link_url" not in e_cols:
        cur.execute("ALTER TABLE events ADD COLUMN link_url TEXT")
    if "comments" not in e_cols:
        cur.execute("ALTER TABLE events ADD COLUMN comments TEXT")

    # rounds table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id     INTEGER,
            event_name   TEXT,
            event_date   TEXT,
            round_number INTEGER NOT NULL,
            your_deck    TEXT,
            opp_deck     TEXT NOT NULL,
            match_result TEXT NOT NULL,
            die_roll_won INTEGER NOT NULL DEFAULT 0,
            comments     TEXT,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    cur.execute("PRAGMA table_info(rounds)")
    r_cols = [row["name"] for row in cur.fetchall()]
    if "event_id" not in r_cols:
        cur.execute("ALTER TABLE rounds ADD COLUMN event_id INTEGER")
    if "comments" not in r_cols:
        cur.execute("ALTER TABLE rounds ADD COLUMN comments TEXT")

    # games table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id    INTEGER NOT NULL,
            game_number INTEGER NOT NULL,
            result      TEXT NOT NULL,
            on_play     INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (round_id) REFERENCES rounds(id) ON DELETE CASCADE
        )
    """)

    # attach legacy rounds with NULL event_id to a default event
    cur.execute("SELECT COUNT(*) AS c FROM rounds WHERE event_id IS NULL")
    row = cur.fetchone()
    if row and row["c"] > 0:
        cur.execute("INSERT INTO events(name) VALUES (?)", ("Imported Rounds",))
        default_id = cur.lastrowid
        cur.execute("UPDATE rounds SET event_id = ? WHERE event_id IS NULL",
                    (default_id,))

    conn.commit()
    conn.close()


# ---------- Serialization helpers ----------

def round_to_dict(row, games):
    return {
        "id": row["id"],
        "eventId": row["event_id"],
        "roundNumber": row["round_number"],
        "oppDeck": row["opp_deck"],
        "matchResult": row["match_result"],
        "dieRollWon": bool(row["die_roll_won"]),
        "comments": row["comments"],
        "games": [
            {
                "id": g["id"],
                "number": g["game_number"],
                "result": g["result"],
                "onPlay": bool(g["on_play"]),
            }
            for g in games
        ],
    }


def compute_match_result_from_games(games):
    wins = sum(1 for g in games if g.get("result") == "W")
    losses = sum(1 for g in games if g.get("result") == "L")
    if wins == 0 and losses == 0:
        return "Draw"
    if wins > losses:
        return "Win"
    if losses > wins:
        return "Loss"
    return "Draw"


def compute_record_from_round_rows(rows):
    wins = sum(1 for r in rows if r["match_result"] == "Win")
    losses = sum(1 for r in rows if r["match_result"] == "Loss")
    draws = sum(1 for r in rows if r["match_result"] == "Draw")
    if draws:
        return f"{wins}-{losses}-{draws}"
    return f"{wins}-{losses}"


# ---------- Events API ----------

@app.route("/api/events", methods=["GET"])
def get_events():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM events ORDER BY id DESC")
    events_rows = cur.fetchall()

    events = []
    for e in events_rows:
        cur.execute("SELECT match_result FROM rounds WHERE event_id = ?", (e["id"],))
        round_rows = cur.fetchall()
        record = compute_record_from_round_rows(round_rows) if round_rows else "0-0"
        events.append({
            "id": e["id"],
            "name": e["name"],
            "yourDeck": e["your_deck"],
            "linkUrl": e["link_url"],
            "comments": e["comments"],
            "record": record,
        })

    conn.close()
    return jsonify(events)


@app.route("/api/events", methods=["POST"])
def create_event():
    data = request.get_json(force=True) or {}

    name = (data.get("name") or "").strip()
    your_deck = (data.get("yourDeck") or "").strip()
    link_url = (data.get("linkUrl") or "").strip() or None

    if not name or not your_deck:
        return jsonify({"error": "Event name and your deck are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO events(name, your_deck, link_url, comments) VALUES (?, ?, ?, ?)",
        (name, your_deck, link_url, None),
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "id": event_id,
        "name": name,
        "yourDeck": your_deck,
        "linkUrl": link_url,
        "comments": None,
        "record": "0-0",
    }), 201


@app.route("/api/events/<int:event_id>", methods=["PATCH"])
def update_event(event_id):
    data = request.get_json(force=True) or {}
    fields = []
    params = []

    if "name" in data:
        fields.append("name = ?")
        params.append(data.get("name"))

    if "comments" in data:
        fields.append("comments = ?")
        params.append(data.get("comments"))

    if "yourDeck" in data:
        fields.append("your_deck = ?")
        params.append(data.get("yourDeck"))

    if "linkUrl" in data:
        fields.append("link_url = ?")
        params.append(data.get("linkUrl"))

    if not fields:
        return jsonify({"error": "No updatable fields provided"}), 400

    params.append(event_id)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"UPDATE events SET {', '.join(fields)} WHERE id = ?", params)
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/events/<int:event_id>", methods=["DELETE"])
def delete_event(event_id):
    conn = get_db()
    cur = conn.cursor()

    # Manually delete games -> rounds -> event (in case FK cascade not active)
    cur.execute("SELECT id FROM rounds WHERE event_id = ?", (event_id,))
    round_ids = [r["id"] for r in cur.fetchall()]

    if round_ids:
        placeholders = ",".join("?" for _ in round_ids)
        cur.execute(f"DELETE FROM games WHERE round_id IN ({placeholders})", round_ids)

    cur.execute("DELETE FROM rounds WHERE event_id = ?", (event_id,))
    cur.execute("DELETE FROM events WHERE id = ?", (event_id,))

    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------- Rounds API ----------

@app.route("/api/rounds", methods=["GET"])
def get_rounds():
    event_id = request.args.get("event_id", type=int)

    conn = get_db()
    cur = conn.cursor()

    if event_id:
        cur.execute(
            "SELECT * FROM rounds WHERE event_id = ? ORDER BY round_number ASC",
            (event_id,),
        )
    else:
        cur.execute("SELECT * FROM rounds ORDER BY round_number ASC")

    rounds_rows = cur.fetchall()
    round_ids = [r["id"] for r in rounds_rows]
    games_by_round = {rid: [] for rid in round_ids}

    if round_ids:
        placeholders = ",".join("?" for _ in round_ids)
        cur.execute(
            f"SELECT * FROM games "
            f"WHERE round_id IN ({placeholders}) "
            f"ORDER BY game_number ASC",
            round_ids,
        )
        for g in cur.fetchall():
            games_by_round[g["round_id"]].append(g)

    conn.close()

    result = [
        round_to_dict(r, games_by_round.get(r["id"], []))
        for r in rounds_rows
    ]
    return jsonify(result)


@app.route("/api/rounds", methods=["POST"])
def create_round():
    data = request.get_json(force=True) or {}

    event_id = int(data.get("eventId") or 0)
    round_number = int(data.get("roundNumber") or 0)
    opp_deck = (data.get("oppDeck") or "").strip()
    games_payload = data.get("games") or []
    die_roll_won = 1 if data.get("dieRollWon") else 0

    if event_id <= 0 or round_number < 1 or not opp_deck:
        return jsonify({"error": "Invalid input"}), 400

    match_result = compute_match_result_from_games(games_payload)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO rounds (event_id, event_name, event_date, round_number, your_deck,
                            opp_deck, match_result, die_roll_won, comments)
        VALUES (?, NULL, NULL, ?, NULL, ?, ?, ?, NULL)
    """, (event_id, round_number, opp_deck, match_result, die_roll_won))
    round_id = cur.lastrowid

    for g in games_payload:
        result = g.get("result")
        if not result:
            continue
        game_number = int(g.get("number") or 0)
        on_play = 1 if g.get("onPlay") else 0
        cur.execute("""
            INSERT INTO games (round_id, game_number, result, on_play)
            VALUES (?, ?, ?, ?)
        """, (round_id, game_number, result, on_play))

    conn.commit()

    cur.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
    r = cur.fetchone()
    cur.execute(
        "SELECT * FROM games WHERE round_id = ? ORDER BY game_number ASC",
        (round_id,),
    )
    g_rows = cur.fetchall()
    conn.close()

    return jsonify(round_to_dict(r, g_rows)), 201


@app.route("/api/rounds/<int:round_id>", methods=["PATCH"])
def update_round(round_id):
    data = request.get_json(force=True) or {}

    fields = []
    params = []

    round_number = data.get("roundNumber")
    opp_deck = data.get("oppDeck")
    die_roll_won = data.get("dieRollWon")
    games_payload = data.get("games")
    comments = data.get("comments")

    if round_number is not None:
        fields.append("round_number = ?")
        params.append(int(round_number))

    if opp_deck is not None:
        fields.append("opp_deck = ?")
        params.append((opp_deck or "").strip())

    if die_roll_won is not None:
        fields.append("die_roll_won = ?")
        params.append(1 if die_roll_won else 0)

    if comments is not None:
        fields.append("comments = ?")
        params.append(comments)

    if games_payload is not None:
        match_result = compute_match_result_from_games(games_payload)
        fields.append("match_result = ?")
        params.append(match_result)

    if not fields and games_payload is None:
        return jsonify({"error": "No updatable fields provided"}), 400

    params.append(round_id)

    conn = get_db()
    cur = conn.cursor()

    if fields:
        cur.execute(f"UPDATE rounds SET {', '.join(fields)} WHERE id = ?", params)

    # Replace games if provided
    if games_payload is not None:
        cur.execute("DELETE FROM games WHERE round_id = ?", (round_id,))
        for g in games_payload:
            result = g.get("result")
            if not result:
                continue
            game_number = int(g.get("number") or 0)
            on_play = 1 if g.get("onPlay") else 0
            cur.execute("""
                INSERT INTO games (round_id, game_number, result, on_play)
                VALUES (?, ?, ?, ?)
            """, (round_id, game_number, result, on_play))

    conn.commit()

    # Return fresh round
    cur.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
    r = cur.fetchone()
    cur.execute(
        "SELECT * FROM games WHERE round_id = ? ORDER BY game_number ASC",
        (round_id,),
    )
    g_rows = cur.fetchall()
    conn.close()

    return jsonify(round_to_dict(r, g_rows))


@app.route("/api/rounds/<int:round_id>", methods=["DELETE"])
def delete_round(round_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM rounds WHERE id = ?", (round_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ---------- Frontend ----------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
