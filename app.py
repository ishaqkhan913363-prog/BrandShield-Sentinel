from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import sqlite3, os, csv, io, json, re, hashlib, secrets, unicodedata
from itertools import combinations
from urllib.parse import urlsplit, urlunsplit

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SENTINEL_DB_PATH", str(BASE / "sentinel.db"))).expanduser()
IS_PRODUCTION = os.environ.get("SENTINEL_ENV", "development").lower() == "production"
SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY")
if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SENTINEL_SECRET_KEY must be configured in production.")
app = Flask(__name__)
app.secret_key = SECRET_KEY or "local-development-key-only"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_CHECK_DEFAULT=True,
)
csrf = CSRFProtect(app)
MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_IMPORT_ROWS = 10000
MONITORING_PAGE_SIZE = 25
MAX_LINKED_ENTITIES_PER_INDICATOR = 25
MAX_NETWORK_LINKS = 5000
app.config["MAX_CONTENT_LENGTH"] = MAX_IMPORT_BYTES + 64 * 1024

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_observed_at(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            name TEXT NOT NULL, industry TEXT DEFAULT '', website TEXT DEFAULT '',
            description TEXT DEFAULT '', created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            kind TEXT NOT NULL, value TEXT NOT NULL, notes TEXT DEFAULT '',
            created_at TEXT NOT NULL, UNIQUE(brand_id, kind, value),
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            channel TEXT NOT NULL, name TEXT NOT NULL, url TEXT DEFAULT '',
            developer TEXT DEFAULT '', description TEXT DEFAULT '', logo_match INTEGER DEFAULT 0,
            status TEXT DEFAULT 'New', source TEXT DEFAULT 'Manual entry', confidence INTEGER DEFAULT 0,
            risk TEXT DEFAULT 'Low', rationale TEXT DEFAULT '', first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id INTEGER NOT NULL,
            kind TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            label TEXT NOT NULL, scanned_count INTEGER DEFAULT 0, flagged_count INTEGER DEFAULT 0,
            source_mode TEXT DEFAULT 'Demo + manual', created_at TEXT NOT NULL,
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            key TEXT NOT NULL, value TEXT DEFAULT '', UNIQUE(brand_id, key),
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS network_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL, entity_type TEXT NOT NULL,
            label TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(brand_id, candidate_id),
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE,
            FOREIGN KEY(candidate_id) REFERENCES candidates(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS network_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
            kind TEXT NOT NULL, normalized_value TEXT NOT NULL,
            display_value TEXT NOT NULL, first_observed TEXT NOT NULL,
            UNIQUE(brand_id, kind, normalized_value),
            FOREIGN KEY(brand_id) REFERENCES brands(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS network_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER NOT NULL,
            indicator_id INTEGER NOT NULL, source_field TEXT NOT NULL,
            observed_at TEXT NOT NULL, time_basis TEXT NOT NULL DEFAULT 'captured',
            source_confidence REAL NOT NULL,
            UNIQUE(entity_id,indicator_id,source_field),
            FOREIGN KEY(entity_id) REFERENCES network_entities(id) ON DELETE CASCADE,
            FOREIGN KEY(indicator_id) REFERENCES network_indicators(id) ON DELETE CASCADE
        );
        """)
        candidate_columns = {row["name"] for row in c.execute("PRAGMA table_info(candidates)")}
        if "observed_at" not in candidate_columns:
            c.execute("ALTER TABLE candidates ADD COLUMN observed_at TEXT DEFAULT ''")
        user_columns = {row["name"] for row in c.execute("PRAGMA table_info(users)")}
        if "full_name" not in user_columns:
            c.execute("ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''")
        observation_columns = {row["name"] for row in c.execute("PRAGMA table_info(network_observations)")}
        if "time_basis" not in observation_columns:
            c.execute("ALTER TABLE network_observations ADD COLUMN time_basis TEXT NOT NULL DEFAULT 'captured'")
        c.execute("""UPDATE users SET full_name=trim(
            substr(email,1,instr(email,'@')-1)) WHERE full_name=''""")
        # Seed a usable demo workspace on first run.
        if not IS_PRODUCTION and c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            c.execute("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",
                      ("demo@sentinel.local", generate_password_hash("SentinelDemo!26"), now()))
        user = c.execute("SELECT id FROM users WHERE email=?", ("demo@sentinel.local",)).fetchone()
        if user:
            uid = user["id"]
            if c.execute("SELECT COUNT(*) FROM brands WHERE user_id=?", (uid,)).fetchone()[0] == 0:
                c.execute("INSERT INTO brands(user_id,name,industry,website,description,created_at) VALUES(?,?,?,?,?,?)",
                          (uid, "Northstar", "Consumer technology", "https://northstar.example",
                           "Demo brand workspace. Replace these values with your legitimate brand details.", now()))
                bid = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                seed_assets = [
                    ("Official website", "https://northstar.example", "Demo URL — replace with verified official domain"),
                    ("Social handle", "@northstar_official", "Demo handle"),
                    ("App package", "com.northstar.mobile", "Demo package identifier"),
                    ("Trademark / keyword", "Northstar", "Brand name")
                ]
                for kind, value, notes in seed_assets:
                    c.execute("INSERT OR IGNORE INTO assets(brand_id,kind,value,notes,created_at) VALUES(?,?,?,?,?)",
                              (bid, kind, value, notes, now()))
                samples = [
                    ("Social", "Northstar Support Desk", "https://social.example/northstar-help", "", "Urgent account recovery and payment support", 0, "Demo dataset", "New"),
                    ("App Store", "Northstar Wallet Plus", "https://store.example/apps/northstar-wallet", "Unknown Studio", "A companion wallet app using similar naming", 1, "Demo dataset", "Investigating"),
                    ("Social", "Northstar Rewards Center", "https://social.example/northstar-rewards", "", "Claim a reward by sharing account details", 0, "Demo dataset", "New"),
                    ("App Store", "North Star Notes", "https://store.example/apps/north-star-notes", "Paper Kite Labs", "Notes app with a partially similar name", 0, "Demo dataset", "False positive")
                ]
                for channel, name, url, dev, desc, logo, source, status in samples:
                    score, risk, rationale = score_candidate("Northstar", channel, name, url, dev, desc, logo,
                                                             ["https://northstar.example", "@northstar_official", "com.northstar.mobile"])
                    if status == "False positive":
                        score, risk = 21, "Low"
                    c.execute("""INSERT INTO candidates(brand_id,channel,name,url,developer,description,logo_match,status,source,
                              confidence,risk,rationale,first_seen,last_seen,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (bid, channel, name, url, dev, desc, logo, status, source, score, risk, rationale, now(), now(), now()))
                c.execute("INSERT INTO scans(brand_id,label,scanned_count,flagged_count,source_mode,created_at) VALUES(?,?,?,?,?,?)",
                          (bid, "Initial demo scan", 24, 3, "Synthetic sample data", now()))
                for key, val in [("social_sources","Demo data, manual entry"),("app_sources","Demo data, manual entry"),
                                 ("notifications","In-app"),("scan_mode","Demo + manual")]:
                    c.execute("INSERT OR IGNORE INTO settings(brand_id,key,value) VALUES(?,?,?)",(bid,key,val))

def normalize(s):
    s = unicodedata.normalize("NFKD", (s or "").lower())
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]", "", s)

def candidate_fingerprint(channel, name, url):
    return (channel.strip().casefold(), normalize(name), normalize(url))

def extract_network_indicators(candidate):
    indicators = {}
    def add(kind, value, source_field, display_value=None):
        normalized_value = normalize(value) if kind == "publisher" else value
        if not normalized_value:
            return
        key = (kind, normalized_value, source_field)
        indicators[key] = (kind, normalized_value, display_value or value, source_field)

    for source_field in ("url", "description"):
        text = candidate[source_field] or ""
        urls = [candidate["url"]] if source_field == "url" and candidate["url"] else []
        urls.extend(re.findall(r"https?://[^\s<>'\"),]+", text, flags=re.IGNORECASE))
        for raw_url in urls:
            raw_url = raw_url.rstrip(".,;:!?)]}")
            try:
                parsed = urlsplit(raw_url if "://" in raw_url else "https://" + raw_url)
                hostname = (parsed.hostname or "").lower().rstrip(".")
                if not hostname or "." not in hostname:
                    continue
                port = f":{parsed.port}" if parsed.port else ""
                canonical_url = urlunsplit((
                    parsed.scheme.lower(), hostname + port, parsed.path.rstrip("/"),
                    parsed.query, ""
                ))
                context_start = max(0, text.lower().find(raw_url.lower()) - 80)
                context_end = text.lower().find(raw_url.lower()) + len(raw_url) + 80
                payment_context = re.search(
                    r"payment|pay|checkout|donat|wallet|transfer|cash.?app|venmo|paypal|stripe|upi",
                    raw_url + " " + text[context_start:context_end], re.IGNORECASE)
                add("payment_url" if payment_context else "url", canonical_url,
                    source_field, raw_url)
                common_hosts = {
                    "instagram.com", "facebook.com", "tiktok.com", "youtube.com",
                    "linkedin.com", "x.com", "twitter.com", "play.google.com",
                    "apps.apple.com", "apple.com", "linktr.ee", "bit.ly",
                }
                is_common_host = any(hostname == host or hostname.endswith("." + host)
                                     for host in common_hosts)
                if not hostname.endswith(".example") and not is_common_host:
                    add("domain", hostname, source_field, hostname)
            except ValueError:
                continue

        for raw_phone in re.findall(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)", text):
            digits = re.sub(r"\D", "", raw_phone)
            if 9 <= len(digits) <= 15:
                add("phone", digits, source_field, raw_phone.strip())

    developer = (candidate["developer"] or "").strip()
    if candidate["channel"] == "App Store" and developer:
        add("publisher", developer, "developer", developer)
    return list(indicators.values())

def sync_network_entity(connection, candidate, entity_ids, indicator_ids, observations_by_entity):
    source_quality = {
        "Manual entry": 0.60,
        "CSV import": 0.60,
        "Demo dataset": 0.35,
    }.get(candidate["source"], 0.50)
    entity_id = entity_ids.get(candidate["id"])
    if entity_id is None:
        connection.execute("""INSERT INTO network_entities
            (brand_id,candidate_id,entity_type,label,created_at) VALUES(?,?,?,?,?)
            ON CONFLICT(brand_id,candidate_id) DO UPDATE SET
            entity_type=excluded.entity_type,label=excluded.label""",
            (candidate["brand_id"], candidate["id"], candidate["channel"],
             candidate["name"], candidate["created_at"]))
        entity_id = connection.execute(
            "SELECT id FROM network_entities WHERE brand_id=? AND candidate_id=?",
            (candidate["brand_id"], candidate["id"])).fetchone()["id"]
        entity_ids[candidate["id"]] = entity_id
    else:
        connection.execute("UPDATE network_entities SET entity_type=?,label=? WHERE id=?",
                           (candidate["channel"], candidate["name"], entity_id))

    expected = set()
    source_observed_at = parse_observed_at(candidate["observed_at"])
    observed_at = source_observed_at or candidate["created_at"]
    time_basis = "source-reported" if source_observed_at else "captured"
    for kind, normalized_value, display_value, source_field in extract_network_indicators(candidate):
        indicator_key = (candidate["brand_id"], kind, normalized_value)
        indicator_id = indicator_ids.get(indicator_key)
        if indicator_id is None:
            connection.execute("""INSERT OR IGNORE INTO network_indicators
                (brand_id,kind,normalized_value,display_value,first_observed) VALUES(?,?,?,?,?)""",
                (candidate["brand_id"], kind, normalized_value, display_value, candidate["last_seen"]))
            indicator_id = connection.execute("""SELECT id FROM network_indicators
                WHERE brand_id=? AND kind=? AND normalized_value=?""",
                indicator_key).fetchone()["id"]
            indicator_ids[indicator_key] = indicator_id
        expected.add((indicator_id, source_field))
        connection.execute("""INSERT INTO network_observations
            (entity_id,indicator_id,source_field,observed_at,time_basis,source_confidence)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(entity_id,indicator_id,source_field) DO UPDATE SET
            observed_at=excluded.observed_at,time_basis=excluded.time_basis,
            source_confidence=excluded.source_confidence""",
            (entity_id, indicator_id, source_field, observed_at, time_basis, source_quality))

    current = observations_by_entity.get(entity_id, set())
    connection.executemany("""DELETE FROM network_observations
        WHERE entity_id=? AND indicator_id=? AND source_field=?""",
        [(entity_id, indicator_id, source_field)
         for indicator_id, source_field in current if (indicator_id, source_field) not in expected])
    observations_by_entity[entity_id] = expected

def build_network_graph(connection, brand_id):
    candidates = connection.execute("""SELECT * FROM candidates WHERE brand_id=?
        ORDER BY confidence DESC,id DESC""", (brand_id,)).fetchall()
    entity_ids = {row["candidate_id"]: row["id"] for row in connection.execute(
        "SELECT id,candidate_id FROM network_entities WHERE brand_id=?", (brand_id,)).fetchall()}
    indicator_ids = {
        (row["brand_id"], row["kind"], row["normalized_value"]): row["id"]
        for row in connection.execute(
            "SELECT id,brand_id,kind,normalized_value FROM network_indicators WHERE brand_id=?",
            (brand_id,)).fetchall()
    }
    observations_by_entity = {}
    for row in connection.execute("""SELECT o.entity_id,o.indicator_id,o.source_field
        FROM network_observations o JOIN network_entities e ON e.id=o.entity_id
        WHERE e.brand_id=?""", (brand_id,)).fetchall():
        observations_by_entity.setdefault(row["entity_id"], set()).add(
            (row["indicator_id"], row["source_field"]))
    for candidate in candidates:
        sync_network_entity(connection, candidate, entity_ids, indicator_ids,
                            observations_by_entity)
    connection.execute("""DELETE FROM network_indicators WHERE brand_id=?
        AND NOT EXISTS (SELECT 1 FROM network_observations
                        WHERE network_observations.indicator_id=network_indicators.id)""",
        (brand_id,))

    entities = connection.execute("""SELECT e.id AS entity_id,e.candidate_id,e.entity_type,e.label,
        c.risk,c.status,c.confidence,c.source,c.created_at
        FROM network_entities e JOIN candidates c ON c.id=e.candidate_id
        WHERE e.brand_id=? ORDER BY e.id""", (brand_id,)).fetchall()
    all_observations = connection.execute("""SELECT o.entity_id,e.candidate_id,c.status,i.kind,
        i.normalized_value,i.display_value AS value,
        o.source_field,o.observed_at,o.time_basis,o.source_confidence FROM network_observations o
        JOIN network_indicators i ON i.id=o.indicator_id
        JOIN network_entities e ON e.id=o.entity_id
        JOIN candidates c ON c.id=e.candidate_id
        WHERE e.brand_id=? ORDER BY i.kind,i.display_value""", (brand_id,)).fetchall()
    by_entity = {}
    for observation in all_observations:
        by_entity.setdefault(observation["entity_id"], []).append(observation)
    nodes = []
    for row in entities:
        nodes.append({
            "id": f"candidate-{row['candidate_id']}",
            "candidate_id": row["candidate_id"],
            "label": row["label"],
            "type": row["entity_type"],
            "risk": row["risk"],
            "status": row["status"],
            "score": row["confidence"],
            "source": row["source"],
            "created_at": row["created_at"],
            "observations": [
                {key: item[key] for key in ("kind", "value", "source_field", "observed_at",
                                             "time_basis", "source_confidence")}
                for item in by_entity.get(row["entity_id"], [])
            ],
        })

    grouped = {}
    for observation in all_observations:
        key = (observation["kind"], observation["normalized_value"])
        grouped.setdefault(key, []).append(observation)

    strength_by_kind = {"url": 90, "payment_url": 94, "phone": 90,
                        "domain": 55, "publisher": 48}
    edges = {}
    suppressed_link_pairs = 0
    for (kind, _), matches in grouped.items():
        by_candidate = {}
        for item in matches:
            if item["status"] == "False positive":
                continue
            by_candidate.setdefault(item["candidate_id"], item)
        if len(by_candidate) > MAX_LINKED_ENTITIES_PER_INDICATOR:
            continue
        for first, second in combinations(by_candidate.values(), 2):
            first_id, second_id = sorted((first["candidate_id"], second["candidate_id"]))
            key = (first_id, second_id)
            if key not in edges and len(edges) >= MAX_NETWORK_LINKS:
                suppressed_link_pairs += 1
                continue
            reliability = min(first["source_confidence"], second["source_confidence"])
            strength = round(strength_by_kind[kind] * (0.65 + 0.35 * reliability))
            evidence = {
                "type": kind,
                "value": first["value"],
                "source_fields": [first["source_field"], second["source_field"]],
                "observed_at": [first["observed_at"], second["observed_at"]],
                "time_basis": [first["time_basis"], second["time_basis"]],
                "time_basis": [first["time_basis"], second["time_basis"]],
                "source_quality": round(reliability, 2),
                "strength": strength,
            }
            if key not in edges:
                edges[key] = {"source": f"candidate-{first_id}",
                              "target": f"candidate-{second_id}", "evidence": []}
            edges[key]["evidence"].append(evidence)
    links = []
    for edge in edges.values():
        edge["evidence"].sort(key=lambda item: item["strength"], reverse=True)
        edge["strength"] = max(item["strength"] for item in edge["evidence"])
        edge["label"] = ", ".join(dict.fromkeys(
            {"url": "shared URL", "payment_url": "shared payment URL",
             "phone": "shared phone", "domain": "shared domain",
             "publisher": "shared publisher"}[item["type"]]
            for item in edge["evidence"]))
        links.append(edge)
    degree = {}
    for link in links:
        degree[link["source"]] = degree.get(link["source"], 0) + 1
        degree[link["target"]] = degree.get(link["target"], 0) + 1
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    nodes.sort(key=lambda node: (degree.get(node["id"], 0), risk_order.get(node["risk"], 0),
                                 node["score"]), reverse=True)
    return {"nodes": nodes, "links": links,
            "suppressed_link_pairs": suppressed_link_pairs}

def score_candidate(brand, channel, name, url, developer, description, logo_match, official_values):
    bn, cn = normalize(brand), normalize(name)
    score = 0
    reasons = []
    if bn and cn:
        if bn == cn:
            score += 45; reasons.append("Exact normalized brand name")
        elif bn in cn or cn in bn:
            score += 28; reasons.append("Brand name appears inside candidate name")
        else:
            # Similarity based on shared tokens / character overlap, conservative only.
            from difflib import SequenceMatcher
            ratio = SequenceMatcher(None, bn, cn).ratio()
            if ratio >= .72:
                score += 22; reasons.append("Look-alike name similarity")
    if logo_match:
        score += 25; reasons.append("Logo marked as visually similar")
    desc = (description or "").lower()
    suspicious_terms = ["verify account", "claim reward", "password", "payment", "support desk", "account recovery",
                        "official support", "wallet", "urgent", "login"]
    matched = [t for t in suspicious_terms if t in desc]
    if matched:
        score += min(20, 5 + 3 * len(matched)); reasons.append("Description contains risk terms: " + ", ".join(matched[:4]))
    if channel.lower() == "app store" and developer.strip():
        dev = normalize(developer)
        official_dev = any("developer:" + dev == normalize(x) for x in official_values)
        if not official_dev:
            score += 8; reasons.append("Developer not matched to a registered official identifier")
    candidate_url = normalize(url)
    if candidate_url and any(candidate_url == normalize(x) for x in official_values):
        score = 0; reasons = ["Exact official identifier matched — excluded by False-Positive Shield"]
    score = min(100, score)
    risk = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
    rationale = "; ".join(reasons) if reasons else "No strong similarity signal found; review manually if context suggests risk."
    return score, risk, rationale

def current_user():
    if not session.get("user_id"): return None
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        return dict(user) if user else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"): return jsonify({"error":"Authentication required"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def active_brand(c):
    user_id = session["user_id"]
    bid = session.get("brand_id")
    brand = c.execute("SELECT * FROM brands WHERE id=? AND user_id=?", (bid, user_id)).fetchone() if bid else None
    if not brand:
        brand = c.execute("SELECT * FROM brands WHERE user_id=? ORDER BY id LIMIT 1", (user_id,)).fetchone()
        if brand: session["brand_id"] = brand["id"]
    return brand

@app.context_processor
def inject_globals():
    user = current_user()
    return {"logged_in": user is not None, "active_page": request.endpoint or "",
            "profile_user": user, "demo_mode": not IS_PRODUCTION}

@app.route("/")
def home():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    return render_template("login.html", signup=False)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear(); session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html", signup=False)

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            try:
                with db() as c:
                    c.execute("INSERT INTO users(email,password_hash,created_at,full_name) VALUES(?,?,?,?)",
                              (email, generate_password_hash(password), now(),
                               email.split("@", 1)[0]))
                    uid = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
                    c.execute("INSERT INTO brands(user_id,name,industry,website,description,created_at) VALUES(?,?,?,?,?,?)",
                              (uid, "My Brand", "", "", "Add verified brand details to begin.", now()))
                    bid = c.execute("SELECT last_insert_rowid()").fetchone()[0]
                    c.execute("INSERT INTO settings(brand_id,key,value) VALUES(?,?,?)",(bid,"scan_mode","Manual + demo"))
                session.clear(); session["user_id"] = uid
                return redirect(url_for("brand_profile"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
    return render_template("login.html", signup=True)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            if not full_name:
                flash("Your name is required.", "error")
            elif len(full_name) > 100:
                flash("Your name must be 100 characters or fewer.", "error")
            else:
                c.execute("UPDATE users SET full_name=? WHERE id=?",
                          (full_name, user["id"]))
                flash("Profile updated.", "success")
                return redirect(url_for("profile"))
        user = dict(user)
    return render_template("profile.html", user=user)

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as c:
        brand = active_brand(c)
        if not brand: return redirect(url_for("brand_profile"))
        candidates = c.execute("""SELECT * FROM candidates WHERE brand_id=?
            AND status NOT IN ('False positive','Resolved')
            ORDER BY CASE risk WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC,
            confidence DESC, id DESC LIMIT 6""", (brand["id"],)).fetchall()
        scans = c.execute("SELECT * FROM scans WHERE brand_id=? ORDER BY id DESC LIMIT 6",(brand["id"],)).fetchall()
        totals = c.execute("""SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN risk IN ('High','Critical') AND status NOT IN ('False positive','Resolved') THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN channel='Social' THEN 1 ELSE 0 END), 0) AS social,
            COALESCE(SUM(CASE WHEN channel='App Store' THEN 1 ELSE 0 END), 0) AS apps,
            COALESCE(SUM(CASE WHEN status='Investigating' THEN 1 ELSE 0 END), 0) AS investigating
            FROM candidates WHERE brand_id=?""", (brand["id"],)).fetchone()
        risk_counts = {row["risk"]: row["count"] for row in c.execute(
            "SELECT risk, COUNT(*) AS count FROM candidates WHERE brand_id=? GROUP BY risk",
            (brand["id"],)).fetchall()}
        stats = {
            "total": totals["total"],
            "high": totals["high"],
            "social": totals["social"],
            "apps": totals["apps"],
            "investigating": totals["investigating"]
        }
    return render_template("dashboard.html", brand=brand, candidates=candidates, stats=stats,
                           risk_counts=risk_counts, scans=scans)

@app.route("/brand", methods=["GET","POST"])
@login_required
def brand_profile():
    with db() as c:
        brand = active_brand(c)
        if request.method == "POST":
            name = request.form.get("name","").strip()
            if not name:
                flash("Brand name is required.", "error")
            else:
                c.execute("UPDATE brands SET name=?,industry=?,website=?,description=? WHERE id=?",
                          (name,request.form.get("industry","").strip(),request.form.get("website","").strip(),
                           request.form.get("description","").strip(),brand["id"]))
                flash("Brand profile saved.", "success")
                return redirect(url_for("brand_profile"))
        brand = active_brand(c)
        assets = c.execute("SELECT * FROM assets WHERE brand_id=? ORDER BY id DESC",(brand["id"],)).fetchall()
    return render_template("brand.html", brand=brand, assets=assets)

@app.route("/assets/add", methods=["POST"])
@login_required
def add_asset():
    with db() as c:
        brand = active_brand(c)
        kind, value = request.form.get("kind","").strip(), request.form.get("value","").strip()
        if not kind or not value:
            flash("Asset type and value are required.", "error")
        else:
            try:
                c.execute("INSERT INTO assets(brand_id,kind,value,notes,created_at) VALUES(?,?,?,?,?)",
                          (brand["id"],kind,value,request.form.get("notes","").strip(),now()))
                flash("Official asset registered. Exact matches will be excluded from alerts.", "success")
            except sqlite3.IntegrityError:
                flash("That asset is already registered.", "error")
    return redirect(url_for("brand_profile"))

@app.route("/assets/<int:asset_id>/delete", methods=["POST"])
@login_required
def delete_asset(asset_id):
    with db() as c:
        brand = active_brand(c)
        c.execute("DELETE FROM assets WHERE id=? AND brand_id=?",(asset_id,brand["id"]))
    flash("Asset removed.", "success")
    return redirect(url_for("brand_profile"))

@app.route("/monitoring")
@login_required
def monitoring():
    channel = request.args.get("channel","all")
    risk = request.args.get("risk","all")
    status = request.args.get("status","all")
    q = request.args.get("q","").strip()
    page = max(1, request.args.get("page", 1, type=int))
    with db() as c:
        brand = active_brand(c)
        sql = "SELECT * FROM candidates WHERE brand_id=?"
        args = [brand["id"]]
        if channel != "all": sql += " AND channel=?"; args.append(channel)
        if risk != "all": sql += " AND risk=?"; args.append(risk)
        if status != "all": sql += " AND status=?"; args.append(status)
        if q:
            sql += " AND (name LIKE ? OR url LIKE ? OR developer LIKE ? OR description LIKE ?)"
            args.extend([f"%{q}%"]*4)
        total = c.execute("SELECT COUNT(*) FROM candidates WHERE " + sql.split(" WHERE ", 1)[1],args).fetchone()[0]
        page_count = max(1, (total + MONITORING_PAGE_SIZE - 1) // MONITORING_PAGE_SIZE)
        page = min(page, page_count)
        sql += " ORDER BY CASE risk WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, confidence DESC, id DESC LIMIT ? OFFSET ?"
        candidates = c.execute(sql,args + [MONITORING_PAGE_SIZE,(page - 1) * MONITORING_PAGE_SIZE]).fetchall()
    filters = {"channel": channel, "risk": risk, "status": status, "q": q}
    return render_template("monitoring.html", candidates=candidates, channel=channel, risk=risk,
                           status=status, q=q, page=page, page_count=page_count, total=total,
                           filters=filters)

@app.route("/candidates/add", methods=["POST"])
@login_required
def add_candidate():
    with db() as c:
        brand = active_brand(c)
        channel = request.form.get("channel","Social")
        if channel not in ("Social","App Store"): channel = "Social"
        name = request.form.get("name","").strip()
        url = request.form.get("url","").strip()
        dev = request.form.get("developer","").strip()
        desc = request.form.get("description","").strip()
        observed_raw = request.form.get("observed_at","").strip()
        observed_at = parse_observed_at(observed_raw)
        logo = 1 if request.form.get("logo_match") else 0
        assets = c.execute("SELECT value FROM assets WHERE brand_id=?",(brand["id"],)).fetchall()
        official = [a["value"] for a in assets]
        score, risk, rationale = score_candidate(brand["name"],channel,name,url,dev,desc,logo,official)
        if not name:
            flash("Candidate name is required.", "error")
        elif observed_raw and not observed_at:
            flash("Observation time must be ISO 8601 and include a timezone, such as 2026-10-14T08:00:00Z.", "error")
        elif any(normalize(url) == normalize(x) for x in official if url):
            flash("False-Positive Shield: this exact URL/identifier is registered as official and was not added.", "success")
        else:
            existing = c.execute("SELECT channel,name,url FROM candidates WHERE brand_id=?",
                                 (brand["id"],)).fetchall()
            fingerprint = candidate_fingerprint(channel, name, url)
            if any(candidate_fingerprint(row["channel"], row["name"], row["url"]) == fingerprint
                   for row in existing):
                flash("This candidate already exists in the workspace.", "error")
                return redirect(url_for("monitoring"))
            created_at = now()
            c.execute("""INSERT INTO candidates(brand_id,channel,name,url,developer,description,logo_match,status,source,
                      confidence,risk,rationale,first_seen,last_seen,created_at,observed_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (brand["id"],channel,name,url,dev,desc,logo,"New","Manual entry",score,risk,rationale,
                       created_at,created_at,created_at,observed_at or ""))
            flash(f"Candidate added with {risk.lower()} preliminary risk ({score}/100). Similarity is not proof of malicious activity.", "success")
    return redirect(url_for("monitoring",channel="all"))

@app.route("/candidates/<int:candidate_id>", methods=["GET","POST"])
@login_required
def candidate_detail(candidate_id):
    with db() as c:
        brand = active_brand(c)
        candidate = c.execute("SELECT * FROM candidates WHERE id=? AND brand_id=?",(candidate_id,brand["id"])).fetchone()
        if not candidate: return "Candidate not found", 404
        if request.method == "POST":
            action = request.form.get("action")
            if action == "status":
                new_status = request.form.get("status","New")
                if new_status not in ("New","Investigating","Escalated","Resolved","False positive"): new_status="New"
                c.execute("UPDATE candidates SET status=?,last_seen=? WHERE id=?",(new_status,now(),candidate_id))
                flash("Investigation status updated.", "success")
                return redirect(url_for("candidate_detail",candidate_id=candidate_id))
            elif action == "evidence":
                note = request.form.get("note","").strip()
                kind = request.form.get("kind","Analyst note").strip()
                if note:
                    c.execute("INSERT INTO evidence(candidate_id,kind,note,created_at) VALUES(?,?,?,?)",(candidate_id,kind,note,now()))
                    flash("Evidence note saved.", "success")
                return redirect(url_for("candidate_detail",candidate_id=candidate_id))
        evidence = c.execute("SELECT * FROM evidence WHERE candidate_id=? ORDER BY id DESC",(candidate_id,)).fetchall()
    return render_template("candidate.html", candidate=candidate, evidence=evidence)

@app.route("/candidates/<int:candidate_id>/delete", methods=["POST"])
@login_required
def delete_candidate(candidate_id):
    with db() as c:
        brand = active_brand(c)
        c.execute("DELETE FROM candidates WHERE id=? AND brand_id=?",(candidate_id,brand["id"]))
    flash("Candidate deleted.", "success")
    return redirect(url_for("monitoring"))

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    with db() as c:
        brand = active_brand(c)
        candidates = c.execute("SELECT * FROM candidates WHERE brand_id=?",(brand["id"],)).fetchall()
        assets = [r["value"] for r in c.execute("SELECT value FROM assets WHERE brand_id=?",(brand["id"],)).fetchall()]
        flagged = 0
        for cand in candidates:
            score, risk, rationale = score_candidate(brand["name"],cand["channel"],cand["name"],cand["url"],cand["developer"],cand["description"],cand["logo_match"],assets)
            if any(normalize(cand["url"]) == normalize(a) for a in assets if cand["url"]):
                continue
            c.execute("UPDATE candidates SET confidence=?,risk=?,rationale=?,last_seen=? WHERE id=?",
                      (score,risk,rationale,now(),cand["id"]))
            if risk in ("High","Critical") and cand["status"] not in ("False positive","Resolved"): flagged += 1
        c.execute("INSERT INTO scans(brand_id,label,scanned_count,flagged_count,source_mode,created_at) VALUES(?,?,?,?,?,?)",
                  (brand["id"],"Manual re-score",len(candidates),flagged,"Local heuristic engine; no external crawl",now()))
    flash(f"Re-score complete: reviewed {len(candidates)} saved candidates and flagged {flagged} high/critical items. No live platform crawl was performed.", "success")
    return redirect(url_for("dashboard"))

@app.route("/import", methods=["GET","POST"])
@login_required
def import_candidates():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename.lower().endswith(".csv"):
            flash("Upload a .csv file.", "error"); return redirect(url_for("import_candidates"))
        try:
            raw_content = f.stream.read(MAX_IMPORT_BYTES + 1)
            if len(raw_content) > MAX_IMPORT_BYTES:
                flash("CSV exceeds the 5 MB upload limit.", "error")
                return redirect(url_for("import_candidates"))
            content = raw_content.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(content, newline=""))
            required = {"channel","name"}
            if not reader.fieldnames or not required.issubset({x.strip().lower() for x in reader.fieldnames}):
                flash("CSV must include channel and name columns. Optional: url, developer, description, logo_match, observed_at.", "error")
                return redirect(url_for("import_candidates"))
            with db() as c:
                brand = active_brand(c)
                assets = [r["value"] for r in c.execute("SELECT value FROM assets WHERE brand_id=?",(brand["id"],)).fetchall()]
                existing = c.execute("SELECT channel,name,url FROM candidates WHERE brand_id=?",
                                     (brand["id"],)).fetchall()
                seen = {candidate_fingerprint(row["channel"], row["name"], row["url"]) for row in existing}
                imported = skipped_official = skipped_duplicate = skipped_invalid = 0
                row_number = 1
                for row_number, raw in enumerate(reader, start=2):
                    if row_number > MAX_IMPORT_ROWS + 1:
                        flash(f"Import stopped at the {MAX_IMPORT_ROWS:,}-row limit. {imported} records were imported.", "error")
                        break
                    if None in raw:
                        skipped_invalid += 1
                        continue
                    row = {k.strip().lower(): (v or "").strip() for k,v in raw.items() if k}
                    channel_value = row.get("channel","").lower()
                    if channel_value not in ("social", "app store", "app", "store"):
                        skipped_invalid += 1
                        continue
                    channel = "App Store" if channel_value in ("app store","app","store") else "Social"
                    name, url, dev, desc = row.get("name",""),row.get("url",""),row.get("developer",""),row.get("description","")
                    if not name:
                        skipped_invalid += 1
                        continue
                    observed_raw = row.get("observed_at", "")
                    observed_at = parse_observed_at(observed_raw)
                    if observed_raw and not observed_at:
                        skipped_invalid += 1
                        continue
                    if url and any(normalize(url)==normalize(a) for a in assets):
                        skipped_official += 1
                        continue
                    fingerprint = candidate_fingerprint(channel, name, url)
                    if fingerprint in seen:
                        skipped_duplicate += 1
                        continue
                    logo = 1 if row.get("logo_match","").lower() in ("1","true","yes","y") else 0
                    score,risk,rationale = score_candidate(brand["name"],channel,name,url,dev,desc,logo,assets)
                    created_at = now()
                    c.execute("""INSERT INTO candidates(brand_id,channel,name,url,developer,description,logo_match,status,source,
                              confidence,risk,rationale,first_seen,last_seen,created_at,observed_at)
                              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                              (brand["id"],channel,name,url,dev,desc,logo,"New","CSV import",score,risk,rationale,
                               created_at,created_at,created_at,observed_at or ""))
                    seen.add(fingerprint)
                    imported += 1
            if row_number > MAX_IMPORT_ROWS + 1:
                return redirect(url_for("monitoring"))
            flash(f"Import complete: {imported} added, {skipped_duplicate} duplicates, "
                  f"{skipped_official} official matches, {skipped_invalid} invalid rows skipped.", "success")
            return redirect(url_for("monitoring"))
        except (UnicodeDecodeError, csv.Error, ValueError):
            flash("Could not parse CSV. Check UTF-8 encoding, row formatting and column names.", "error")
    return render_template("import.html")

@app.route("/campaigns")
@login_required
def campaigns():
    with db() as c:
        brand = active_brand(c)
        rows = c.execute("SELECT * FROM candidates WHERE brand_id=? AND status NOT IN ('False positive','Resolved') ORDER BY id DESC",(brand["id"],)).fetchall()
    # Lightweight explainable grouping; it does not claim shared actor attribution.
    groups = {}
    for r in rows:
        tokens = set(re.findall(r"[a-z0-9]{4,}", (r["name"]+" "+r["description"]).lower()))
        tokens.discard(normalize(brand["name"]))
        key = sorted(tokens)[0] if tokens else "needs-review"
        groups.setdefault(key, []).append(r)
    groups = [(k,v) for k,v in groups.items() if len(v) >= 2]
    return render_template("campaigns.html", groups=groups, rows=rows)

@app.route("/network")
@login_required
def scam_network():
    return render_template("network.html")

@app.route("/api/network")
@login_required
def network_data():
    with db() as c:
        brand = active_brand(c)
        graph = build_network_graph(c, brand["id"])
        suppressed = c.execute("""SELECT COUNT(*) FROM (
            SELECT i.id FROM network_indicators i JOIN network_observations o ON o.indicator_id=i.id
            JOIN network_entities e ON e.id=o.entity_id
            JOIN candidates ca ON ca.id=e.candidate_id
            WHERE i.brand_id=? AND ca.status!='False positive'
            GROUP BY i.id HAVING COUNT(DISTINCT e.candidate_id)>?)""",
            (brand["id"], MAX_LINKED_ENTITIES_PER_INDICATOR)).fetchone()[0]
    graph["suppressed_common_indicators"] = suppressed
    graph["max_entities_per_indicator"] = MAX_LINKED_ENTITIES_PER_INDICATOR
    return jsonify(graph)

@app.route("/network/export.csv")
@login_required
def export_network_csv():
    with db() as c:
        brand = active_brand(c)
        graph = build_network_graph(c, brand["id"])
    nodes = {node["id"]: node for node in graph["nodes"]}
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["case_a", "risk_a", "case_b", "risk_b", "link_strength",
                     "shared_evidence_type", "shared_identifier", "observed_source_fields",
                     "observed_timestamps_utc", "timestamp_basis", "source_provenance_weight",
                     "review_guidance"])
    for edge in graph["links"]:
        first, second = nodes[edge["source"]], nodes[edge["target"]]
        for evidence in edge["evidence"]:
            writer.writerow([
                first["label"], first["risk"], second["label"], second["risk"],
                evidence["strength"], evidence["type"], evidence["value"],
                " / ".join(evidence["source_fields"]),
                " / ".join(evidence["observed_at"]), " / ".join(evidence["time_basis"]),
                evidence["source_quality"],
                "Validate ownership and context; shared infrastructure is not proof of coordination.",
            ])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sentinel-network-investigation.csv"})

@app.route("/evidence")
@login_required
def evidence_vault():
    with db() as c:
        brand = active_brand(c)
        rows = c.execute("""SELECT e.*, ca.name AS candidate_name, ca.id AS candidate_id, ca.channel AS channel
                            FROM evidence e JOIN candidates ca ON ca.id=e.candidate_id
                            WHERE ca.brand_id=? ORDER BY e.id DESC""",(brand["id"],)).fetchall()
    return render_template("evidence.html", rows=rows)

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    with db() as c:
        brand = active_brand(c)
        if request.method == "POST":
            for key in ("social_sources","app_sources","notifications","scan_mode"):
                c.execute("INSERT INTO settings(brand_id,key,value) VALUES(?,?,?) ON CONFLICT(brand_id,key) DO UPDATE SET value=excluded.value",
                          (brand["id"],key,request.form.get(key,"").strip()))
            flash("Settings saved.", "success")
            return redirect(url_for("settings"))
        values = {r["key"]:r["value"] for r in c.execute("SELECT key,value FROM settings WHERE brand_id=?",(brand["id"],)).fetchall()}
    return render_template("settings.html", brand=brand, values=values)

@app.route("/export.csv")
@login_required
def export_csv():
    with db() as c:
        brand = active_brand(c)
        rows = c.execute("SELECT channel,name,url,developer,description,status,confidence,risk,rationale,source,first_seen,last_seen,observed_at FROM candidates WHERE brand_id=? ORDER BY id DESC",(brand["id"],)).fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["channel","name","url","developer","description","status","confidence","risk","rationale","source","first_seen","last_seen","observed_at"])
    writer.writerows([tuple(r) for r in rows])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=sentinel-candidates.csv"})

@app.route("/api/health")
def health():
    return jsonify({"status":"ok","application":"BrandShield Sentinel","mode":"local-demo/heuristic","external_connectors":"not configured"})

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", message="Something went wrong. Check the terminal for the local error log."), 500

init_db()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST","127.0.0.1"),
            port=int(os.environ.get("PORT","5000")),
            debug=not IS_PRODUCTION and os.environ.get("FLASK_DEBUG","0")=="1")
