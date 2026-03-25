"""
NACSystem - FastAPI Policy Engine
=================================
This API is the "brain" of our NAC system. FreeRADIUS calls these
endpoints via the rlm_rest module to make Authentication, Authorization,
and Accounting decisions.

Endpoints:
  POST /auth             → Authentication  (check username + password)
  POST /authorize        → Authorization   (fetch group + VLAN policy)
  POST /accounting       → Accounting      (log session start/stop)
  GET  /users            → List all users and their groups
  GET  /sessions/active  → Show currently active network sessions
  GET  /dashboard        → Live HTML monitoring dashboard
  GET  /health           → Docker health check
"""

import os
import json
import hashlib
from datetime import timezone, datetime
from urllib.parse import parse_qsl

import psycopg2
import psycopg2.extras
import redis
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

# ── Create the FastAPI app ───────────────────────────────────
app = FastAPI(
    title="NACSystem Policy Engine",
    version="0.2.0",
    description="Network Access Control policy engine using AAA architecture",
)

# ── Jinja2 template engine for the HTML dashboard ────────────
# WHY Jinja2: It lets us write HTML with {{ variables }} and {% loops %}
# so we can render dynamic data (sessions, users) into a web page.
templates = Jinja2Templates(directory="templates")


# ════════════════════════════════════════════════════════════
# DATABASE & REDIS CONNECTIONS
# ════════════════════════════════════════════════════════════

def get_db():
    """
    Open a fresh connection to PostgreSQL.
    WHY a new connection each time: This is the simplest approach.
    In production you'd use a connection pool, but for our internship
    project this is easier to understand and debug.
    """
    return psycopg2.connect(os.environ["DATABASE_URL"])


def get_redis():
    """
    Create a Redis client from the REDIS_URL environment variable.
    decode_responses=True makes Redis return strings instead of bytes.
    """
    return redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


# ════════════════════════════════════════════════════════════
# HELPER: Password hashing with SHA-256
# ════════════════════════════════════════════════════════════

def sha256_hash(password: str) -> str:
    """
    Generate a SHA-256 hash of the password.
    WHY SHA-256 instead of NT-Password (MD4):
      - MD4 is deprecated and blocked in Python 3.13 / OpenSSL 3.x
      - SHA-256 is secure, widely supported, and easy to explain
    Since OUR API handles authentication (not FreeRADIUS directly),
    we can use any hash algorithm we want.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# ════════════════════════════════════════════════════════════
# ENDPOINT 1: POST /auth  (AUTHENTICATION)
# ════════════════════════════════════════════════════════════

def normalize_mac(mac: str) -> str:
    """
    Convert any MAC address format to lowercase colon-separated.
    WHY: Different switches/APs send MACs in different formats:

      - Cisco:  aabb.ccdd.eeff
      - Windows: AA-BB-CC-DD-EE-FF
      - Linux:   aa:bb:cc:dd:ee:ff
      - Some:    AABBCCDDEEFF
      
    We normalize to "aa:bb:cc:dd:ee:ff" so we can match against
    the single format stored in our database.
    """
    # Remove all separators (colons, dashes, dots) and lowercase
    clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    # If it's exactly 12 hex characters, it's a MAC address
    if len(clean) == 12 and all(c in "0123456789abcdef" for c in clean):
        # Re-insert colons every 2 characters: "aabbccddeeff" → "aa:bb:cc:dd:ee:ff"
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    # Not a MAC address — return as-is
    return mac


@app.post("/auth")
async def authenticate(request: Request):
    """
    Check if the user's credentials are valid.

    Supports two authentication methods:
      1. Normal user auth: username + SHA-256 hashed password
      2. MAB (MAC Authentication Bypass): for devices like printers
         that can't type a password. The switch sends the device's
         MAC address as BOTH the username AND the password.

    IMPORTANT — rlm_rest uses HTTP status codes, NOT JSON body:
      - HTTP 204 = Access-Accept  (authentication passed)
      - HTTP 401 = Access-Reject  (wrong password)
      - HTTP 404 = User not found

    Flow:
      1. Read username + password from the request
      2. Check if this looks like a MAB request (username is a MAC)
      3. If MAB: normalize the MAC and look it up in radcheck
      4. If normal: compare the password hash against radcheck
      5. Return the correct HTTP status code
    """
    # FreeRADIUS rlm_rest sends data as form-encoded body
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    # Step 1: Check if this is a MAB request
    # WHY: In MAB, the switch sends the MAC as the username.
    # We normalize it so "AA-BB-CC-DD-EE-FF" matches "aa:bb:cc:dd:ee:ff" in our DB.
    normalized = normalize_mac(username)
    is_mab = normalized != username or normalized == password.lower().replace("-", ":").replace(".", ":")

    # Use the normalized MAC as the lookup key for MAB requests
    lookup_name = normalized if is_mab else username

    conn = get_db()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Look up all check attributes for this username (or MAC)
        cursor.execute(
            "SELECT attribute, value FROM radcheck WHERE username = %s",
            (lookup_name,)
        )
        rows = cursor.fetchall()

        # If no rows found, this user/device doesn't exist
        if not rows:
            return Response(status_code=404)

        # Check each stored attribute against the submitted password
        for row in rows:
            attribute = row["attribute"]
            stored_value = row["value"]

            if attribute == "SHA-256-Password":
                # Normal user: hash the submitted password and compare
                if sha256_hash(password) == stored_value.lower():
                    return Response(status_code=204)

            elif attribute == "Cleartext-Password":
                # MAB device: the "password" is just the MAC address again
                # Normalize both sides so format differences don't matter
                if normalize_mac(password) == normalize_mac(stored_value):
                    return Response(status_code=204)

        # If we get here, no attribute matched — reject
        return Response(status_code=401)

    finally:
        conn.close()


# ════════════════════════════════════════════════════════════
# ENDPOINT 2: POST /authorize  (AUTHORIZATION)
# ════════════════════════════════════════════════════════════

@app.post("/authorize")
async def authorize(request: Request):
    """
    FreeRADIUS calls this endpoint TWICE per authentication request:

    1. During AUTHORIZE phase (force_to='plain'):
       → Just checks if user exists (HTTP 200 = yes, 404 = no)
       → The JSON body is IGNORED in this phase

    2. During POST-AUTH phase (force_to='json'):
       → After successful authentication, rlm_rest parses the JSON body
       → In post-auth, parsed attributes go directly into the REPLY list
       → This is how VLAN attributes reach the Access-Accept packet

    WHY two calls to the same endpoint:
       In FreeRADIUS 3.2, rlm_rest in the authorize section puts parsed
       JSON attributes into the control/request list — NOT the reply list.
       No JSON format (nested, flat, prefixed) fixes this. But in the
       post-auth section, rlm_rest puts parsed attributes into the REPLY
       list, which IS sent to the switch. So we call the same endpoint
       from both phases: authorize ignores the body, post-auth parses it.
    """
    # Parse the raw body ourselves instead of using request.form().
    # WHY: rlm_rest may send different Content-Type headers depending
    # on the force_to setting. parse_qsl works regardless of Content-Type.
    body = (await request.body()).decode()
    params = dict(parse_qsl(body))
    username = params.get("username", "")

    # Normalize MAC addresses so MAB lookups work regardless of format
    normalized = normalize_mac(username)
    lookup_name = normalized if normalized != username else username

    conn = get_db()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Step 1: Check if user exists in radcheck
        cursor.execute(
            "SELECT attribute, value FROM radcheck WHERE username = %s",
            (lookup_name,)
        )
        if not cursor.fetchone():
            return Response(status_code=404)

        # Step 2: Find the user's group
        cursor.execute(
            "SELECT groupname FROM radusergroup WHERE username = %s ORDER BY priority LIMIT 1",
            (lookup_name,)
        )
        group_row = cursor.fetchone()

        # Step 3: Get ALL VLAN attributes for this group
        # Return them as flat JSON: {"Tunnel-Type": "13", ...}
        # When called from post-auth, rlm_rest parses these directly
        # into the RADIUS reply list → they appear in Access-Accept
        attrs = {}
        if group_row:
            cursor.execute(
                "SELECT attribute, value FROM radgroupreply WHERE groupname = %s",
                (group_row["groupname"],)
            )
            for row in cursor.fetchall():
                attrs[row["attribute"]] = row["value"]

        return JSONResponse(content=attrs)

    finally:
        conn.close()


# ════════════════════════════════════════════════════════════
# ENDPOINT 3: POST /accounting  (ACCOUNTING)
# ════════════════════════════════════════════════════════════

@app.post("/accounting")
async def accounting(request: Request):
    """
    FreeRADIUS sends accounting packets when a user's session
    starts, updates, or stops. We log these to PostgreSQL (radacct)
    and track active sessions in Redis for fast lookups.

    Acct-Status-Type tells us what kind of event this is:
      - "Start"   → user just connected
      - "Interim-Update" → periodic update (still connected)
      - "Stop"    → user disconnected

    IMPORTANT — We return HTTP 204 (No Content) on success.
    WHY: rlm_rest maps 204 → "ok" without trying to parse the body.
    If we returned 200 with JSON, rlm_rest would try to parse our
    JSON keys as RADIUS attributes, fail, and silently drop the
    entire accounting call.
    """
    form = await request.form()

    # Extract the fields FreeRADIUS sends us
    # WHY safe_int helper: Some fields may arrive as empty strings
    # when the NAS doesn't include them. int("") would crash the
    # entire endpoint, so we default missing numbers to 0.
    def safe_int(value):
        """Convert a string to int, defaulting to 0 if empty or invalid."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0

    status_type = form.get("Acct-Status-Type", "")
    username = form.get("username", "")
    session_id = form.get("Acct-Session-Id", "unknown")
    unique_id = form.get("Acct-Unique-Session-Id", "") or session_id
    nas_ip = form.get("NAS-IP-Address", "")
    nas_port = form.get("NAS-Port-Id", "")
    framed_ip = form.get("Framed-IP-Address", "")
    calling_station = form.get("Calling-Station-Id", "")
    session_time = safe_int(form.get("Acct-Session-Time", "0"))
    input_octets = safe_int(form.get("Acct-Input-Octets", "0"))
    output_octets = safe_int(form.get("Acct-Output-Octets", "0"))

    now = datetime.now(timezone.utc)

    # Wrap everything in try/except so we ALWAYS return 204 to FreeRADIUS.
    # WHY: If we return 500 (crash), FreeRADIUS treats it as "fail" and
    # keeps retrying, which floods the logs. Better to log the error
    # on our side and let RADIUS move on.
    try:
        conn = get_db()
        r = get_redis()
        cursor = conn.cursor()

        if status_type == "Start":
            # ── Session Start ────────────────────────────────
            # Insert a new row into radacct
            cursor.execute("""
                INSERT INTO radacct
                    (acctsessionid, acctuniqueid, username, nasipaddress,
                     nasportid, acctstarttime, framedipaddress, callingstationid)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (acctuniqueid) DO NOTHING
            """, (session_id, unique_id, username, nas_ip,
                  nas_port, now, framed_ip, calling_station))
            conn.commit()

            # Cache this session in Redis so /sessions/active is fast
            # WHY Redis: querying "WHERE acctstoptime IS NULL" works but
            # Redis gives us instant lookups without hitting the database
            session_data = {
                "username": username,
                "session_id": session_id,
                "nas_ip": nas_ip,
                "framed_ip": framed_ip,
                "mac": calling_station,
                "start_time": now.isoformat(),
            }
            # Use session_id as Redis key (consistent across Start/Stop)
            r.set(f"session:{session_id}", json.dumps(session_data))

        elif status_type == "Interim-Update":
            # ── Periodic Update ──────────────────────────────
            # WHY match on acctsessionid: The acctuniqueid is a hash
            # generated by FreeRADIUS that includes ALL packet fields.
            # Start and Interim packets have different fields, so the
            # hash differs. acctsessionid is the stable session ID that
            # stays the same for the entire session lifecycle.
            cursor.execute("""
                UPDATE radacct
                SET acctupdatetime = %s,
                    acctsessiontime = %s,
                    acctinputoctets = %s,
                    acctoutputoctets = %s
                WHERE acctsessionid = %s
            """, (now, session_time, input_octets, output_octets, session_id))
            conn.commit()

        elif status_type == "Stop":
            # ── Session End ──────────────────────────────────
            terminate_cause = form.get("Acct-Terminate-Cause", "Unknown")

            # WHY match on acctsessionid: Same reason as Interim-Update.
            # The Stop packet has extra fields (Acct-Terminate-Cause,
            # Acct-Session-Time) that change the acctuniqueid hash,
            # so it would never match the Start row.
            cursor.execute("""
                UPDATE radacct
                SET acctstoptime = %s,
                    acctsessiontime = %s,
                    acctinputoctets = %s,
                    acctoutputoctets = %s,
                    acctterminatecause = %s
                WHERE acctsessionid = %s
            """, (now, session_time, input_octets,
                  output_octets, terminate_cause, session_id))
            conn.commit()

            # Remove from Redis since the session is no longer active
            r.delete(f"session:{session_id}")

        conn.close()

    except Exception as e:
        # Log the error but don't crash — return 204 so FreeRADIUS is happy
        print(f"ACCOUNTING ERROR: {e}")

    # 204 No Content = rlm_rest treats this as "ok" without parsing body
    return Response(status_code=204)


# ════════════════════════════════════════════════════════════
# ENDPOINT 4: GET /users  (USER LIST)
# ════════════════════════════════════════════════════════════

@app.get("/users")
def list_users():
    """
    Return a list of all known users with their group assignments.
    Useful for the admin dashboard and debugging.

    We JOIN radcheck with radusergroup to show each user's group.
    """
    conn = get_db()
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # LEFT JOIN so we also see users who have no group yet
        cursor.execute("""
            SELECT DISTINCT
                rc.username,
                rc.attribute AS auth_type,
                rug.groupname
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            ORDER BY rc.username
        """)
        rows = cursor.fetchall()

        users = []
        for row in rows:
            users.append({
                "username": row["username"],
                "auth_type": row["auth_type"],
                "group": row["groupname"],
            })

        return {"users": users, "total": len(users)}

    finally:
        conn.close()


# ════════════════════════════════════════════════════════════
# ENDPOINT 5: GET /sessions/active  (ACTIVE SESSIONS)
# ════════════════════════════════════════════════════════════

@app.get("/sessions/active")
def active_sessions():
    """
    Return all currently active network sessions from Redis.

    WHY Redis instead of PostgreSQL:
      - Active sessions are cached in Redis during accounting "Start"
      - Redis is an in-memory store, so lookups are nearly instant
      - When a session ends ("Stop"), we delete it from Redis
      - This gives us a real-time view of who is on the network RIGHT NOW
    """
    r = get_redis()

    # Find all keys matching the pattern "session:*"
    session_keys = r.keys("session:*")

    sessions = []
    for key in session_keys:
        data = r.get(key)
        if data:
            sessions.append(json.loads(data))

    return {"active_sessions": sessions, "total": len(sessions)}


# ════════════════════════════════════════════════════════════
# ENDPOINT 6: GET /dashboard  (MONITORING DASHBOARD)
# ════════════════════════════════════════════════════════════

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    """
    Render a live HTML dashboard showing:
      - Summary cards (active sessions, total users, accounting records)
      - Active sessions table (from Redis)
      - Registered users table (from PostgreSQL)
      - Recent accounting logs (from PostgreSQL)

    WHY HTML instead of JSON: This is a human-readable monitoring page
    that can be opened in any browser — no frontend framework needed.
    """
    r = get_redis()
    conn = get_db()

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # ── Active Sessions from Redis ───────────────────────
        session_keys = r.keys("session:*")
        sessions = []
        for key in session_keys:
            data = r.get(key)
            if data:
                sessions.append(json.loads(data))

        # ── Registered Users from PostgreSQL ─────────────────
        # Join radcheck + radusergroup + radgroupreply to get
        # each user's group and VLAN in one query
        cursor.execute("""
            SELECT DISTINCT
                rc.username,
                rc.attribute AS auth_type,
                rug.groupname,
                rgr.value AS vlan
            FROM radcheck rc
            LEFT JOIN radusergroup rug ON rc.username = rug.username
            LEFT JOIN radgroupreply rgr
                ON rug.groupname = rgr.groupname
                AND rgr.attribute = 'Tunnel-Private-Group-Id'
            ORDER BY rc.username
        """)
        users = []
        for row in cursor.fetchall():
            users.append({
                "username": row["username"],
                "auth_type": row["auth_type"],
                "group": row["groupname"],
                "vlan": row["vlan"],
            })

        # ── Accounting Logs from PostgreSQL ───────────────────
        # Show the 20 most recent sessions
        cursor.execute("""
            SELECT username, acctsessionid, acctstarttime,
                   acctstoptime, acctsessiontime, acctterminatecause
            FROM radacct
            ORDER BY acctstarttime DESC
            LIMIT 20
        """)
        acct_logs = []
        for row in cursor.fetchall():
            acct_logs.append({
                "username": row["username"],
                "session_id": row["acctsessionid"],
                "start_time": str(row["acctstarttime"]) if row["acctstarttime"] else None,
                "stop_time": str(row["acctstoptime"]) if row["acctstoptime"] else None,
                "session_time": row["acctsessiontime"],
                "terminate_cause": row["acctterminatecause"],
            })

        # ── Count totals for the summary cards ────────────────
        cursor.execute("SELECT COUNT(DISTINCT username) FROM radcheck")
        total_users = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM radacct")
        total_acct = cursor.fetchone()[0]

        # Render the HTML template with all the data
        # WHY keyword arguments: newer Starlette versions require
        # explicit "name", "request", and "context" kwargs.
        return templates.TemplateResponse(
            name="dashboard.html",
            request=request,
            context={
                "sessions": sessions,
                "active_count": len(sessions),
                "users": users,
                "total_users": total_users,
                "acct_logs": acct_logs,
                "total_acct": total_acct,
            },
        )

    finally:
        conn.close()


# ════════════════════════════════════════════════════════════
# HEALTH CHECK
# ════════════════════════════════════════════════════════════

@app.get("/health")
def health_check():
    """
    Docker uses this to know if the container is alive.
    Also verifies that PostgreSQL and Redis connections work.
    """
    status = {"api": "healthy"}

    # Check PostgreSQL
    try:
        conn = get_db()
        conn.close()
        status["postgres"] = "connected"
    except Exception:
        status["postgres"] = "disconnected"

    # Check Redis
    try:
        r = get_redis()
        r.ping()
        status["redis"] = "connected"
    except Exception:
        status["redis"] = "disconnected"

    return status
