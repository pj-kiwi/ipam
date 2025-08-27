#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IPAM Web App: Self-contained Python installer

This script creates a Flask-based IP Address Management (IPAM) web app
with basic authentication and an SQLite backend. It can:
- Generate the full project structure with all files
- Optionally create a virtual environment
- Install dependencies
- Optionally run the app

Usage examples:
  python install_ipam_web.py
  python install_ipam_web.py --venv --install
  python install_ipam_web.py --venv --install --run --host 0.0.0.0 --port 5000
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path
import textwrap
import shutil
import platform

# ----------------- Project Contents -----------------

REQUIREMENTS_TXT = """\
Flask>=3.0
Werkzeug>=3.0
"""

APP_PY = r"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import io
import csv
import sqlite3
import secrets
import ipaddress
from datetime import datetime
from functools import wraps
from flask import (
    Flask, g, render_template, request, redirect, url_for,
    flash, session, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("IPAM_DB_PATH", "ipam.db")
MAX_PREPOP_HOSTS = 4096  # from desktop version
DEFAULT_ADMIN_USER = os.environ.get("IPAM_ADMIN_USER", "admin")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

app = Flask(__name__, static_url_path="/static", static_folder="static")
app.config["SECRET_KEY"] = SECRET_KEY

# ----------------- DB & Helpers -----------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ipv4_to_int(ip_str: str) -> int:
    return int(ipaddress.IPv4Address(ip_str))

def init_db():
    con = get_db()
    cur = con.cursor()
    # Subnets
    cur.execute("""
    CREATE TABLE IF NOT EXISTS subnets(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        cidr TEXT NOT NULL UNIQUE,
        site TEXT,
        vlan TEXT,
        description TEXT
    );
    """)
    # IP addresses
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_addresses(
        id INTEGER PRIMARY KEY,
        subnet_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        ip_int INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('Free','Allocated','Reserved')),
        hostname TEXT,
        owner TEXT,
        mac TEXT,
        note TEXT,
        updated_at TEXT,
        UNIQUE(subnet_id, ip),
        FOREIGN KEY(subnet_id) REFERENCES subnets(id) ON DELETE CASCADE
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_subnet_int ON ip_addresses(subnet_id, ip_int);")
    # History
    cur.execute("""
    CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY,
        ip_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        who TEXT,
        note TEXT,
        at TEXT NOT NULL,
        FOREIGN KEY(ip_id) REFERENCES ip_addresses(id) ON DELETE CASCADE
    );
    """)
    # Users (new)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        created_at TEXT NOT NULL
    );
    """)
    con.commit()

def ensure_default_admin():
    """Create a default admin if no users exist; print temp password to console."""
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM users;")
    if cur.fetchone()["c"] == 0:
        temp_pw = secrets.token_urlsafe(12)
        cur.execute("""
            INSERT INTO users(username, password_hash, role, created_at)
            VALUES (?, ?, 'admin', ?)
        """, (DEFAULT_ADMIN_USER, generate_password_hash(temp_pw), now_ts()))
        con.commit()
        print("="*72)
        print(" First-time setup: default admin created")
        print(f" Username: {DEFAULT_ADMIN_USER}")
        print(f" Password: {temp_pw}")
        print(" Please login and change this password under Profile.")
        print("="*72)

# --------------- Auth & CSRF -----------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def current_username():
    return session.get("username", "admin")

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(16)
        session["_csrf"] = token
    return token

def require_csrf():
    token_form = request.form.get("_csrf")
    token_sess = session.get("_csrf")
    if not token_form or not token_sess or token_form != token_sess:
        abort(400, description="Invalid CSRF token")

app.jinja_env.globals["csrf_token"] = csrf_token
# --------------- Data Access (CRUD) -----------------

def create_subnet(name, cidr, site="", vlan="", description=""):
    try:
        net = ipaddress.ip_network(cidr, strict=True)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 supported in this version.")
    except Exception as e:
        raise ValueError(f"Invalid CIDR: {e}")

    usable_hosts = max(net.num_addresses - 2, 0) if net.prefixlen <= 30 else (1 if net.prefixlen == 32 else 0)

    con = get_db()
    cur = con.cursor()
    cur.execute("INSERT INTO subnets(name, cidr, site, vlan, description) VALUES (?,?,?,?,?)",
                (name, cidr, site, vlan, description))
    subnet_id = cur.lastrowid

    # Pre-populate small subnets
    if usable_hosts <= MAX_PREPOP_HOSTS and usable_hosts > 0:
        hosts = list(net.hosts())
        rows = []
        ts = now_ts()
        for host in hosts:
            rows.append((subnet_id, str(host), int(host), 'Free', None, None, None, None, ts))
        cur.executemany("""
            INSERT INTO ip_addresses(subnet_id, ip, ip_int, status, hostname, owner, mac, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    elif usable_hosts == 0:
        hosts = list(net.hosts())
        ts = now_ts()
        for host in hosts:
            cur.execute("""
                INSERT INTO ip_addresses(subnet_id, ip, ip_int, status, hostname, owner, mac, note, updated_at)
                VALUES (?, ?, ?, 'Free', NULL, NULL, NULL, NULL, ?)
            """, (subnet_id, str(host), int(host), ts))
    con.commit()
    return subnet_id

def list_subnets():
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, name, cidr, site, vlan, description FROM subnets ORDER BY cidr")
    results = []
    for s in cur.fetchall():
        cur.execute("SELECT COUNT(*) AS c FROM ip_addresses WHERE subnet_id=?", (s["id"],))
        total = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) AS u FROM ip_addresses WHERE subnet_id=? AND status IN ('Allocated','Reserved')", (s["id"],))
        used = cur.fetchone()["u"]
        util = int((used / total * 100)) if total else 0
        results.append({**dict(s), "used": used, "total": total, "util": util})
    return results

def get_subnet(subnet_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT * FROM subnets WHERE id=?", (subnet_id,))
    return cur.fetchone()

def delete_subnet(subnet_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("DELETE FROM subnets WHERE id=?", (subnet_id,))
    con.commit()

def list_ips(subnet_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, ip, status, hostname, owner, mac, note, updated_at
        FROM ip_addresses
        WHERE subnet_id=?
        ORDER BY ip_int
    """, (subnet_id,))
    return cur.fetchall()

def get_ip_row(ip_row_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT * FROM ip_addresses WHERE id=?", (ip_row_id,))
    return cur.fetchone()

def next_free_ip(subnet_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, ip FROM ip_addresses
        WHERE subnet_id=? AND status='Free'
        ORDER BY ip_int ASC LIMIT 1
    """, (subnet_id,))
    return cur.fetchone()

def set_ip_status(ip_row_id, status, who="admin", note=None, hostname=None, owner=None, mac=None):
    ts = now_ts()
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        UPDATE ip_addresses
           SET status=?,
               hostname=COALESCE(?, hostname),
               owner=COALESCE(?, owner),
               mac=COALESCE(?, mac),
               note=COALESCE(?, note),
               updated_at=?
         WHERE id=?
    """, (status, hostname, owner, mac, note, ts, ip_row_id))
    cur.execute("INSERT INTO history(ip_id, action, who, note, at) VALUES (?,?,?,?,?)",
                (ip_row_id, status, who, note, ts))
    con.commit()

def release_ip(ip_row_id, who="admin", note=None):
    ts = now_ts()
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        UPDATE ip_addresses
           SET status='Free',
               hostname=NULL,
               owner=NULL,
               mac=NULL,
               note=NULL,
               updated_at=?
         WHERE id=?
    """, (ts, ip_row_id))
    cur.execute("INSERT INTO history(ip_id, action, who, note, at) VALUES (?,?,?,?,?)",
                (ip_row_id, "Released", who, note, ts))
    con.commit()

def find_ip_by_text(text):
    tx = f"%{text.strip()}%"
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT s.name AS subnet_name, s.cidr, i.*
          FROM ip_addresses i
          JOIN subnets s ON s.id=i.subnet_id
         WHERE i.ip LIKE ? OR IFNULL(i.hostname,'') LIKE ?
         ORDER BY i.ip_int
    """, (tx, tx))
    return cur.fetchall()

def export_subnet_to_csv(subnet_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT ip, status, hostname, owner, mac, note, updated_at
          FROM ip_addresses
         WHERE subnet_id=?
         ORDER BY ip_int
    """, (subnet_id,))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "status", "hostname", "owner", "mac", "note", "updated_at"])
    for r in cur.fetchall():
        writer.writerow([
            r["ip"], r["status"], r["hostname"] or "", r["owner"] or "",
            r["mac"] or "", r["note"] or "", r["updated_at"] or ""
        ])
    output.seek(0)
    return output

def import_csv_to_subnet(subnet_id, file_storage):
    """
    file_storage: Werkzeug FileStorage (from request.files['file'])
    CSV headers: ip,status,hostname,owner,mac,note
    """
    ts = now_ts()
    con = get_db()
    cur = con.cursor()
    count = 0

    stream = io.TextIOWrapper(file_storage.stream, encoding="utf-8")
    reader = csv.DictReader(stream)
    for row in reader:
        ip = (row.get("ip") or "").strip()
        status = (row.get("status") or "Free").strip().title()
        hostname = (row.get("hostname") or None)
        owner = (row.get("owner") or None)
        mac = (row.get("mac") or None)
        note = (row.get("note") or None)

        if status not in ("Free", "Allocated", "Reserved"):
            status = "Free"

        # ensure ip exists or insert if inside subnet
        cur.execute("SELECT id FROM ip_addresses WHERE subnet_id=? AND ip=?", (subnet_id, ip))
        r = cur.fetchone()
        if r is None:
            subnet = get_subnet(subnet_id)
            try:
                net = ipaddress.ip_network(subnet["cidr"])
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj in net and ip_obj not in (net.network_address, net.broadcast_address):
                    cur.execute("""
                        INSERT INTO ip_addresses(subnet_id, ip, ip_int, status, hostname, owner, mac, note, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (subnet_id, ip, int(ip_obj), status, hostname, owner, mac, note, ts))
                    ip_row_id = cur.lastrowid
                else:
                    continue
            except Exception:
                continue
        else:
            ip_row_id = r["id"]
            cur.execute("""
                UPDATE ip_addresses
                   SET status=?, hostname=?, owner=?, mac=?, note=?, updated_at=?
                 WHERE id=?
            """, (status, hostname, owner, mac, note, ts, ip_row_id))

        # history
        cur.execute("INSERT INTO history(ip_id, action, who, note, at) VALUES (?,?,?,?,?)",
                    (ip_row_id, "Imported", current_username(), note, ts))
        count += 1
    con.commit()
    return count

def get_history(ip_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("""
        SELECT * FROM history WHERE ip_id=? ORDER BY id DESC
    """, (ip_id,))
    return cur.fetchall()

# --------------- Routes -----------------

@app.before_request
def before_request():
    init_db()
    ensure_default_admin()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    require_csrf()
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    subnets = list_subnets()
    return render_template("subnets.html", subnets=subnets)

@app.route("/subnets/new", methods=["GET", "POST"])
@login_required
def new_subnet():
    if request.method == "POST":
        require_csrf()
        try:
            name = request.form["name"].strip()
            cidr = request.form["cidr"].strip()
            site = request.form.get("site", "").strip()
            vlan = request.form.get("vlan", "").strip()
            desc = request.form.get("description", "").strip()
            sid = create_subnet(name, cidr, site, vlan, desc)
            flash("Subnet created.", "success")
            return redirect(url_for("view_subnet", subnet_id=sid))
        except Exception as e:
            flash(str(e), "danger")
    return render_template("subnets.html", subnets=list_subnets(), show_new=True)

@app.route("/subnets/<int:subnet_id>/delete", methods=["POST"])
@login_required
def delete_subnet_route(subnet_id):
    require_csrf()
    s = get_subnet(subnet_id)
    if not s:
        abort(404)
    delete_subnet(subnet_id)
    flash(f"Deleted subnet {s['name']} ({s['cidr']}).", "warning")
    return redirect(url_for("dashboard"))

@app.route("/subnets/<int:subnet_id>")
@login_required
def view_subnet(subnet_id):
    s = get_subnet(subnet_id)
    if not s:
        abort(404)
    ips = list_ips(subnet_id)
    # compute utilization
    used = len([r for r in ips if r["status"] in ("Allocated","Reserved")])
    total = len(ips)
    util = int((used / total * 100)) if total else 0
    return render_template("ips.html", subnet=s, ips=ips, used=used, total=total, util=util)

@app.route("/subnets/<int:subnet_id>/allocate_next", methods=["POST"])
@login_required
def allocate_next(subnet_id):
    require_csrf()
    r = next_free_ip(subnet_id)
    if not r:
        flash("No Free IP available (or subnet not pre-populated).", "warning")
        return redirect(url_for("view_subnet", subnet_id=subnet_id))
    # minimal allocation details
    hostname = request.form.get("hostname") or None
    owner = request.form.get("owner") or None
    mac = request.form.get("mac") or None
    note = request.form.get("note") or None
    set_ip_status(r["id"], "Allocated", who=current_username(), hostname=hostname, owner=owner, mac=mac, note=note)
    flash(f"Allocated {get_ip_row(r['id'])['ip']}.", "success")
    return redirect(url_for("view_subnet", subnet_id=subnet_id))

@app.route("/ips/<int:ip_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ip(ip_id):
    r = get_ip_row(ip_id)
    if not r:
        abort(404)
    if request.method == "POST":
        require_csrf()
        status = request.form.get("status", r["status"])
        hostname = request.form.get("hostname") or None
        owner = request.form.get("owner") or None
        mac = request.form.get("mac") or None
        note = request.form.get("note") or None
        set_ip_status(ip_id, status, who=current_username(), hostname=hostname, owner=owner, mac=mac, note=note)
        flash("IP updated.", "success")
        return redirect(url_for("view_subnet", subnet_id=r["subnet_id"]))
    return render_template("ips.html", subnet=get_subnet(r["subnet_id"]), ips=list_ips(r["subnet_id"]),
                           edit_ip=r)

@app.route("/ips/<int:ip_id>/reserve", methods=["POST"])
@login_required
def reserve_ip(ip_id):
    require_csrf()
    r = get_ip_row(ip_id)
    if not r:
        abort(404)
    set_ip_status(ip_id, "Reserved", who=current_username())
    flash(f"Reserved {r['ip']}.", "info")
    return redirect(url_for("view_subnet", subnet_id=r["subnet_id"]))

@app.route("/ips/<int:ip_id>/allocate", methods=["POST"])
@login_required
def allocate_ip(ip_id):
    require_csrf()
    r = get_ip_row(ip_id)
    if not r:
        abort(404)
    set_ip_status(ip_id, "Allocated", who=current_username())
    flash(f"Allocated {r['ip']}.", "success")
    return redirect(url_for("view_subnet", subnet_id=r["subnet_id"]))

@app.route("/ips/<int:ip_id>/release", methods=["POST"])
@login_required
def release_ip_route(ip_id):
    require_csrf()
    r = get_ip_row(ip_id)
    if not r:
        abort(404)
    release_ip(ip_id, who=current_username())
    flash(f"Released {r['ip']}.", "warning")
    return redirect(url_for("view_subnet", subnet_id=r["subnet_id"]))

@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    rows = find_ip_by_text(q) if q else []
    return render_template("search.html", q=q, rows=rows)

@app.route("/subnets/<int:subnet_id>/export")
@login_required
def export_subnet(subnet_id):
    s = get_subnet(subnet_id)
    if not s:
        abort(404)
    output = export_subnet_to_csv(subnet_id)
    filename = f"ipam_{s['name'].replace(' ','_')}_{s['cidr'].replace('/','_')}.csv"
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )

@app.route("/subnets/<int:subnet_id>/import", methods=["POST"])
@login_required
def import_subnet(subnet_id):
    require_csrf()
    s = get_subnet(subnet_id)
    if not s:
        abort(404)
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".csv"):
        flash("Please upload a CSV file.", "danger")
        return redirect(url_for("view_subnet", subnet_id=subnet_id))
    count = import_csv_to_subnet(subnet_id, f)
    flash(f"Imported {count} rows.", "success")
    return redirect(url_for("view_subnet", subnet_id=subnet_id))

@app.route("/ips/<int:ip_id>/history")
@login_required
def history(ip_id):
    r = get_ip_row(ip_id)
    if not r:
        abort(404)
    hist = get_history(ip_id)
    return render_template("history.html", ip=r, history=hist, subnet=get_subnet(r["subnet_id"]))

# --- Optional: very simple profile page to change password ---
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        require_csrf()
        pw1 = request.form.get("password", "")
        pw2 = request.form.get("password2", "")
        if not pw1 or pw1 != pw2:
            flash("Passwords must match and not be empty.", "danger")
        else:
            con = get_db()
            cur = con.cursor()
            cur.execute("UPDATE users SET password_hash=? WHERE id=?",
                        (generate_password_hash(pw1), session["user_id"]))
            con.commit()
            flash("Password updated.", "success")
    return render_template("base.html", content_title="Profile", content_html="""
        <form method="POST">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <div class="form-row"><label>New password</label><input type="password" name="password" required></div>
          <div class="form-row"><label>Confirm password</label><input type="password" name="password2" required></div>
          <button class="btn">Update</button>
        </form>
    """)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
"""

BASE_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IPAM</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="{{ url_for('static', filename='styles.css') }}" rel="stylesheet">
</head>
<body>
  <nav class="topnav">
    <div class="brand"><a href="{{ url_for('dashboard') }}">IPAM</a></div>
    {% if session.get('user_id') %}
      <div class="navlinks">
        <a href="{{ url_for('dashboard') }}">Subnets</a>
        <a href="{{ url_for('search') }}">Search</a>
        <a href="{{ url_for('profile') }}">Profile</a>
        <form method="POST" action="{{ url_for('logout') }}" style="display:inline">
          <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
          <button class="linkish">Logout ({{ session.get('username') }})</button>
        </form>
      </div>
    {% endif %}
  </nav>

  <main class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="flash-wrap">
          {% for cat, msg in messages %}
            <div class="flash {{ cat }}">{{ msg }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {% if content_title %}<h2>{{ content_title }}</h2>{% endif %}
    {% if content_html %}{{ content_html|safe }}{% endif %}
    {% block content %}{% endblock %}
  </main>
</body>
</html>
"""

LOGIN_HTML = r"""{% extends "base.html" %}
{% block content %}
<div class="auth-card">
  <h2>Sign in</h2>
  <form method="POST">
    <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <div class="form-row">
      <label>Username</label>
      <input type="text" name="username" autofocus required>
    </div>
    <div class="form-row">
      <label>Password</label>
      <input type="password" name="password" required>
    </div>
    <button class="btn">Login</button>
  </form>
</div>
{% endblock %}
"""

SUBNETS_HTML = r"""{% extends "base.html" %}
{% block content %}
<div class="toolbar">
  <form method="GET" action="{{ url_for('new_subnet') }}" style="display:inline">
    <button class="btn">Add Subnet</button>
  </form>
</div>

{% if show_new %}
<div class="card">
  <h3>New Subnet</h3>
  <form method="POST" action="{{ url_for('new_subnet') }}">
    <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <div class="grid">
      <div class="form-row"><label>Name *</label><input name="name" required></div>
      <div class="form-row"><label>CIDR *</label><input name="cidr" placeholder="192.168.10.0/24" required></div>
      <div class="form-row"><label>Site</label><input name="site"></div>
      <div class="form-row"><label>VLAN</label><input name="vlan"></div>
      <div class="form-row span2"><label>Description</label><textarea name="description" rows="2"></textarea></div>
    </div>
    <button class="btn">Create</button>
    <a class="btn secondary" href="{{ url_for('dashboard') }}">Cancel</a>
  </form>
</div>
{% endif %}

<div class="card">
  <h3>Subnets</h3>
  <table>
    <thead><tr><th>Name</th><th>CIDR</th><th>Site</th><th>VLAN</th><th>Util</th><th>Description</th><th></th></tr></thead>
    <tbody>
      {% for s in subnets %}
      <tr>
        <td><a href="{{ url_for('view_subnet', subnet_id=s.id) }}">{{ s.name }}</a></td>
        <td>{{ s.cidr }}</td>
        <td>{{ s.site or '' }}</td>
        <td>{{ s.vlan or '' }}</td>
        <td>{{ s.used }}/{{ s.total }} ({{ s.util }}%)</td>
        <td>{{ s.description or '' }}</td>
        <td>
          <form method="POST" action="{{ url_for('delete_subnet_route', subnet_id=s.id) }}" onsubmit="return confirm('Delete this subnet and all IPs?');">
            <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
            <button class="btn danger">Delete</button>
          </form>
        </td>
      </tr>
      {% else %}
      <tr><td colspan="7">No subnets yet. Click "Add Subnet".</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

IPS_HTML = r"""{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Subnet: {{ subnet.name }} — {{ subnet.cidr }}</h3>
  <p>Site: {{ subnet.site or '—' }} &nbsp; | &nbsp; VLAN: {{ subnet.vlan or '—' }} &nbsp; | &nbsp; Utilization: {{ used }}/{{ total }} ({{ util }}%)</p>

  <div class="toolbar">
    <form method="POST" action="{{ url_for('allocate_next', subnet_id=subnet.id) }}">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <input name="hostname" placeholder="hostname (optional)" style="max-width:200px">
      <input name="owner" placeholder="owner (optional)" style="max-width:150px">
      <input name="mac" placeholder="MAC (optional)" style="max-width:150px">
      <input name="note" placeholder="note (optional)" style="max-width:240px">
      <button class="btn">Allocate next free</button>
    </form>
    <div class="spacer"></div>
    <form method="GET" action="{{ url_for('export_subnet', subnet_id=subnet.id) }}" style="display:inline">
      <button class="btn secondary">Export CSV</button>
    </form>
    <form method="POST" action="{{ url_for('import_subnet', subnet_id=subnet.id) }}" enctype="multipart/form-data" style="display:inline">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <input type="file" name="file" accept=".csv" required>
      <button class="btn secondary">Import CSV</button>
    </form>
  </div>

  {% if edit_ip %}
  <div class="card alt">
    <h4>Edit: {{ edit_ip.ip }}</h4>
    <form method="POST" action="{{ url_for('edit_ip', ip_id=edit_ip.id) }}">
      <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
      <div class="grid">
        <div class="form-row">
          <label>Status</label>
          <select name="status">
            <option value="Free" {{ 'selected' if edit_ip.status=='Free' }}>Free</option>
            <option value="Allocated" {{ 'selected' if edit_ip.status=='Allocated' }}>Allocated</option>
            <option value="Reserved" {{ 'selected' if edit_ip.status=='Reserved' }}>Reserved</option>
          </select>
        </div>
        <div class="form-row"><label>Hostname</label><input name="hostname" value="{{ edit_ip.hostname or '' }}"></div>
        <div class="form-row"><label>Owner</label><input name="owner" value="{{ edit_ip.owner or '' }}"></div>
        <div class="form-row"><label>MAC</label><input name="mac" value="{{ edit_ip.mac or '' }}"></div>
        <div class="form-row span2">
          <label>Note</label>
          <textarea name="note" rows="2">{{ edit_ip.note or '' }}</textarea>
        </div>
      </div>
      <button class="btn">Save</button>
      <a class="btn secondary" href="{{ url_for('view_subnet', subnet_id=subnet.id) }}">Cancel</a>
    </form>
  </div>
  {% endif %}

  <table>
    <thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>Owner</th><th>MAC</th><th>Note</th><th>Updated</th><th></th></tr></thead>
    <tbody>
      {% for r in ips %}
        <tr class="{{ r.status }}">
          <td><a href="{{ url_for('history', ip_id=r.id) }}" title="View history">{{ r.ip }}</a></td>
          <td>{{ r.status }}</td>
          <td>{{ r.hostname or '' }}</td>
          <td>{{ r.owner or '' }}</td>
          <td>{{ r.mac or '' }}</td>
          <td class="truncate" title="{{ r.note or '' }}">{{ r.note or '' }}</td>
          <td>{{ r.updated_at or '' }}</td>
          <td class="actions">
            <form method="GET" action="{{ url_for('edit_ip', ip_id=r.id) }}" style="display:inline">
              <button class="btn small">Edit</button>
            </form>
            <form method="POST" action="{{ url_for('reserve_ip', ip_id=r.id) }}" style="display:inline">
              <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
              <button class="btn small">Reserve</button>
            </form>
            <form method="POST" action="{{ url_for('allocate_ip', ip_id=r.id) }}" style="display:inline">
              <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
              <button class="btn small">Allocate</button>
            </form>
            <form method="POST" action="{{ url_for('release_ip_route', ip_id=r.id) }}" style="display:inline" onsubmit="return confirm('Release this IP?');">
              <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
              <button class="btn small danger">Release</button>
            </form>
          </td>
        </tr>
      {% else %}
        <tr><td colspan="8">No IPs populated for this subnet (likely too large). Use CSV import or choose a smaller subnet.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

SEARCH_HTML = r"""{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>Search</h3>
  <form method="GET">
    <input type="text" name="q" value="{{ q }}" placeholder="IP or hostname" style="max-width:300px">
    <button class="btn">Go</button>
  </form>
  <table style="margin-top:1rem">
    <thead>
      <tr><th>IP</th><th>Hostname</th><th>Status</th><th>Subnet</th><th>CIDR</th><th>Owner</th><th>MAC</th><th>Updated</th></tr>
    </thead>
    <tbody>
      {% for r in rows %}
      <tr class="{{ r.status }}">
        <td>{{ r.ip }}</td>
        <td>{{ r.hostname or '' }}</td>
        <td>{{ r.status }}</td>
        <td>{{ r.subnet_name }}</td>
        <td>{{ r.cidr }}</td>
        <td>{{ r.owner or '' }}</td>
        <td>{{ r.mac or '' }}</td>
        <td>{{ r.updated_at or '' }}</td>
      </tr>
      {% else %}
      <tr><td colspan="8">Enter a query to search.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

HISTORY_HTML = r"""{% extends "base.html" %}
{% block content %}
<div class="card">
  <h3>History for {{ ip.ip }} ({{ subnet.name }} — {{ subnet.cidr }})</h3>
  <table>
    <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Note</th></tr></thead>
    <tbody>
      {% for h in history %}
        <tr>
          <td>{{ h['at'] }}</td>
          <td>{{ h['who'] or '' }}</td>
          <td>{{ h['action'] }}</td>
          <td>{{ h['note'] or '' }}</td>
        </tr>
      {% else %}
        <tr><td colspan="4">No history yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>
  <p><a class="btn" href="{{ url_for('view_subnet', subnet_id=subnet.id) }}">Back to subnet</a></p>
</div>
{% endblock %}
"""

STYLES_CSS = r""":root { --bg:#0f172a; --panel:#111827; --muted:#6b7280; --text:#e5e7eb; --accent:#60a5fa; --danger:#ef4444; --warn:#f59e0b; --ok:#22c55e; }
* { box-sizing: border-box; }
body { margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background: var(--bg); color: var(--text);} 
a { color: var(--accent); text-decoration: none; }
.container { max-width: 1200px; margin: 1.5rem auto; padding: 0 1rem; }
.topnav { display:flex; justify-content: space-between; align-items:center; background:#0b1020; padding:.75rem 1rem; }
.topnav .brand a { font-weight:700; color:white; }
.topnav .navlinks a, .topnav .navlinks form { margin-left: 1rem; display:inline-block; }
.linkish { background:none; border:none; color: var(--accent); cursor:pointer; font:inherit; padding:0; }
.card { background: var(--panel); border: 1px solid #1f2937; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
.card.alt { background: #0e162b; }
.toolbar { display:flex; gap: .75rem; align-items:center; }
.toolbar .spacer { flex:1; }
.grid { display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
.grid .span2 { grid-column: span 2; }
.form-row { display:flex; flex-direction: column; gap:.25rem; }
label { color: var(--muted); font-size:.9rem; }
input, select, textarea { background:#0b1224; color: var(--text); border:1px solid #1f2937; border-radius:6px; padding:.5rem; }
.btn { background: var(--accent); color:#0b1020; border:none; border-radius:6px; padding:.5rem .8rem; cursor:pointer; font-weight:600; }
.btn.secondary { background:#374151; color:#e5e7eb; }
.btn.danger { background: var(--danger); color: white; }
.btn.small { padding:.3rem .5rem; font-size:.85rem; }
table { width:100%; border-collapse: collapse; }
th, td { padding:.55rem .5rem; border-bottom:1px solid #1f2937; text-align:left; }
tr.Allocated { background: rgba(239, 68, 68, 0.10); }
tr.Reserved { background: rgba(245, 158, 11, 0.10); }
tr.Free { background: rgba(34, 197, 94, 0.10); }
.flash-wrap { margin-bottom:.75rem; }
.flash { padding:.5rem .75rem; border-radius:6px; margin-bottom:.3rem; }
.flash.success { background: rgba(34,197,94,.15); border:1px solid rgba(34,197,94,.4); }
.flash.info { background: rgba(96,165,250,.15); border:1px solid rgba(96,165,250,.4); }
.flash.warning { background: rgba(245,158,11,.15); border:1px solid rgba(245,158,11,.4); }
.flash.danger { background: rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.4); }
.auth-card { max-width: 420px; margin: 4rem auto; }
.actions form { margin-right:.25rem; }
.truncate { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
"""

README_MD = r"""# IPAM Web (Flask)

A simple IP Address Management web app with basic authentication and SQLite.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
