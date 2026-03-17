from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from weasyprint import HTML
from flask import send_file

from recon.risk_engine import calculate_risk

from flask import session
from werkzeug.security import generate_password_hash, check_password_hash

import threading
from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime
import os

from database import get_db
from config import REPORT_DIR
from recon import (
    subdomain,
    live_hosts,
    port_scan,
    tech_fingerprint,
    directory_enum
)

app = Flask(__name__)
app.secret_key = "red_team_recon_secret"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            db.commit()
        except:
            return "Username already exists"
        finally:
            db.close()

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        db.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        else:
            return "Invalid credentials"

    return render_template("login.html")


@app.route("/", methods=["GET", "POST"])
def index():
    if not login_required():
        return redirect(url_for("login"))

    if request.method == "POST":
        target = request.form.get("target").strip()

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "INSERT INTO scans (target, scan_date, status) VALUES (?, ?, ?)",
            (
                target,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "running"
            )
        )

        scan_id = cursor.lastrowid
        db.commit()
        db.close()

        threading.Thread(
            target=run_recon_background,
            args=(scan_id, target),
            daemon=True
        ).start()

        return redirect(url_for("scan_status", scan_id=scan_id))

    return render_template("index.html")


def run_recon_background(scan_id, target):
    start_time = time.time()

    db = get_db()
    cursor = db.cursor()

    modules = {
        "Subdomain Enumeration": lambda: subdomain.run(target),
        "Live Host Detection": lambda: live_hosts.run(target),
        "Port Scanning": lambda: port_scan.run(target),
        "Technology Fingerprinting": lambda: tech_fingerprint.run(target),
        "Directory Enumeration": lambda: directory_enum.run(target),
    }

    results_dict = {}

    # Run modules in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_module = {
            executor.submit(func): name for name, func in modules.items()
        }

        for future in as_completed(future_to_module):
            module_name = future_to_module[future]
            try:
                results_dict[module_name] = future.result(timeout=300)
            except Exception as e:
                results_dict[module_name] = f"Error: {str(e)}"

    # Store results
    for module, output in results_dict.items():
        cursor.execute(
            "INSERT INTO results (scan_id, module, output) VALUES (?, ?, ?)",
            (scan_id, module, output)
        )

    # Risk scoring
    risk_level, risk_score = calculate_risk(results_dict)

    duration = round(time.time() - start_time, 2)

    cursor.execute(
        """
        UPDATE scans
        SET status = ?, risk_level = ?, risk_score = ?
        WHERE id = ?
        """,
        ("completed", risk_level, risk_score, scan_id)
    )

    db.commit()
    db.close()

    generate_report(scan_id)
    generate_pdf(scan_id)



@app.route("/download/pdf/<int:scan_id>")
def download_pdf(scan_id):
    if not login_required():
        return redirect(url_for("login"))

    pdf_path = os.path.join(REPORT_DIR, f"report_{scan_id}.pdf")

    if not os.path.exists(pdf_path):
        return "PDF not found"

    return send_file(pdf_path, as_attachment=True)


@app.route("/results/<int:scan_id>")
def results(scan_id):
    db = get_db()
    scan = db.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    results = db.execute(
        "SELECT * FROM results WHERE scan_id = ?", (scan_id,)
    ).fetchall()

    db.close()

    return render_template("results.html", scan=scan, results=results)


def generate_report(scan_id):
    db = get_db()
    scan = db.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    results = db.execute(
        "SELECT * FROM results WHERE scan_id = ?", (scan_id,)
    ).fetchall()

    db.close()

    os.makedirs(REPORT_DIR, exist_ok=True)

    report_path = os.path.join(REPORT_DIR, f"report_{scan_id}.html")

    with app.app_context():
        html = render_template("report.html", scan=scan, results=results)

    with open(report_path, "w") as f:
        f.write(html)

def generate_pdf(scan_id):
    html_path = os.path.join(REPORT_DIR, f"report_{scan_id}.html")
    pdf_path = os.path.join(REPORT_DIR, f"report_{scan_id}.pdf")

    if not os.path.exists(html_path):
        return

    HTML(filename=html_path).write_pdf(pdf_path)

@app.route("/status/<int:scan_id>")
def scan_status(scan_id):
    db = get_db()
    scan = db.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()
    db.close()

    if scan["status"] == "completed":
        return redirect(url_for("results", scan_id=scan_id))

    return render_template("scan_status.html", scan=scan)



def login_required():
    return "user_id" in session


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))

    db = get_db()
    scans = db.execute(
        """
        SELECT id, target, scan_date, risk_level, risk_score
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()
    db.close()

    return render_template("dashboard.html", scans=scans)



if __name__ == "__main__":
    print("[+] Starting Red Team Recon Application")
    app.run(host="127.0.0.1", port=5000, debug=True)
