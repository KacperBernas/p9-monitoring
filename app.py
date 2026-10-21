import os
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

from app.database import get_connection, init_database
from app.security_events import log_security_event

app = Flask(
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)
app.secret_key = os.environ.get("SECRET_KEY", "local-lab-only-change-me")

init_database()


def initialize_users():
    connection = get_connection()

    users = [
        ("admin", "AdminLab2026!", "admin"),
        ("student", "StudentLab2026!", "user"),
    ]

    for username, password, role in users:
        existing = connection.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing is None:
            connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )

    connection.commit()
    connection.close()


initialize_users()


def client_ip():
    return request.remote_addr or "unknown"


@app.route("/")
def home():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_connection()
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["username"] = user["username"]
            session["role"] = user["role"]

            log_security_event(
                event_type="LOGIN_SUCCESS",
                severity="INFO",
                result="SUCCESS",
                username=username,
                ip_address=client_ip(),
                endpoint="/login",
                details="User authenticated successfully",
            )

            return redirect(url_for("dashboard"))

        log_security_event(
            event_type="LOGIN_FAILED",
            severity="WARNING",
            result="FAILURE",
            username=username or "unknown",
            ip_address=client_ip(),
            endpoint="/login",
            details="Invalid username or password",
        )

        return render_template("login.html", error="Nieprawidłowy login lub hasło.")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        log_security_event(
            event_type="AUTHZ_DENIED",
            severity="WARNING",
            result="FAILURE",
            ip_address=client_ip(),
            endpoint="/dashboard",
            details="Unauthenticated access attempt",
        )
        return redirect(url_for("login"))

    connection = get_connection()

    events = connection.execute(
        "SELECT * FROM security_events ORDER BY id DESC LIMIT 50"
    ).fetchall()

    alerts = connection.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"
    ).fetchall()

    event_count = connection.execute(
        "SELECT COUNT(*) AS count FROM security_events"
    ).fetchone()["count"]

    failed_logins = connection.execute(
        "SELECT COUNT(*) AS count FROM security_events WHERE event_type = 'LOGIN_FAILED'"
    ).fetchone()["count"]

    open_alerts = connection.execute(
        "SELECT COUNT(*) AS count FROM alerts WHERE status = 'OPEN'"
    ).fetchone()["count"]

    connection.close()

    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts,
        event_count=event_count,
        failed_logins=failed_logins,
        open_alerts=open_alerts,
        username=session["username"],
        role=session["role"],
    )

@app.route("/admin")
def admin():
    username = session.get("username")
    role = session.get("role")

    if not username:
        log_security_event(
            event_type="AUTHZ_DENIED",
            severity="WARNING",
            result="FAILURE",
            ip_address=client_ip(),
            endpoint="/admin",
            details="Unauthenticated access attempt to admin panel",
        )
        return "403 Forbidden", 403

    if role != "admin":
        log_security_event(
            event_type="ACCESS_DENIED",
            severity="WARNING",
            result="FAILURE",
            username=username,
            ip_address=client_ip(),
            endpoint="/admin",
            details="User attempted to access admin panel without permission",
        )
        return "403 Forbidden", 403

    return "Panel administratora — dostęp przyznany."
@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username")

    log_security_event(
        event_type="LOGOUT",
        severity="INFO",
        result="SUCCESS",
        username=username,
        ip_address=client_ip(),
        endpoint="/logout",
        details="User logged out",
    )

    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)