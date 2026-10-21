import os
import uuid

from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    session,
)
from werkzeug.security import generate_password_hash, check_password_hash

from app.database import get_connection, init_database
from app.security_events import log_security_event

app = Flask(
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Brak wymaganej zmiennej środowiskowej SECRET_KEY")
init_database()


@app.before_request
def assign_request_id():
    g.request_id = str(uuid.uuid4())


def initialize_users():
    connection = get_connection()

    try:
        users = [
            ("admin", "AdminLab2026!", "admin"),
            ("student", "StudentLab2026!", "user"),
        ]

        for username, password, role in users:
            existing = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if existing is None:
                connection.execute(
                    """
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                    """,
                    (username, generate_password_hash(password), role),
                )

        connection.commit()
    finally:
        connection.close()


initialize_users()


def client_ip():
    return request.remote_addr or "unknown"


def is_admin():
    return bool(session.get("username")) and session.get("role") == "admin"


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
        try:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
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

        return render_template(
            "login.html",
            error="Nieprawidłowy login lub hasło.",
        )

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

    event_type = request.args.get("event_type", "").strip()
    severity = request.args.get("severity", "").strip()
    username_filter = request.args.get("username", "").strip()

    allowed_event_types = {
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "LOGOUT",
        "AUTHZ_DENIED",
        "ACCESS_DENIED",
        "ROLE_CHANGED",
    }
    allowed_severities = {"INFO", "WARNING", "HIGH"}

    if event_type not in allowed_event_types:
        event_type = ""

    if severity not in allowed_severities:
        severity = ""

    connection = get_connection()

    try:
        query = "SELECT * FROM security_events WHERE 1=1"
        parameters = []

        if event_type:
            query += " AND event_type = ?"
            parameters.append(event_type)

        if severity:
            query += " AND severity = ?"
            parameters.append(severity)

        if username_filter:
            query += " AND username LIKE ?"
            parameters.append(f"%{username_filter}%")

        query += " ORDER BY id DESC LIMIT 50"

        events = connection.execute(query, parameters).fetchall()

        alerts = connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"
        ).fetchall()

        event_count = connection.execute(
            "SELECT COUNT(*) AS count FROM security_events"
        ).fetchone()["count"]

        failed_logins = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM security_events
            WHERE event_type = 'LOGIN_FAILED'
            """
        ).fetchone()["count"]

        open_alerts = connection.execute(
            "SELECT COUNT(*) AS count FROM alerts WHERE status = 'OPEN'"
        ).fetchone()["count"]
    finally:
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
        event_type_filter=event_type,
        severity_filter=severity,
        username_filter=username_filter,
    )


@app.route("/admin")
def admin():
    username = session.get("username")

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

    if not is_admin():
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

    return redirect(url_for("manage_role"))


@app.route("/admin/role", methods=["GET", "POST"])
def manage_role():
    username = session.get("username")

    if not username:
        log_security_event(
            event_type="AUTHZ_DENIED",
            severity="WARNING",
            result="FAILURE",
            ip_address=client_ip(),
            endpoint="/admin/role",
            details="Unauthenticated attempt to manage user roles",
        )
        return "403 Forbidden", 403

    if not is_admin():
        log_security_event(
            event_type="ACCESS_DENIED",
            severity="WARNING",
            result="FAILURE",
            username=username,
            ip_address=client_ip(),
            endpoint="/admin/role",
            details="Non-admin attempted to manage user roles",
        )
        return "403 Forbidden", 403

    message = ""

    if request.method == "POST":
        target_username = request.form.get("username", "").strip()
        new_role = request.form.get("role", "").strip()

        if target_username != "student" or new_role not in {"user", "admin"}:
            message = "Nieprawidłowy użytkownik lub rola."
        else:
            connection = get_connection()

            try:
                target = connection.execute(
                    "SELECT username, role FROM users WHERE username = ?",
                    (target_username,),
                ).fetchone()

                if target is None:
                    message = "Nie znaleziono użytkownika."
                elif target["role"] == new_role:
                    message = "Użytkownik ma już wybraną rolę."
                else:
                    old_role = target["role"]

                    connection.execute(
                        "UPDATE users SET role = ? WHERE username = ?",
                        (new_role, target_username),
                    )
                    connection.commit()

                    log_security_event(
                        event_type="ROLE_CHANGED",
                        severity="WARNING",
                        result="SUCCESS",
                        username=username,
                        ip_address=client_ip(),
                        endpoint="/admin/role",
                        details=(
                            f"Role of {target_username} changed "
                            f"from {old_role} to {new_role}"
                        ),
                    )

                    message = (
                        f"Zmieniono rolę użytkownika {target_username} "
                        f"z {old_role} na {new_role}."
                    )
            finally:
                connection.close()

    connection = get_connection()

    try:
        target = connection.execute(
            "SELECT username, role FROM users WHERE username = 'student'"
        ).fetchone()
    finally:
        connection.close()

    return render_template(
        "manage_role.html",
        target=target,
        message=message,
    )


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
