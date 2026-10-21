
from datetime import datetime, timezone

from app.database import get_connection
from app.correlation import correlate_failed_login


def log_security_event(
    event_type,
    severity="INFO",
    result="SUCCESS",
    username=None,
    ip_address=None,
    endpoint=None,
    details=None,
):
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO security_events (
                timestamp, event_type, severity, username,
                ip_address, endpoint, result, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                event_type,
                severity,
                username,
                ip_address,
                endpoint,
                result,
                details,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    if event_type == "LOGIN_FAILED":
        correlate_failed_login(ip_address)
