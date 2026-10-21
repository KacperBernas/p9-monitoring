
from datetime import datetime, timezone

from flask import g

from app.database import get_connection
from app.correlation import (
    correlate_failed_login,
    correlate_access_denied,
    correlate_multiple_accounts,
)


def log_security_event(
    event_type,
    severity="INFO",
    result="SUCCESS",
    username=None,
    ip_address=None,
    endpoint=None,
    details=None,
):
    request_id = getattr(g, "request_id", None)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO security_events (
                timestamp,
                event_type,
                severity,
                username,
                ip_address,
                endpoint,
                result,
                details,
                request_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                request_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    if event_type == "LOGIN_FAILED":
        correlate_failed_login(ip_address)
        correlate_multiple_accounts(ip_address)
    elif event_type == "ACCESS_DENIED" and endpoint == "/admin":
        correlate_access_denied(ip_address)
