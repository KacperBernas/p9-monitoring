
from datetime import datetime, timedelta, timezone

from app.database import get_connection


def correlate_failed_login(ip_address):
    if not ip_address or ip_address == "unknown":
        return

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=60)).isoformat()
    now_iso = now.isoformat()

    connection = get_connection()

    try:
        result = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE event_type = 'LOGIN_FAILED'
              AND ip_address = ?
              AND timestamp >= ?
            """,
            (ip_address, cutoff),
        ).fetchone()

        if result["total"] < 5:
            return

        title = "Podejrzana seria nieudanych logowań"

        existing_alert = connection.execute(
            """
            SELECT id
            FROM alerts
            WHERE title = ?
              AND status = 'OPEN'
              AND description LIKE ?
              AND timestamp >= ?
            LIMIT 1
            """,
            (title, f"%IP {ip_address}%", cutoff),
        ).fetchone()

        if existing_alert:
            return

        connection.execute(
            """
            INSERT INTO alerts (
                timestamp, title, severity, description, status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                title,
                "HIGH",
                f"Co najmniej 5 nieudanych logowań z adresu IP {ip_address} w ciągu 60 sekund.",
                "OPEN",
            ),
        )

        connection.commit()

    finally:
        connection.close()


def correlate_access_denied(ip_address):
    if not ip_address or ip_address == "unknown":
        return

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=60)).isoformat()
    now_iso = now.isoformat()

    connection = get_connection()

    try:
        result = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE event_type = 'ACCESS_DENIED'
              AND endpoint = '/admin'
              AND ip_address = ?
              AND timestamp >= ?
            """,
            (ip_address, cutoff),
        ).fetchone()

        if result["total"] < 3:
            return

        title = "Powtarzające się odmowy dostępu do panelu administratora"
        description = (
            f"Co najmniej 3 odmowy dostępu do panelu administratora "
            f"z adresu IP {ip_address} w ciągu 60 sekund."
        )

        existing_alert = connection.execute(
            """
            SELECT id
            FROM alerts
            WHERE title = ?
              AND status = 'OPEN'
              AND description = ?
            LIMIT 1
            """,
            (title, description),
        ).fetchone()

        if existing_alert:
            return

        connection.execute(
            """
            INSERT INTO alerts (
                timestamp, title, severity, description, status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                title,
                "HIGH",
                description,
                "OPEN",
            ),
        )

        connection.commit()

    finally:
        connection.close()


def correlate_multiple_accounts(ip_address):
    if not ip_address or ip_address == "unknown":
        return

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(seconds=60)).isoformat()
    now_iso = now.isoformat()

    connection = get_connection()

    try:
        result = connection.execute(
            """
            SELECT COUNT(DISTINCT username) AS total
            FROM security_events
            WHERE event_type = 'LOGIN_FAILED'
              AND ip_address = ?
              AND timestamp >= ?
              AND username IS NOT NULL
            """,
            (ip_address, cutoff),
        ).fetchone()

        if result["total"] < 3:
            return

        title = "Nieudane logowania na wiele kont z jednego IP"
        description = (
            f"Nieudane próby logowania na co najmniej 3 różne konta "
            f"z adresu IP {ip_address} w ciągu 60 sekund."
        )

        existing_alert = connection.execute(
            """
            SELECT id
            FROM alerts
            WHERE title = ?
              AND status = 'OPEN'
              AND description = ?
            LIMIT 1
            """,
            (title, description),
        ).fetchone()

        if existing_alert:
            return

        connection.execute(
            """
            INSERT INTO alerts (
                timestamp, title, severity, description, status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                title,
                "HIGH",
                description,
                "OPEN",
            ),
        )

        connection.commit()

    finally:
        connection.close()

