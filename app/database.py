import sqlite3
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_db_path: str = ""


def init_db(db_path: str) -> None:
    global _db_path
    _db_path = db_path

    with _connect() as con:
        con.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT,
                severity       TEXT,
                category       TEXT,
                title          TEXT,
                detail         TEXT,
                recommendation TEXT DEFAULT '',
                resolved       INTEGER DEFAULT 0,
                fingerprint    TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS devices (
                mac         TEXT PRIMARY KEY,
                ip          TEXT,
                name        TEXT,
                vendor      TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                trusted     INTEGER DEFAULT 0,
                device_type TEXT
            );

            CREATE TABLE IF NOT EXISTS ports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac  TEXT,
                port        INTEGER,
                protocol    TEXT,
                service     TEXT,
                version     TEXT,
                detected_at TEXT,
                UNIQUE(device_mac, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS cves (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac  TEXT,
                cve_id      TEXT,
                severity    TEXT,
                cvss_score  REAL,
                description TEXT,
                detected_at TEXT,
                UNIQUE(device_mac, cve_id)
            );

            CREATE TABLE IF NOT EXISTS zigbee_devices (
                ieee          TEXT PRIMARY KEY,
                friendly_name TEXT,
                first_seen    TEXT,
                last_seen     TEXT,
                trusted       INTEGER DEFAULT 0,
                lqi_history   TEXT
            );
        """)

    with _connect() as con:
        try:
            con.execute("ALTER TABLE alerts ADD COLUMN recommendation TEXT DEFAULT ''")
        except Exception:
            pass

    logger.info("DB inicializada en %s", db_path)


@contextmanager
def _connect():
    con = sqlite3.connect(_db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()



def insert_alert(
    severity: str, category: str, title: str, detail: str, recommendation: str = "") -> bool:
    fingerprint = hashlib.md5(f"{category}:{title}".encode()).hexdigest()
    with _connect() as con:
        cur = con.execute(
            "INSERT OR IGNORE INTO alerts "
            "(timestamp, severity, category, title, detail, recommendation, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (_now(), severity, category, title, detail, recommendation, fingerprint),
        )
        is_new = cur.rowcount == 1
        if not is_new and recommendation:
            con.execute(
                "UPDATE alerts SET recommendation = ? "
                "WHERE fingerprint = ? AND (recommendation IS NULL OR recommendation = '')",
                (recommendation, fingerprint),
            )
        return is_new


def get_alerts(limit: int = 50) -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            "SELECT * FROM alerts WHERE resolved = 0 ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def resolve_alert(alert_id: int) -> None:
    with _connect() as con:
        con.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))



def upsert_device(
    mac: str,
    ip: str,
    name: str = "",
    vendor: str = "",
    trusted: int = 0,
    device_type: str = "unknown") -> None:
    now = _now()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO devices (mac, ip, name, vendor, first_seen, last_seen, trusted, device_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip          = excluded.ip,
                name        = excluded.name,
                vendor      = excluded.vendor,
                last_seen   = excluded.last_seen,
                device_type = excluded.device_type
            """,
            (mac, ip, name, vendor, now, now, trusted, device_type),
        )


def get_devices() -> list[dict]:
    with _connect() as con:
        rows = con.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]



def upsert_zigbee_device(
    ieee: str, friendly_name: str = "", lqi_history: str = "[]", trusted: int = 0) -> None:
    now = _now()
    with _connect() as con:
        con.execute(
            """
            INSERT INTO zigbee_devices (ieee, friendly_name, first_seen, last_seen, trusted, lqi_history)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ieee) DO UPDATE SET
                friendly_name = excluded.friendly_name,
                last_seen     = excluded.last_seen,
                trusted       = MAX(zigbee_devices.trusted, excluded.trusted)
            """,
            (ieee, friendly_name, now, now, trusted, lqi_history),
        )


def update_zigbee_lqi(ieee: str, lqi_history: str) -> None:
    with _connect() as con:
        con.execute(
            "UPDATE zigbee_devices SET lqi_history = ?, last_seen = ? WHERE ieee = ?",
            (lqi_history, _now(), ieee),
        )


def get_zigbee_devices() -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            "SELECT * FROM zigbee_devices ORDER BY last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]



def insert_port(
    device_mac: str, port: int, protocol: str, service: str = "", version: str = "") -> None:
    with _connect() as con:
        con.execute(
            "INSERT OR IGNORE INTO ports (device_mac, port, protocol, service, version, detected_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_mac, port, protocol, service, version, _now()),
        )


def get_ports_by_mac(mac: str) -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            "SELECT * FROM ports WHERE device_mac = ? ORDER BY port",
            (mac,),
        ).fetchall()
    return [dict(r) for r in rows]



def insert_cve(
    device_mac: str, cve_id: str, severity: str, cvss_score: float, description: str) -> None:
    with _connect() as con:
        con.execute(
            "INSERT OR IGNORE INTO cves (device_mac, cve_id, severity, cvss_score, description, detected_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_mac, cve_id, severity, cvss_score, description, _now()),
        )


def get_cves_by_mac(mac: str) -> list[dict]:
    with _connect() as con:
        rows = con.execute(
            "SELECT * FROM cves WHERE device_mac = ? ORDER BY cvss_score DESC",
            (mac,),
        ).fetchall()
    return [dict(r) for r in rows]
