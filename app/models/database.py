import sqlite3
import json
from datetime import datetime
from flask import current_app, g


def get_db():
    """
    İstek (request) bazında bir SQLite bağlantısı döner. Flask'ın `g`
    nesnesi sayesinde aynı istek içinde birden fazla sorgu yapılsa bile
    bağlantı yalnızca bir kez açılır.
    """
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row  # satırlara sözlük gibi erişebilmek için
    return g.db


def close_db(e=None):
    """İstek sonlandığında veritabanı bağlantısını kapatır."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """
    Uygulama başlatılırken çağrılır; gerekli tablo yoksa oluşturur.
    Bu fonksiyon, app factory (create_app) içinden çağrılacak.
    """
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE_PATH"])
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        db.commit()
        db.close()

    # Her istek sonunda bağlantıyı otomatik kapat
    app.teardown_appcontext(close_db)


def save_scan_result(scan_data):
    """
    Tamamlanan bir taramanın tüm sonucunu (JSON olarak) veritabanına kaydeder.

    Args:
        scan_data (dict): /scan endpoint'inin ürettiği tam sonuç sözlüğü.

    Returns:
        int: Yeni kaydın id'si.
    """
    db = get_db()
    risk = scan_data.get("risk", {})

    cursor = db.execute(
        """
        INSERT INTO scans (target, scan_date, risk_score, risk_level, result_json)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            scan_data.get("target"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            risk.get("score", 0),
            risk.get("level", "low"),
            json.dumps(scan_data),
        )
    )
    db.commit()
    return cursor.lastrowid


def get_recent_scans(limit=5):
    """Dashboard'da gösterilecek en son N taramayı döner (özet bilgilerle)."""
    db = get_db()
    rows = db.execute(
        """
        SELECT id, target, scan_date, risk_score, risk_level
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


def get_all_scans():
    """Scan History sayfası için tüm geçmiş taramaları döner."""
    db = get_db()
    rows = db.execute(
        """
        SELECT id, target, scan_date, risk_score, risk_level
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    """Tek bir taramanın tam kaydını (result_json dahil) döner."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["result_json"] = json.loads(result["result_json"])
    return result
