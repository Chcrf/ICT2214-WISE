import sqlite3
import json
import os
import sys
import hashlib
import shutil
import subprocess
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from wise_config import CONFIG

DB_PATH = CONFIG["paths"]["db_path"]

UPLOADS_DIR = CONFIG["paths"]["uploads_dir"]
os.makedirs(UPLOADS_DIR, exist_ok=True)

ANALYSIS_RESULTS_DIR = CONFIG["paths"]["analysis_results_dir"]
os.makedirs(ANALYSIS_RESULTS_DIR, exist_ok=True)


def _format_file_size(size_bytes):
    """Describe  format file size."""
    if size_bytes is None:
        return "Unknown"
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def _compute_ssdeep(file_path):
    """Describe  compute ssdeep."""
    if not file_path or not os.path.exists(file_path):
        return None
    if not shutil.which("ssdeep"):
        return None
    try:
        result = subprocess.run(
            ["ssdeep", "-b", file_path],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            return None
        lines = [line.strip()
                 for line in result.stdout.splitlines() if line.strip()]
        for line in lines:
            if line.lower().startswith("ssdeep"):
                continue
            return line.split(",", 1)[0]
    except Exception:
        return None
    return None


def _compute_additional_hashes(file_path, existing):
    """Describe  compute additional hashes."""
    hashes: Dict[str, str] = {k: v for k, v in existing.items() if v}
    if not file_path or not os.path.exists(file_path):
        return hashes

    hashers = {
        "sha224": hashlib.sha224(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
        "blake2b": hashlib.blake2b(),
        "blake2s": hashlib.blake2s(),
    }
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except Exception:
        return hashes

    for name, hasher in hashers.items():
        hashes.setdefault(name, hasher.hexdigest())

    ssdeep_hash = _compute_ssdeep(file_path)
    if ssdeep_hash:
        hashes.setdefault("ssdeep", ssdeep_hash)

    return hashes


def _extract_strings(file_path, max_lines=2000, min_length=4):
    """Describe  extract strings."""
    if not file_path or not os.path.exists(file_path):
        return []
    if not shutil.which("strings"):
        return []
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", str(min_length), file_path],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            return []
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if max_lines and len(lines) > max_lines:
            return lines[:max_lines]
        return lines
    except Exception:
        return []


def _load_function_map_legacy_file(investigation_id):
    """Legacy fallback: load function map from JSON artifact on disk."""
    if not investigation_id:
        return None
    path = os.path.join(ANALYSIS_RESULTS_DIR,
                        f"function_map_{investigation_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if isinstance(payload, dict):
            mapping = payload.get("mapping")
            if isinstance(mapping, list):
                return mapping
        return None
    except Exception:
        return None


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Initialize the database schema."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256_hash TEXT,
                md5_hash TEXT,
                sha1_hash TEXT,
                sample_name TEXT NOT NULL,
                file_size INTEGER,
                file_type TEXT,
                file_path TEXT,
                hashes_json TEXT,
                strings_json TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT DEFAULT 'pending',
                sample_lost INTEGER DEFAULT 0,
                investigation_type TEXT NOT NULL DEFAULT 'file',
                source TEXT,
                parent_investigation_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (parent_investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
        """)

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigations_sha256 ON investigations(sha256_hash)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigations_parent ON investigations(parent_investigation_id)")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                analysis_summary TEXT,
                risk_level TEXT DEFAULT 'Unknown',
                memory_usage TEXT,
                suspicious INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                stage TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 0,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
        """)

        def add_column_if_missing(table, column, definition):
            """Describe add column if missing."""
            cursor.execute(f"PRAGMA table_info({table})")
            columns = {row[1] for row in cursor.fetchall()}
            if column not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

        add_column_if_missing(
            "investigations", "investigation_type", "TEXT NOT NULL DEFAULT 'file'")
        add_column_if_missing("investigations", "source", "TEXT")
        add_column_if_missing(
            "investigations", "parent_investigation_id", "INTEGER")
        add_column_if_missing("investigations", "hashes_json", "TEXT")
        add_column_if_missing("investigations", "strings_json", "TEXT")

        def _migrate_drop_investigations_result_analysis_id():
            cursor.execute("PRAGMA table_info(investigations)")
            cols = {row[1] for row in cursor.fetchall()}
            if "result_analysis_id" not in cols:
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                CREATE TABLE investigations_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256_hash TEXT,
                    md5_hash TEXT,
                    sha1_hash TEXT,
                    sample_name TEXT NOT NULL,
                    file_size INTEGER,
                    file_type TEXT,
                    file_path TEXT,
                    hashes_json TEXT,
                    strings_json TEXT,
                    status TEXT DEFAULT 'pending',
                    result TEXT DEFAULT 'pending',
                    sample_lost INTEGER DEFAULT 0,
                    investigation_type TEXT NOT NULL DEFAULT 'file',
                    source TEXT,
                    parent_investigation_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (parent_investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO investigations_new (
                    id, sha256_hash, md5_hash, sha1_hash, sample_name, file_size,
                    file_type, file_path, hashes_json, strings_json, status, result,
                    sample_lost, investigation_type, source, parent_investigation_id,
                    created_at, updated_at
                )
                SELECT
                    id, sha256_hash, md5_hash, sha1_hash, sample_name, file_size,
                    file_type, file_path, hashes_json, strings_json, status, result,
                    sample_lost, investigation_type, source, parent_investigation_id,
                    created_at, updated_at
                FROM investigations
            """)
            cursor.execute("DROP TABLE investigations")
            cursor.execute("ALTER TABLE investigations_new RENAME TO investigations")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_sha256 ON investigations(sha256_hash)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_parent ON investigations(parent_investigation_id)")
            cursor.execute("PRAGMA foreign_keys = ON")

        def _migrate_drop_analysis_db_filename():
            cursor.execute("PRAGMA table_info(analysis_results)")
            cols = {row[1] for row in cursor.fetchall()}
            if "analysis_db_filename" not in cols:
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                CREATE TABLE analysis_results_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    analysis_summary TEXT,
                    risk_level TEXT DEFAULT 'Unknown',
                    memory_usage TEXT,
                    suspicious INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO analysis_results_new (
                    id, investigation_id, analysis_summary, risk_level,
                    memory_usage, suspicious, created_at
                )
                SELECT
                    id, investigation_id, analysis_summary, risk_level,
                    memory_usage, suspicious, created_at
                FROM analysis_results
            """)
            cursor.execute("DROP TABLE analysis_results")
            cursor.execute("ALTER TABLE analysis_results_new RENAME TO analysis_results")
            cursor.execute("PRAGMA foreign_keys = ON")

        _migrate_drop_investigations_result_analysis_id()
        _migrate_drop_analysis_db_filename()

        def _fk_has_cascade(table, from_col, to_table):
            cursor.execute(f"PRAGMA foreign_key_list({table})")
            rows = cursor.fetchall()
            for row in rows:
                if row["from"] == from_col and row["table"] == to_table and str(row["on_delete"]).upper() == "CASCADE":
                    return True
            return False

        def _migrate_investigations_parent_fk_cascade():
            if _fk_has_cascade("investigations", "parent_investigation_id", "investigations"):
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                UPDATE investigations
                SET parent_investigation_id = NULL
                WHERE parent_investigation_id IS NOT NULL
                  AND parent_investigation_id NOT IN (SELECT id FROM investigations)
            """)
            cursor.execute("""
                CREATE TABLE investigations_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256_hash TEXT,
                    md5_hash TEXT,
                    sha1_hash TEXT,
                    sample_name TEXT NOT NULL,
                    file_size INTEGER,
                    file_type TEXT,
                    file_path TEXT,
                    hashes_json TEXT,
                    strings_json TEXT,
                    status TEXT DEFAULT 'pending',
                    result TEXT DEFAULT 'pending',
                    sample_lost INTEGER DEFAULT 0,
                    investigation_type TEXT NOT NULL DEFAULT 'file',
                    source TEXT,
                    parent_investigation_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (parent_investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO investigations_new (
                    id, sha256_hash, md5_hash, sha1_hash, sample_name, file_size,
                    file_type, file_path, hashes_json, strings_json, status, result,
                    sample_lost, investigation_type, source, parent_investigation_id,
                    created_at, updated_at
                )
                SELECT
                    id, sha256_hash, md5_hash, sha1_hash, sample_name, file_size,
                    file_type, file_path, hashes_json, strings_json, status, result,
                    sample_lost, investigation_type, source, parent_investigation_id,
                    created_at, updated_at
                FROM investigations
            """)
            cursor.execute("DROP TABLE investigations")
            cursor.execute("ALTER TABLE investigations_new RENAME TO investigations")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_sha256 ON investigations(sha256_hash)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigations_parent ON investigations(parent_investigation_id)")
            cursor.execute("PRAGMA foreign_keys = ON")

        def _migrate_analysis_results_fk_cascade():
            if _fk_has_cascade("analysis_results", "investigation_id", "investigations"):
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                CREATE TABLE analysis_results_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    analysis_summary TEXT,
                    risk_level TEXT DEFAULT 'Unknown',
                    memory_usage TEXT,
                    suspicious INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO analysis_results_new (
                    id, investigation_id, analysis_summary, risk_level,
                    memory_usage, suspicious, created_at
                )
                SELECT
                    id, investigation_id, analysis_summary, risk_level,
                    memory_usage, suspicious, created_at
                FROM analysis_results
            """)
            cursor.execute("DROP TABLE analysis_results")
            cursor.execute("ALTER TABLE analysis_results_new RENAME TO analysis_results")
            cursor.execute("PRAGMA foreign_keys = ON")

        def _migrate_processing_queue_fk_cascade():
            if _fk_has_cascade("processing_queue", "investigation_id", "investigations"):
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                CREATE TABLE processing_queue_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    stage TEXT DEFAULT 'pending',
                    priority INTEGER DEFAULT 0,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO processing_queue_new (
                    id, investigation_id, stage, priority, error_message,
                    created_at, started_at, completed_at
                )
                SELECT
                    id, investigation_id, stage, priority, error_message,
                    created_at, started_at, completed_at
                FROM processing_queue
            """)
            cursor.execute("DROP TABLE processing_queue")
            cursor.execute("ALTER TABLE processing_queue_new RENAME TO processing_queue")
            cursor.execute("PRAGMA foreign_keys = ON")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dynamic_results (
                investigation_id INTEGER PRIMARY KEY,
                data TEXT,
                url_threat_intelligence TEXT,
                trace_viewer TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            )
        """)
        add_column_if_missing("dynamic_results", "trace_viewer", "TEXT")

        def _migrate_dynamic_results_fk_cascade():
            if _fk_has_cascade("dynamic_results", "investigation_id", "investigations"):
                return
            cursor.execute("PRAGMA foreign_keys = OFF")
            cursor.execute("""
                CREATE TABLE dynamic_results_new (
                    investigation_id INTEGER PRIMARY KEY,
                    data TEXT,
                    url_threat_intelligence TEXT,
                    trace_viewer TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                INSERT INTO dynamic_results_new (
                    investigation_id, data, url_threat_intelligence,
                    trace_viewer, created_at, updated_at
                )
                SELECT
                    investigation_id, data, url_threat_intelligence,
                    trace_viewer, created_at, updated_at
                FROM dynamic_results
            """)
            cursor.execute("DROP TABLE dynamic_results")
            cursor.execute("ALTER TABLE dynamic_results_new RENAME TO dynamic_results")
            cursor.execute("PRAGMA foreign_keys = ON")

        _migrate_investigations_parent_fk_cascade()
        _migrate_analysis_results_fk_cascade()
        _migrate_processing_queue_fk_cascade()
        _migrate_dynamic_results_fk_cascade()

        conn.commit()
        print("[Database] Schema initialized successfully")


def create_investigation(
    sha256_hash,
    sample_name,
    md5_hash=None,
    sha1_hash=None,
    file_size=None,
    file_type=None,
    file_path=None,
    investigation_type='file',
    source=None,
    parent_investigation_id=None,
):
    """Create a new investigation record."""

    if sha256_hash is None:
        sha256_hash = ""

    base_hashes = {
        "md5": md5_hash,
        "sha1": sha1_hash,
        "sha256": sha256_hash,
    }
    hashes_payload = _compute_additional_hashes(file_path, base_hashes)
    strings_payload = _extract_strings(file_path)
    hashes_json = json.dumps(hashes_payload) if hashes_payload else None
    strings_json = json.dumps(strings_payload) if strings_payload else None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO investigations
                (sha256_hash, md5_hash, sha1_hash, sample_name, file_size, file_type, file_path, hashes_json, strings_json, status, investigation_type, source, parent_investigation_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            """, (sha256_hash, md5_hash, sha1_hash, sample_name, file_size, file_type, file_path, hashes_json, strings_json, investigation_type, source, parent_investigation_id))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:

            cursor.execute(
                "SELECT id FROM investigations WHERE sha256_hash = ?", (sha256_hash,))
            row = cursor.fetchone()
            return row["id"] if row else None


def get_investigation_by_hash(sha256_hash):
    """Get investigation by SHA256 hash."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM investigations WHERE sha256_hash = ?
        """, (sha256_hash,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_investigation_by_id(investigation_id):
    """Get investigation by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_children_for_parent(parent_investigation_id):
    """Return child investigations for a URL parent."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, sha256_hash as hash, sample_name as sampleName,
                   status, parent_investigation_id as parentId, source,
                   investigation_type
            FROM investigations
            WHERE parent_investigation_id = ?
            ORDER BY created_at ASC
        """, (parent_investigation_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def delete_investigation(investigation_id):
    """Delete investigation and related DB records (not filesystem artifacts)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM investigations WHERE id = ?",
                       (investigation_id,))
        if not cursor.fetchone():
            return False
        _delete_investigation_record(cursor, investigation_id)
        cursor.execute(
            "DELETE FROM dynamic_results WHERE investigation_id = ?", (investigation_id,))
        conn.commit()
        return True


def update_sample_lost(investigation_id, lost):
    """Update sample_lost status for an investigation."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE investigations
            SET sample_lost = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (1 if lost else 0, investigation_id))
        conn.commit()


def get_all_investigations(page=1, page_size=10):
    """Get paginated list of investigations, checking if sample files still exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        offset = (page - 1) * page_size
        cursor.execute("""
            SELECT id, sha256_hash as hash, sample_name as sampleName,
                   status, result, sample_lost as sampleLost, file_path, created_at,
                   investigation_type, parent_investigation_id, source
            FROM investigations
            WHERE parent_investigation_id IS NULL
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """, (page_size, offset))
        rows = cursor.fetchall()

        results = []
        url_parent_ids = []
        for row in rows:
            item = dict(row)
            file_path = item.pop('file_path', None)

            if file_path and not item['sampleLost']:

                if not os.path.exists(file_path):

                    update_sample_lost(item['id'], True)
                    item['sampleLost'] = 1

            results.append(item)
            if item.get("investigation_type") == "url":
                url_parent_ids.append(item["id"])

        if url_parent_ids:
            placeholders = ",".join("?" for _ in url_parent_ids)
            cursor.execute(f"""
                SELECT id, sha256_hash as hash, sample_name as sampleName,
                       status, parent_investigation_id as parentId, source,
                       investigation_type
                FROM investigations
                WHERE parent_investigation_id IN ({placeholders})
                ORDER BY created_at ASC
            """, tuple(url_parent_ids))
            child_rows = cursor.fetchall()

            children_by_parent: Dict[int, List[Dict[str, Any]]] = {}
            for row in child_rows:
                child = dict(row)
                parent_id = child.pop("parentId", None)
                children_by_parent.setdefault(parent_id, []).append(child)

            for item in results:
                if item.get("investigation_type") == "url":
                    item["children"] = children_by_parent.get(item["id"], [])

        return results


def get_investigations_count():
    """Get total count of investigations."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as count FROM investigations WHERE parent_investigation_id IS NULL")
        row = cursor.fetchone()
        return row["count"]


def update_investigation_status(investigation_id, status, result=None):
    """Update investigation status and result."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if result:
            cursor.execute("""
                UPDATE investigations
                SET status = ?, result = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, result, investigation_id))
        else:
            cursor.execute("""
                UPDATE investigations
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, investigation_id))
        conn.commit()


def _get_analysis_db_path(analysis_db_filename):
    """Describe  get analysis db path."""
    return os.path.join(ANALYSIS_RESULTS_DIR, analysis_db_filename)


def _ensure_analysis_db(analysis_db_path):
    """Create per-investigation analysis DB and table if missing."""
    conn = sqlite3.connect(analysis_db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wasm_decompile TEXT,
                ai_decompile TEXT,
                function_name_map_json TEXT,
                analysis_summary TEXT,
                risk_level TEXT DEFAULT 'Unknown',
                functions_json TEXT,
                imports_json TEXT,
                exports_json TEXT,
                memory_usage TEXT,
                suspicious INTEGER DEFAULT 0,
                security_findings_json TEXT,
                yara_rule TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        try:
            cursor.execute(
                "ALTER TABLE analysis_results ADD COLUMN security_findings_json TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE analysis_results ADD COLUMN yara_rule TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE analysis_results ADD COLUMN ai_decompile TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE analysis_results ADD COLUMN function_name_map_json TEXT")
        except Exception:
            pass
        conn.commit()
    finally:
        conn.close()


def _upsert_analysis_db(
    analysis_db_path,
    wasm_decompile,
    ai_decompile,
    function_name_map_json,
    analysis_summary,
    risk_level,
    functions_json,
    imports_json,
    exports_json,
    memory_usage,
    suspicious,
    security_findings_json=None,
    yara_rule=None,
):
    """Describe  upsert analysis db."""
    conn = sqlite3.connect(analysis_db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM analysis_results LIMIT 1")
        row = cursor.fetchone()
        if row:
            cursor.execute("""
                UPDATE analysis_results SET
                    wasm_decompile = COALESCE(?, wasm_decompile),
                    ai_decompile = COALESCE(?, ai_decompile),
                    function_name_map_json = COALESCE(?, function_name_map_json),
                    analysis_summary = COALESCE(?, analysis_summary),
                    risk_level = COALESCE(?, risk_level),
                    functions_json = COALESCE(?, functions_json),
                    imports_json = COALESCE(?, imports_json),
                    exports_json = COALESCE(?, exports_json),
                    memory_usage = COALESCE(?, memory_usage),
                    suspicious = COALESCE(?, suspicious),
                    security_findings_json = COALESCE(?, security_findings_json),
                    yara_rule = COALESCE(?, yara_rule),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                wasm_decompile,
                ai_decompile,
                function_name_map_json,
                analysis_summary,
                risk_level,
                functions_json,
                imports_json,
                exports_json,
                memory_usage,
                (1 if suspicious else 0) if suspicious is not None else None,
                security_findings_json,
                yara_rule,
                row[0]
            ))
        else:
            cursor.execute("""
                INSERT INTO analysis_results
                (wasm_decompile, ai_decompile, function_name_map_json, analysis_summary, risk_level,
                 functions_json, imports_json, exports_json, memory_usage, suspicious,
                 security_findings_json, yara_rule)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                wasm_decompile,
                ai_decompile,
                function_name_map_json,
                analysis_summary,
                risk_level or "Unknown",
                functions_json,
                imports_json,
                exports_json,
                memory_usage,
                1 if suspicious else 0,
                security_findings_json,
                yara_rule
            ))
        conn.commit()
    finally:
        conn.close()


def _load_analysis_db(analysis_db_path):
    """Describe  load analysis db."""
    if not os.path.exists(analysis_db_path):
        return None
    conn = sqlite3.connect(analysis_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analysis_results LIMIT 1")
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _delete_investigation_record(cursor, investigation_id):
    """Delete investigation and related records when analysis DB is missing/corrupt."""

    cursor.execute(
        "DELETE FROM processing_queue WHERE investigation_id = ?", (investigation_id,))

    cursor.execute(
        "DELETE FROM analysis_results WHERE investigation_id = ?", (investigation_id,))

    cursor.execute("DELETE FROM investigations WHERE id = ?",
                   (investigation_id,))


def create_analysis_result(
    investigation_id,
    wasm_decompile=None,
    ai_decompile=None,
    function_name_map=None,
    analysis_summary=None,
    risk_level=None,
    functions=None,
    imports=None,
    exports=None,
    memory_usage=None,
    suspicious=None,
    security_findings_json=None,
    yara_rule=None,
):
    """Create or update analysis results for an investigation.

    Heavy fields are stored in a per-investigation SQLite DB. The main DB only
    stores metadata and the filename pointing to the analysis DB.
    """
    analysis_db_filename = f"analysis_{investigation_id}.db"
    analysis_db_path = _get_analysis_db_path(analysis_db_filename)
    _ensure_analysis_db(analysis_db_path)

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM analysis_results WHERE investigation_id = ?",
            (investigation_id,)
        )
        existing = cursor.fetchone()

        suspicious_value = None if suspicious is None else (
            1 if suspicious else 0)

        if existing:

            cursor.execute("""
                UPDATE analysis_results SET
                    analysis_summary = COALESCE(?, analysis_summary),
                    risk_level = COALESCE(?, risk_level),
                    memory_usage = COALESCE(?, memory_usage),
                    suspicious = COALESCE(?, suspicious)
                WHERE investigation_id = ?
            """, (
                analysis_summary,
                risk_level,
                memory_usage,
                suspicious_value,
                investigation_id
            ))
            analysis_id = existing["id"]
        else:

            cursor.execute("""
                INSERT INTO analysis_results
                (investigation_id, analysis_summary,
                 risk_level, memory_usage, suspicious)
                VALUES (?, ?, ?, ?, ?)
            """, (
                investigation_id,
                analysis_summary,
                risk_level or "Unknown",
                memory_usage,
                suspicious_value or 0
            ))
            analysis_id = cursor.lastrowid

        conn.commit()

    functions_json = json.dumps(functions) if functions is not None else None
    imports_json = json.dumps(imports) if imports is not None else None
    exports_json = json.dumps(exports) if exports is not None else None
    function_name_map_json = json.dumps(
        function_name_map) if function_name_map is not None else None

    _upsert_analysis_db(
        analysis_db_path,
        wasm_decompile,
        ai_decompile,
        function_name_map_json,
        analysis_summary,
        risk_level,
        functions_json,
        imports_json,
        exports_json,
        memory_usage,
        suspicious,
        security_findings_json=security_findings_json,
        yara_rule=yara_rule,
    )

    return analysis_id


def get_analysis_by_hash(sha256_hash):
    """Get full analysis data by SHA256 hash."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.id as investigationId, i.sha256_hash as hash, i.sample_name as sampleName,
                   i.status, i.result,
                   i.md5_hash, i.sha1_hash, i.file_size, i.file_type, i.file_path,
                   i.hashes_json, i.strings_json,
                   i.investigation_type, i.parent_investigation_id, i.source,
                   a.analysis_summary, a.risk_level as riskLevel,
                   a.memory_usage as memoryUsage, a.suspicious
            FROM investigations i
            LEFT JOIN analysis_results a ON i.id = a.investigation_id
            WHERE i.sha256_hash = ?
            ORDER BY i.id DESC
            LIMIT 1
        """, (sha256_hash,))
        row = cursor.fetchone()

        if not row:
            return None

        result = dict(row)

        analysis_data = None
        analysis_db_filename = f"analysis_{result['investigationId']}.db"
        analysis_db_path = _get_analysis_db_path(analysis_db_filename)
        if os.path.exists(analysis_db_path):
            try:
                analysis_data = _load_analysis_db(analysis_db_path)
            except sqlite3.DatabaseError:
                analysis_data = None

        if analysis_data is None:

            try:
                cursor.execute("""
                    SELECT wasm_decompile, ai_decompile, function_name_map_json, analysis_summary,
                           risk_level, functions_json, imports_json, exports_json,
                           memory_usage, suspicious
                    FROM analysis_results
                    WHERE investigation_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                """, (result["investigationId"],))
                legacy_row = cursor.fetchone()
                if legacy_row:
                    analysis_data = dict(legacy_row)
            except sqlite3.OperationalError:
                analysis_data = None

        if analysis_data is None:
            analysis_data = {
                "wasm_decompile": None,
                "ai_decompile": None,
                "function_name_map_json": None,
                "functions_json": "[]",
                "imports_json": "[]",
                "exports_json": "[]",
                "analysis_summary": None,
                "risk_level": None,
                "memory_usage": None,
                "suspicious": 0,
                "security_findings_json": "[]",
                "yara_rule": None
            }

        functions = json.loads(analysis_data.get("functions_json") or "[]")
        imports = json.loads(analysis_data.get("imports_json") or "[]")
        exports = json.loads(analysis_data.get("exports_json") or "[]")
        suspicious = bool(analysis_data.get("suspicious"))
        security_findings = json.loads(
            analysis_data.get("security_findings_json") or "[]")
        function_map_json = analysis_data.get("function_name_map_json")
        function_map = None
        if function_map_json:
            try:
                parsed_map = json.loads(function_map_json)
                if isinstance(parsed_map, list):
                    function_map = parsed_map
            except Exception:
                function_map = None

        summary = result.get("analysis_summary") or analysis_data.get(
            "analysis_summary")
        risk_level = result.get("riskLevel") or analysis_data.get("risk_level")
        memory_usage = result.get(
            "memoryUsage") or analysis_data.get("memory_usage")

        investigation_type = result.get("investigation_type") or "file"
        parent_id = result.get("parent_investigation_id")

        if investigation_type == "url" and not parent_id:
            dyn = get_dynamic_results(result["investigationId"])
            threat_intel = get_url_threat_intel(result["investigationId"])
            return {
                "investigationId": result["investigationId"],
                "type": "url",
                "hash": result["hash"],
                "sampleName": result["sampleName"],
                "investigationType": investigation_type,
                "children": get_children_for_parent(result["investigationId"]),
                "dynamic": dyn,
                "threatIntel": threat_intel if threat_intel is not None else [],
            }

        file_info = {
            "name": result.get("sampleName") or "Unknown",
            "size": result.get("file_size"),
            "size_formatted": _format_file_size(result.get("file_size")),
            "type": result.get("file_type") or "Unknown"
        }
        base_hashes = {
            "md5": result.get("md5_hash"),
            "sha1": result.get("sha1_hash"),
            "sha256": result.get("hash")
        }
        stored_hashes = result.get("hashes_json")
        if stored_hashes:
            try:
                hashes = json.loads(stored_hashes)
            except Exception:
                hashes = base_hashes
        else:
            hashes = base_hashes

        stored_strings = result.get("strings_json")
        if stored_strings:
            try:
                strings = json.loads(stored_strings)
            except Exception:
                strings = []
        else:
            strings = []

        result_obj = {
            "investigationId": result["investigationId"],
            "hash": result["hash"],
            "sampleName": result["sampleName"],
            "wasmDecompile": analysis_data.get("wasm_decompile") or "// Pending analysis...",
            "aiDecompile": analysis_data.get("ai_decompile") or "// Pending AI-enhanced decompilation...",
            "securityFindings": security_findings,
            "fileInfo": file_info,
            "hashes": hashes,
            "strings": strings,
            "analysis": {
                "summary": summary or "Analysis pending...",
                "riskLevel": risk_level or "Unknown",
                "functions": functions,
                "imports": imports,
                "exports": exports,
                "memoryUsage": memory_usage or "Unknown",
                "suspicious": suspicious,
                "yaraRule": analysis_data.get("yara_rule")
            },
            "parentId": parent_id,
        }

        if function_map is None:
            function_map = _load_function_map_legacy_file(result["investigationId"])
        if function_map is not None:
            result_obj["functionMap"] = function_map

        if parent_id:
            parent = get_investigation_by_id(parent_id)
            if parent:
                result_obj["parent"] = {
                    "id": parent_id,
                    "url": parent.get("source") or parent.get("sample_name"),
                }
            dyn = get_dynamic_results(parent_id)
            if dyn is not None:
                result_obj["dynamic"] = _filter_dynamic_results_for_child(
                    dyn,
                    wasm_filename=result.get("sampleName"),
                    wasm_url=result.get("source"),
                )
            threat_intel = get_url_threat_intel(parent_id)
            if threat_intel is not None:
                result_obj["threatIntel"] = threat_intel
        else:

            dyn = get_dynamic_results(result["investigationId"])
            if dyn is not None:
                result_obj["dynamic"] = dyn
            threat_intel = get_url_threat_intel(result["investigationId"])
            if threat_intel is not None:
                result_obj["threatIntel"] = threat_intel
        return result_obj


def get_analysis_by_id(investigation_id):
    """Get full analysis data by investigation id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT i.id as investigationId, i.sha256_hash as hash, i.sample_name as sampleName,
                   i.status, i.result,
                   i.md5_hash, i.sha1_hash, i.file_size, i.file_type, i.file_path,
                   i.hashes_json, i.strings_json,
                   i.investigation_type, i.parent_investigation_id, i.source,
                   a.analysis_summary, a.risk_level as riskLevel,
                   a.memory_usage as memoryUsage, a.suspicious
            FROM investigations i
            LEFT JOIN analysis_results a ON i.id = a.investigation_id
            WHERE i.id = ?
        """, (investigation_id,))
        row = cursor.fetchone()

        if not row:
            return None

        result = dict(row)
        analysis_data = None
        analysis_db_filename = f"analysis_{result['investigationId']}.db"
        analysis_db_path = _get_analysis_db_path(analysis_db_filename)
        if os.path.exists(analysis_db_path):
            try:
                analysis_data = _load_analysis_db(analysis_db_path)
            except sqlite3.DatabaseError:
                analysis_data = None

        if analysis_data is None:
            try:
                cursor.execute("""
                    SELECT wasm_decompile, ai_decompile, function_name_map_json, analysis_summary,
                           risk_level, functions_json, imports_json, exports_json,
                           memory_usage, suspicious
                    FROM analysis_results
                    WHERE investigation_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                """, (result["investigationId"],))
                legacy_row = cursor.fetchone()
                if legacy_row:
                    analysis_data = dict(legacy_row)
            except sqlite3.OperationalError:
                analysis_data = None

        if analysis_data is None:
            analysis_data = {
                "wasm_decompile": None,
                "ai_decompile": None,
                "function_name_map_json": None,
                "functions_json": "[]",
                "imports_json": "[]",
                "exports_json": "[]",
                "analysis_summary": None,
                "risk_level": None,
                "memory_usage": None,
                "suspicious": 0,
                "security_findings_json": "[]",
                "yara_rule": None
            }

        functions = json.loads(analysis_data.get("functions_json") or "[]")
        imports = json.loads(analysis_data.get("imports_json") or "[]")
        exports = json.loads(analysis_data.get("exports_json") or "[]")
        suspicious = bool(analysis_data.get("suspicious"))
        security_findings = json.loads(
            analysis_data.get("security_findings_json") or "[]")
        function_map_json = analysis_data.get("function_name_map_json")
        function_map = None
        if function_map_json:
            try:
                parsed_map = json.loads(function_map_json)
                if isinstance(parsed_map, list):
                    function_map = parsed_map
            except Exception:
                function_map = None

        summary = result.get("analysis_summary") or analysis_data.get(
            "analysis_summary")
        risk_level = result.get("riskLevel") or analysis_data.get("risk_level")
        memory_usage = result.get(
            "memoryUsage") or analysis_data.get("memory_usage")

        investigation_type = result.get("investigation_type") or "file"
        parent_id = result.get("parent_investigation_id")

        if investigation_type == "url" and not parent_id:
            dyn = get_dynamic_results(result["investigationId"])
            threat_intel = get_url_threat_intel(result["investigationId"])
            return {
                "investigationId": result["investigationId"],
                "type": "url",
                "hash": result["hash"],
                "sampleName": result["sampleName"],
                "investigationType": investigation_type,
                "children": get_children_for_parent(result["investigationId"]),
                "dynamic": dyn,
                "threatIntel": threat_intel if threat_intel is not None else [],
            }

        file_info = {
            "name": result.get("sampleName") or "Unknown",
            "size": result.get("file_size"),
            "size_formatted": _format_file_size(result.get("file_size")),
            "type": result.get("file_type") or "Unknown"
        }
        base_hashes = {
            "md5": result.get("md5_hash"),
            "sha1": result.get("sha1_hash"),
            "sha256": result.get("hash")
        }
        stored_hashes = result.get("hashes_json")
        if stored_hashes:
            try:
                hashes = json.loads(stored_hashes)
            except Exception:
                hashes = base_hashes
        else:
            hashes = base_hashes

        stored_strings = result.get("strings_json")
        if stored_strings:
            try:
                strings = json.loads(stored_strings)
            except Exception:
                strings = []
        else:
            strings = []

        result_obj = {
            "investigationId": result["investigationId"],
            "hash": result["hash"],
            "sampleName": result["sampleName"],
            "wasmDecompile": analysis_data.get("wasm_decompile") or "// Pending analysis...",
            "aiDecompile": analysis_data.get("ai_decompile") or "// Pending AI-enhanced decompilation...",
            "securityFindings": security_findings,
            "fileInfo": file_info,
            "hashes": hashes,
            "strings": strings,
            "analysis": {
                "summary": summary or "Analysis pending...",
                "riskLevel": risk_level or "Unknown",
                "functions": functions,
                "imports": imports,
                "exports": exports,
                "memoryUsage": memory_usage or "Unknown",
                "suspicious": suspicious,
                "yaraRule": analysis_data.get("yara_rule")
            }
        }

        if function_map is None:
            function_map = _load_function_map_legacy_file(result["investigationId"])
        if function_map is not None:
            result_obj["functionMap"] = function_map

        if parent_id:
            parent = get_investigation_by_id(parent_id)
            if parent:
                result_obj["parent"] = {
                    "id": parent_id,
                    "url": parent.get("source") or parent.get("sample_name"),
                }
            dyn = get_dynamic_results(parent_id)
            if dyn is not None:
                result_obj["dynamic"] = _filter_dynamic_results_for_child(
                    dyn,
                    wasm_filename=result.get("sampleName"),
                    wasm_url=result.get("source"),
                )
            threat_intel = get_url_threat_intel(parent_id)
            if threat_intel is not None:
                result_obj["threatIntel"] = threat_intel
        else:
            dyn = get_dynamic_results(result["investigationId"])
            if dyn is not None:
                result_obj["dynamic"] = dyn
            threat_intel = get_url_threat_intel(result["investigationId"])
            if threat_intel is not None:
                result_obj["threatIntel"] = threat_intel
        return result_obj


def save_dynamic_results(investigation_id, data):
    """Persist dynamic analysis JSON for an investigation.
    The procedure normalizes the structure so that the JSON stored matches
    the dynamic analysis payload shape expected by the frontend.

    In particular older instrumentation produced
    ``docker: { stats: { ... , stats: [...] } }`` whereas the UI expects
    ``docker: { stats: [...] }``.  We flatten that nesting here so the
    frontend can consume the data uniformly and tests continue to pass.
    """

    docker = data.get("docker")
    if isinstance(docker, dict):
        stats_obj = docker.get("stats")
        if isinstance(stats_obj, dict) and isinstance(stats_obj.get("stats"), list):

            docker["stats"] = stats_obj["stats"]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        json_str = json.dumps(data)
        cursor.execute(
            "SELECT investigation_id FROM dynamic_results WHERE investigation_id = ?", (investigation_id,))
        if cursor.fetchone():
            cursor.execute(
                "UPDATE dynamic_results SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE investigation_id = ?",
                (json_str, investigation_id)
            )
        else:
            cursor.execute(
                "INSERT INTO dynamic_results (investigation_id, data) VALUES (?, ?)",
                (investigation_id, json_str)
            )
        conn.commit()


def get_dynamic_results(investigation_id):
    """Retrieve dynamic analysis JSON for a given investigation id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT data FROM dynamic_results WHERE investigation_id = ?", (investigation_id,))
        row = cursor.fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None


def save_trace_viewer_payload(investigation_id, payload):
    """Save processed trace-viewer payload JSON for a given investigation id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        json_str = json.dumps(payload)
        cursor.execute(
            "SELECT investigation_id FROM dynamic_results WHERE investigation_id = ?",
            (investigation_id,)
        )
        if cursor.fetchone():
            cursor.execute(
                "UPDATE dynamic_results SET trace_viewer = ?, updated_at = CURRENT_TIMESTAMP WHERE investigation_id = ?",
                (json_str, investigation_id)
            )
        else:
            cursor.execute(
                "INSERT INTO dynamic_results (investigation_id, trace_viewer) VALUES (?, ?)",
                (investigation_id, json_str)
            )
        conn.commit()


def get_trace_viewer_payload(investigation_id):
    """Retrieve stored trace-viewer payload for a given investigation id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT trace_viewer FROM dynamic_results WHERE investigation_id = ?", (investigation_id,))
        row = cursor.fetchone()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None


def save_url_threat_intel(investigation_id, intel_data):
    """Save URL threat intelligence as cached JSON"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        json_str = json.dumps(intel_data)
        cursor.execute(
            "SELECT investigation_id FROM dynamic_results WHERE investigation_id = ?",
            (investigation_id,)
        )
        if cursor.fetchone():
            cursor.execute(
                "UPDATE dynamic_results SET url_threat_intelligence = ?, updated_at = CURRENT_TIMESTAMP WHERE investigation_id = ?",
                (json_str, investigation_id)
            )
        else:
            cursor.execute(
                "INSERT INTO dynamic_results (investigation_id, url_threat_intelligence) VALUES (?, ?)",
                (investigation_id, json_str)
            )
        conn.commit()


def get_url_threat_intel(investigation_id):
    """Retrieve cached URL threat intelligence JSON for a given investigation id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url_threat_intelligence FROM dynamic_results WHERE investigation_id = ?", (investigation_id,))
        row = cursor.fetchone()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None


def _filter_dynamic_results_for_child(
    dynamic_data,
    wasm_filename,
    wasm_url,
):
    """Filter a parent dynamic report to the run for a specific WASM."""
    if not isinstance(dynamic_data, dict):
        return dynamic_data

    target_url = (wasm_url or "").strip()
    target_name = (wasm_filename or "").strip()

    def _run_matches(run):
        """Describe  run matches."""
        if not isinstance(run, dict):
            return False
        run_url = (run.get("targetWasmUrl") or "").strip()
        run_name = (run.get("wasmFileName") or "").strip()
        if target_url and run_url and (run_url == target_url or run_url.endswith(target_url) or target_url.endswith(run_url)):
            return True
        if target_name and run_name:
            tn = os.path.basename(target_name).lower()
            rn = os.path.basename(run_name).lower()
            if rn == tn or rn.endswith(tn) or tn.endswith(rn):
                return True
            if rn in tn or tn in rn:
                return True
        return False

    filtered = dict(dynamic_data)
    runs = dynamic_data.get("runs")
    if isinstance(runs, list):
        filtered_runs = [r for r in runs if _run_matches(r)]
    else:
        filtered_runs = []
    filtered["runs"] = filtered_runs

    network = dynamic_data.get("network")
    if isinstance(network, dict):
        run_indexes = {
            r.get("runIndex")
            for r in filtered_runs
            if isinstance(r, dict) and isinstance(r.get("runIndex"), int)
        }
        by_run = network.get("byRun") if isinstance(
            network.get("byRun"), list) else []

        matched_by_run = []
        if by_run:
            for run in by_run:
                if not isinstance(run, dict):
                    continue
                idx = run.get("runIndex")
                run_url = (run.get("targetWasmUrl") or "").strip()
                run_name = (run.get("wasmFileName") or "").strip()
                name_match = False
                if target_name and run_name:
                    tn = os.path.basename(target_name).lower()
                    rn = os.path.basename(run_name).lower()
                    name_match = rn == tn or rn.endswith(
                        tn) or tn.endswith(rn) or rn in tn or tn in rn
                url_match = bool(target_url and run_url and (
                    run_url == target_url or run_url.endswith(target_url) or target_url.endswith(run_url)))
                if (isinstance(idx, int) and idx in run_indexes) or name_match or url_match:
                    matched_by_run.append(run)

        if matched_by_run:
            requests = []
            responses = []
            for run in matched_by_run:
                rqs = run.get("requests") if isinstance(
                    run.get("requests"), list) else []
                rps = run.get("responses") if isinstance(
                    run.get("responses"), list) else []
                requests.extend(rqs)
                responses.extend(rps)
            network_filtered = dict(network)
            network_filtered["requests"] = requests
            network_filtered["responses"] = responses
            network_filtered["byRun"] = matched_by_run
            filtered["network"] = network_filtered
            return filtered

        requests = network.get("requests") or []
        responses = network.get("responses") or []

        def _entry_matches(entry):
            """Describe  entry matches."""
            if not isinstance(entry, dict):
                return False
            url = (entry.get("url") or "").strip()
            if target_url and url and (url == target_url or url.endswith(target_url) or target_url.endswith(url)):
                return True
            if target_name and url and (url.endswith(target_name) or target_name in url):
                return True
            return False

        if isinstance(requests, list):
            requests = [r for r in requests if _entry_matches(r)]
        if isinstance(responses, list):
            responses = [r for r in responses if _entry_matches(r)]
        network_filtered = dict(network)
        network_filtered["requests"] = requests
        network_filtered["responses"] = responses
        filtered["network"] = network_filtered

    return filtered


def get_analysis_by_investigation_id(investigation_id):
    """Return analysis metadata and summary for a given investigation id.

    This mirrors the structure returned by `get_analysis_by_hash` but looks
    up data by `investigation_id`. It will load the per-investigation analysis
    DB if present (analysis_{investigation_id}.db) and return the same
    frontend-shaped dictionary.
    """
    analysis_db_filename = f"analysis_{investigation_id}.db"
    analysis_db_path = _get_analysis_db_path(analysis_db_filename)

    analysis_data = None
    if os.path.exists(analysis_db_path):
        try:
            analysis_data = _load_analysis_db(analysis_db_path)
        except sqlite3.DatabaseError:
            analysis_data = None

    if analysis_data is None:

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT wasm_decompile, ai_decompile, function_name_map_json, analysis_summary,
                           risk_level, functions_json, imports_json, exports_json,
                           memory_usage, suspicious, security_findings_json
                    FROM analysis_results
                    WHERE investigation_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                """, (investigation_id,))
                row = cursor.fetchone()
                if row:
                    analysis_data = dict(row)
            except sqlite3.OperationalError:
                analysis_data = None

    if analysis_data is None:
        analysis_data = {
            "wasm_decompile": None,
            "ai_decompile": None,
            "function_name_map_json": None,
            "functions_json": "[]",
            "imports_json": "[]",
            "exports_json": "[]",
            "analysis_summary": None,
            "risk_level": None,
            "memory_usage": None,
            "suspicious": 0,
            "security_findings_json": "[]",
            "yara_rule": None
        }

    functions = json.loads(analysis_data.get("functions_json") or "[]")
    imports = json.loads(analysis_data.get("imports_json") or "[]")
    exports = json.loads(analysis_data.get("exports_json") or "[]")
    suspicious = bool(analysis_data.get("suspicious"))
    security_findings = json.loads(
        analysis_data.get("security_findings_json") or "[]")
    function_map_json = analysis_data.get("function_name_map_json")
    function_map = None
    if function_map_json:
        try:
            parsed_map = json.loads(function_map_json)
            if isinstance(parsed_map, list):
                function_map = parsed_map
        except Exception:
            function_map = None

    result_obj = {
        "wasmDecompile": analysis_data.get("wasm_decompile") or "// Pending analysis...",
        "aiDecompile": analysis_data.get("ai_decompile") or "// Pending AI-enhanced decompilation...",
        "securityFindings": security_findings,
        "analysis": {
            "summary": analysis_data.get("analysis_summary") or "Analysis pending...",
            "riskLevel": analysis_data.get("risk_level") or "Unknown",
            "functions": functions,
            "imports": imports,
            "exports": exports,
            "memoryUsage": analysis_data.get("memory_usage") or "Unknown",
            "suspicious": suspicious,
            "yaraRule": analysis_data.get("yara_rule")
        }
    }
    if function_map is None:
        function_map = _load_function_map_legacy_file(investigation_id)
    if function_map is not None:
        result_obj["functionMap"] = function_map

    dyn = get_dynamic_results(investigation_id)
    if dyn is not None:
        result_obj["dynamic"] = dyn
    threat_intel = get_url_threat_intel(investigation_id)
    if threat_intel is not None:
        result_obj["threatIntel"] = threat_intel
    return result_obj


def add_to_queue(investigation_id, priority=0):
    """Add an investigation to the processing queue."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO processing_queue (investigation_id, priority)
            VALUES (?, ?)
        """, (investigation_id, priority))
        conn.commit()
        return cursor.lastrowid


def get_next_in_queue():
    """Get the next pending item from the queue."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pq.*, i.file_path, i.sample_name, i.sha256_hash, i.investigation_type, i.source
            FROM processing_queue pq
            JOIN investigations i ON pq.investigation_id = i.id
            WHERE pq.stage = 'pending'
            ORDER BY pq.priority DESC, pq.created_at ASC
            LIMIT 1
        """)
        row = cursor.fetchone()
        return dict(row) if row else None


def update_queue_stage(queue_id, stage, error_message=None):
    """Update queue item stage. For completed/failed, removes item from queue."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if stage == "processing":
            cursor.execute("""
                UPDATE processing_queue
                SET stage = ?, started_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (stage, queue_id))
        elif stage in ("completed", "failed"):

            cursor.execute("""
                UPDATE processing_queue
                SET stage = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (stage, error_message, queue_id))

            cursor.execute(
                "DELETE FROM processing_queue WHERE id = ?", (queue_id,))
        else:
            cursor.execute("""
                UPDATE processing_queue SET stage = ? WHERE id = ?
            """, (stage, queue_id))
        conn.commit()


def get_queue_status():
    """Get current queue status."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT i.sample_name, pq.stage, pq.started_at
            FROM processing_queue pq
            JOIN investigations i ON pq.investigation_id = i.id
            WHERE pq.stage = 'processing'
            ORDER BY pq.started_at DESC
            LIMIT 1
        """)
        current = cursor.fetchone()

        cursor.execute("""
            SELECT i.sample_name
            FROM processing_queue pq
            JOIN investigations i ON pq.investigation_id = i.id
            WHERE pq.stage = 'pending'
            ORDER BY pq.priority DESC, pq.created_at ASC
        """)
        queued = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT sample_name
            FROM investigations
            WHERE status = 'completed'
            ORDER BY updated_at DESC
            LIMIT 10
        """)
        completed = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT sample_name, result
            FROM investigations
            WHERE status = 'failed'
            ORDER BY updated_at DESC
            LIMIT 10
        """)
        failed = [dict(row) for row in cursor.fetchall()]

        return {
            "current": dict(current) if current else None,
            "queue": queued,
            "completed": completed,
            "failed": failed
        }
