import sqlite3
import os

# Path to SQLite database file
DB_PATH = "sbom.db"

# Get a database connection
def get_connection():
    return sqlite3.connect(DB_PATH)

# Initialize database tables
def init_db():
    conn = get_connection()
    cur = conn.cursor()

    # Table for SBOM documents
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        raw_json TEXT
    )
    """)

    # Table for packages/components
    cur.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER,
        name TEXT,
        version TEXT,
        license TEXT,
        FOREIGN KEY(document_id) REFERENCES documents(id)
    )
    """)

    conn.commit()
    conn.close()

# Insert a new document and return its ID
def insert_document(name, raw_json):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO documents (name, raw_json) VALUES (?, ?)",
        (name, raw_json)
    )
    document_id = cur.lastrowid

    conn.commit()
    conn.close()
    return document_id

# Insert a new package/component
def insert_package(document_id, name, version, license):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO packages (document_id, name, version, license) VALUES (?, ?, ?, ?)",
        (document_id, name, version, license)
    )

    conn.commit()
    conn.close()

# Query by component name, optionally filtered by version
def query_by_component(name, version=None):
    conn = get_connection()
    cur = conn.cursor()

    if version:
        cur.execute("""
            SELECT d.name, p.name, p.version, p.license
            FROM packages p
            JOIN documents d ON d.id = p.document_id
            WHERE p.name = ? AND p.version = ?
        """, (name, version))
    else:
        cur.execute("""
            SELECT d.name, p.name, p.version, p.license
            FROM packages p
            JOIN documents d ON d.id = p.document_id
            WHERE p.name = ?
        """, (name,))

    results = cur.fetchall()
    conn.close()
    return results

# Query by license
def query_by_license(license):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT d.name, p.name, p.version, p.license
        FROM packages p
        JOIN documents d ON d.id = p.document_id
        WHERE p.license = ?
    """, (license,))

    results = cur.fetchall()
    conn.close()
    return results
