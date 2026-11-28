"""
MedVault - Database Initialization & Seed Script
Creates tables with strict constraints, foreign keys, and indexes.
Seeds default demonstration accounts with pre-hashed credentials.
"""

import sqlite3
import os
import bcrypt
from datetime import datetime

DATABASE_NAME = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "medvault.db"))


def get_db_connection(db_path=DATABASE_NAME):
    """Establish connection and enforce foreign key constraints."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, rounds: int = 12) -> str:
    """Hash password using bcrypt with configurable work factor."""
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def create_schema(conn):
    """Create normalized relational tables."""
    cursor = conn.cursor()

    # 1. Users table (Strict RBAC, lockout protection)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'doctor', 'patient')),
        full_name TEXT NOT NULL,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        lockout_until TEXT DEFAULT NULL,
        created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP)
    );
    """)

    # 2. Medical Records table (Sensitive CRUD entity)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medical_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL,
        diagnosis TEXT NOT NULL,
        treatment_notes TEXT NOT NULL,
        prescription TEXT NOT NULL,
        is_deleted INTEGER NOT NULL DEFAULT 0,
        record_date TEXT NOT NULL DEFAULT (CURRENT_DATE),
        created_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
        updated_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
        FOREIGN KEY (patient_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (doctor_id) REFERENCES users(id) ON DELETE RESTRICT
    );
    """)

    # 3. Security Audit Logs table (Immutable security trail)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER DEFAULT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILURE', 'WARNING', 'BLOCKED')),
        timestamp TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    # Indexes for performance and quick security audit lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_records_patient ON medical_records(patient_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")

    conn.commit()


def seed_database(conn, rounds: int = 12):
    """Seed initial demonstration accounts and sample medical records."""
    cursor = conn.cursor()

    # Verify if users already exist
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] > 0:
        print("[*] Database already populated. Skipping seed.")
        return

    print(f"[*] Seeding default demonstration accounts with bcrypt hashes (work factor {rounds})...")

    default_users = [
        ("admin", "admin@medvault.local", hash_password("AdminPass123!@#", rounds=rounds), "admin", "System Administrator"),
        ("dr_smith", "dr.smith@medvault.local", hash_password("DoctorPass123!@#", rounds=rounds), "doctor", "Dr. Alice Smith, MD"),
        ("dr_patel", "dr.patel@medvault.local", hash_password("DoctorPass123!@#", rounds=rounds), "doctor", "Dr. Rajesh Patel, MD"),
        ("john_doe", "john.doe@example.com", hash_password("PatientPass123!@#", rounds=rounds), "patient", "Johnathan Doe"),
        ("jane_roe", "jane.roe@example.com", hash_password("PatientPass123!@#", rounds=rounds), "patient", "Jane Roe"),
    ]

    cursor.executemany("""
    INSERT INTO users (username, email, password_hash, role, full_name)
    VALUES (?, ?, ?, ?, ?);
    """, default_users)

    # Retrieve patient and doctor IDs
    cursor.execute("SELECT id FROM users WHERE username = 'john_doe'")
    john_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM users WHERE username = 'jane_roe'")
    jane_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM users WHERE username = 'dr_smith'")
    dr_smith_id = cursor.fetchone()[0]

    default_records = [
        (
            john_id,
            dr_smith_id,
            "Hypertension (Stage 1)",
            "Blood pressure reading 138/88 mmHg. Advised low-sodium diet, regular aerobic exercise, and stress reduction.",
            "Lisinopril 10mg orally once daily.",
            "2026-11-15"
        ),
        (
            jane_id,
            dr_smith_id,
            "Seasonal Allergic Rhinitis",
            "Patient reports nasal congestion and sneezing. Lungs clear, no signs of bacterial infection.",
            "Cetirizine 10mg once daily as needed; Fluticasone propionate nasal spray.",
            "2026-11-20"
        ),
    ]

    cursor.executemany("""
    INSERT INTO medical_records (patient_id, doctor_id, diagnosis, treatment_notes, prescription, record_date)
    VALUES (?, ?, ?, ?, ?, ?);
    """, default_records)

    # Add initial audit log entries
    cursor.execute("""
    INSERT INTO audit_logs (user_id, action, details, ip_address, status)
    VALUES (1, 'SYSTEM_INIT', 'Database schema initialized and seed records inserted.', '127.0.0.1', 'SUCCESS');
    """)

    conn.commit()
    print("[+] Database successfully initialized and seeded.")


if __name__ == "__main__":
    connection = get_db_connection()
    create_schema(connection)
    seed_database(connection)
    connection.close()
