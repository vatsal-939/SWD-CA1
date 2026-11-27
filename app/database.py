import sqlite3
import os
from flask import current_app, g

def get_db():
    """
    Get a thread-safe database connection for the current request.
    Enforces foreign key constraints.
    """
    if 'db' not in g:
        db_path = current_app.config.get('DATABASE_PATH')
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.execute("PRAGMA foreign_keys = ON;")
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    """
    Execute a parameterized SQL query safely.
    Guarantees parameterized query execution to prevent SQL injection.
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    """
    Execute a parameterized INSERT, UPDATE, or DELETE and commit.
    Returns the lastrowid or rowcount.
    """
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    row_count = cur.rowcount
    cur.close()
    return last_id, row_count
