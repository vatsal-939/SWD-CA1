import pytest
import os
import tempfile
from app import create_app
from config import TestingConfig
from init_db import get_db_connection, create_schema, seed_database

@pytest.fixture
def app():
    """Create and configure a clean testing app instance with a temporary database."""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    
    class CustomTestingConfig(TestingConfig):
        DATABASE_PATH = db_path
        WTF_CSRF_ENABLED = False  # Allows direct POST testing without parsing csrf tokens

    # Initialize schema and seed data
    conn = get_db_connection(db_path)
    create_schema(conn)
    seed_database(conn)
    conn.close()

    app = create_app(CustomTestingConfig)

    yield app

    os.close(db_fd)
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()
