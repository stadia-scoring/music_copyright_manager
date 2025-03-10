# db.py
import sqlite3
from pathlib import Path

DB_FILE = Path("database.sqlite")

class DatabaseManager:
    """
    Handles database connection and setup for the application.
    Implements Singleton pattern to ensure only one connection exists.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance.connection = sqlite3.connect(DB_FILE)
            cls._instance.cursor = cls._instance.connection.cursor()
            cls._instance.setup_tables()
        return cls._instance

    def setup_tables(self):
        """Creates necessary tables if they do not exist."""
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT UNIQUE NOT NULL,
                                password_hash TEXT NOT NULL,
                                role TEXT CHECK(role IN ("user", "admin")) NOT NULL,
                                active INTEGER DEFAULT 1)''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS artifacts (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                owner_id INTEGER NOT NULL,
                                title TEXT NOT NULL,
                                file_path TEXT NOT NULL,
                                checksum TEXT NOT NULL,
                                encryption_key TEXT NOT NULL,
                                created_at TEXT NOT NULL,
                                updated_at TEXT NOT NULL,
                                FOREIGN KEY(owner_id) REFERENCES users(id))''')

        self.cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                action TEXT NOT NULL,
                                resource_id INTEGER,
                                success INTEGER NOT NULL,
                                details TEXT,
                                timestamp TEXT NOT NULL,
                                FOREIGN KEY(user_id) REFERENCES users(id))''')

        self.connection.commit()

    def execute(self, query, params=()):
        """Executes a query with optional parameters."""
        self.cursor.execute(query, params)
        self.connection.commit()
        return self.cursor

    def fetch_all(self, query, params=()):
        """Fetches all results for a query."""
        self.cursor.execute(query, params)
        return self.cursor.fetchall()

    def fetch_one(self, query, params=()):
        """Fetches a single result for a query."""
        self.cursor.execute(query, params)
        return self.cursor.fetchone()

    def close(self):
        """Closes the database connection."""
        self.connection.close()