# auth.py
import bcrypt
from db import DatabaseManager

class UserManager:
    """
    Manages user authentication and role-based access control.
    """
    def __init__(self):
        self.db = DatabaseManager()

    def create_user(self, username, password, role="user"):
        """Creates a new user with hashed password."""
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, password_hash, role))
        print(f"User '{username}' created successfully!")

    def authenticate_user(self, username, password):
        """Verifies user login credentials."""
        user = self.db.fetch_one("SELECT id, password_hash, role FROM users WHERE username = ?", (username,))
        if user and bcrypt.checkpw(password.encode(), user[1].encode()):
            print(f"Authentication successful! Welcome, {username}.")
            return user
        print("Authentication failed! Invalid credentials.")
        return None

    def deactivate_user(self, username):
        """Deactivates a user account."""
        self.db.execute("UPDATE users SET active = 0 WHERE username = ?", (username,))
        print(f"User '{username}' has been deactivated.")
