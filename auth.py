import os
import bcrypt
import time
from db import DatabaseManager
from pathlib import Path

class UserManager:
    """
    Manages user authentication and role-based access control.
    """
    def __init__(self):
        self.db = DatabaseManager()
        self.max_attempts = 3  # Max failed attempts before lockout
        self.lockout_time = 300  # 5 minutes lockout (in seconds)
        self.failed_attempts = {}  # In-memory tracking of failed logins

    def create_user(self, username, password, role="user"):
        """Creates a new user with hashed password. Returns new user ID."""
        if self.get_user(username):
            raise Exception("Username already exists")
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        user_id = self.db.cursor.lastrowid  # <-- Return the newly created user ID
        print(f"User '{username}' created successfully with ID {user_id}!")
        return user_id  # <-- important fix here

    def get_user(self, username):
        """Fetches a user record by username."""
        return self.db.fetch_one("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))

    def is_account_locked(self, username):
        """Checks if an account is locked due to too many failed login attempts."""
        if username in self.failed_attempts:
            attempts, last_attempt = self.failed_attempts[username]
            if attempts >= self.max_attempts:
                time_since_last_attempt = time.time() - last_attempt
                if time_since_last_attempt < self.lockout_time:
                    remaining_time = self.lockout_time - time_since_last_attempt
                    print(f"Account locked due to too many failed attempts. Try again in {int(remaining_time)} seconds.")
                    return True
                else:
                    del self.failed_attempts[username]  # Reset after timeout
        return False

    def authenticate_user(self, username, password):
        """Verifies user login credentials with brute force protection."""
        if self.is_account_locked(username):
            return None  # Prevent login if account is locked

        user = self.get_user(username)
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            print(f"Authentication successful! Welcome, {username}.")
            self.failed_attempts.pop(username, None)  # Reset failed attempts on success
            return user

        # Track failed login attempts
        if username in self.failed_attempts:
            attempts, _ = self.failed_attempts[username]
            self.failed_attempts[username] = (attempts + 1, time.time())
        else:
            self.failed_attempts[username] = (1, time.time())

        remaining_attempts = self.max_attempts - self.failed_attempts[username][0]
        print(f"Authentication failed! Invalid credentials. {remaining_attempts} attempts remaining.")

        return None

    def delete_user(self, user_id, admin_id, delete_files=True):
        """
        Deletes a user and optionally deletes or reassigns their files.
        """
        if delete_files:
            artifacts = self.db.fetch_all("SELECT file_path FROM artifacts WHERE owner_id = ?", (user_id,))
            for art in artifacts:
                file_path = art[0]
                if os.path.exists(file_path):
                    os.remove(file_path)
            self.db.execute("DELETE FROM artifacts WHERE owner_id = ?", (user_id,))
        else:
            self.db.execute("UPDATE artifacts SET owner_id = ? WHERE owner_id = ?", (admin_id, user_id))

        self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        print(f"User {user_id} deleted successfully.")
    
    def list_users(self):
        """Returns all users from the database."""
        return self.db.fetch_all("SELECT id, username, password_hash, role FROM users")

    def change_password(self, user_id, new_password):
        """Changes user's password."""
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        self.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        print("Password updated successfully.")