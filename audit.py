# audit.py
import datetime
from db import DatabaseManager

class AuditLogger:
    """
    Handles audit logging for user and file-related actions.
    """
    def __init__(self):
        self.db = DatabaseManager()

    def log_event(self, user_id, action, resource_id=None, success=True, details=""):
        """Logs an event in the audit log."""
        timestamp = datetime.datetime.utcnow().isoformat()
        self.db.execute("""INSERT INTO audit_logs (user_id, action, resource_id, success, details, timestamp)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (user_id, action, resource_id, int(success), details, timestamp))
        print(f"Audit log recorded: {action} by user {user_id}.")

    def get_security_logs(self):
        """Returns logs considered as security logs."""
        return self.db.fetch_all(
            "SELECT * FROM audit_logs WHERE action IN ('login_failure', 'error', 'invalid_option') "
            "OR (action='retrieve_file' AND success=0) OR (action='delete_file' AND success=0)"
        )

    def get_access_logs(self):
        """Returns logs considered as access logs (login successes, logout, password change)."""
        return self.db.fetch_all(
            "SELECT * FROM audit_logs WHERE action IN ('login_success', 'logout', 'password_change')"
        )

    def get_event_logs(self):
        """Returns logs considered as event logs (store_file, retrieve_file, delete_file, create_user, etc.)."""
        return self.db.fetch_all(
            "SELECT * FROM audit_logs WHERE action IN ('store_file', 'retrieve_file', 'delete_file', 'create_user', 'list_users', 'list_files', 'encrypt_file', 'decrypt_file', 'check_integrity') AND success=1"
        )
    
    def get_all_logs(self):
        """Returns all audit logs."""
        return self.db.fetch_all("SELECT * FROM audit_logs")
    
    def get_file_audit(self, artifact_id):
        """Returns a trail of all audit log entries for a given artifact (file)."""
        return self.db.fetch_all("SELECT * FROM audit_logs WHERE resource_id = ?", (artifact_id,))

    def get_last_successful_login(self, user_id):
        """
        Returns the timestamp of the last successful login for the user,
        excluding the current login. If not available, returns a default message.
        """
        logs = self.db.fetch_all(
            "SELECT timestamp FROM audit_logs WHERE user_id = ? AND action = 'login_success' ORDER BY timestamp DESC LIMIT 2",
            (user_id,)
        )
        if len(logs) == 2:
            return logs[1][0]  # Second latest is the previous successful login.
        else:
            return "No previous successful login found."

    def get_last_failed_login(self, username):
        """
        Returns the timestamp of the last failed login attempt that mentions the username.
        If not available, returns a default message.
        """
        log = self.db.fetch_one(
            "SELECT timestamp FROM audit_logs WHERE action = 'login_failure' AND details LIKE ? ORDER BY timestamp DESC LIMIT 1",
            (f"%{username}%",)
        )
        if log:
            return log[0]
        else:
            return "No previous failed login found."