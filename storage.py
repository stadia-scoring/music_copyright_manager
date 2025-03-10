# storage.py
import os
import hashlib
import base64
import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from db import DatabaseManager

# Define the storage directory and ensure it exists.
STORAGE_DIR = Path("./storage")
STORAGE_DIR.mkdir(exist_ok=True)

# Define the examples directory where retrieved files will be placed.
EXAMPLES_DIR = Path("./examples")
EXAMPLES_DIR.mkdir(exist_ok=True)

class FileManager:
    """
    Handles file storage, encryption/decryption, integrity checking, and deletion.
    """
    def __init__(self):
        self.db = DatabaseManager()

    def can_modify_file(self, artifact_id, logged_in_user):
        """
        Checks if the logged_in_user has permission to modify the file associated with artifact_id.
        Returns True if the user is the owner or if the user is an admin; otherwise, returns False.
        """
        artifact = self.db.fetch_one("SELECT owner_id FROM artifacts WHERE id = ?", (artifact_id,))
        if not artifact:
            print("Artifact not found.")
            return False
        owner_id = artifact[0]
        if logged_in_user[3] == "admin" or logged_in_user[0] == owner_id:
            return True
        else:
            print("Permission denied: You cannot modify this file.")
            return False

    def verify_artifact(self, artifact_id):
	    """
	    Checks if the file for artifact_id exists on disk and its checksum matches the stored value.
	    If the integrity check fails, prompts the user to continue or abort.
	    """
	    artifact = self.db.fetch_one("SELECT file_path, checksum FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return False
	    
	    file_path, stored_checksum = artifact
	
	    if not os.path.exists(file_path):
	        print(f"File {file_path} does not exist on disk.")
	        user_input = input("Do you want to continue with this action despite the missing file? (yes/no): ").strip().lower()
	        return user_input == "yes"
	
	    with open(file_path, "rb") as f:
	        current_data = f.read()
	        current_checksum = hashlib.sha256(current_data).hexdigest()
	
	    if current_checksum != stored_checksum:
	        print(f"File integrity check failed for {file_path}. Checksum mismatch.")
	        user_input = input("Do you want to continue with this action despite the integrity failure? (yes/no): ").strip().lower()
	        return user_input == "yes"
	
	    return True  # Integrity check passed

    def store_file(self, user_id, file_path, encrypt_choice=True):
        """
        Stores a file.
        - If encrypt_choice is True, encrypts the file and saves it with a ".enc" extension.
        - Otherwise, stores it as-is.
        In both cases, the file is copied to STORAGE_DIR, its checksum computed, and the original file deleted.
        Returns a tuple (encryption_key, artifact_id); encryption_key is None if not encrypted.
        """
        # Only check STORAGE_DIR as managed.
        abs_storage = str(STORAGE_DIR.resolve())
        abs_file = str(Path(file_path).resolve())
        if abs_file.startswith(abs_storage):
            print("Error: Cannot store a file that is already managed by the system.")
            return None

        original_filename = os.path.basename(file_path)
        new_file_name = f"{Path(original_filename).name}.enc" if encrypt_choice else Path(original_filename).name
        new_file_path = STORAGE_DIR / new_file_name

        with open(file_path, "rb") as file:
            original_data = file.read()

        if encrypt_choice:
            key = Fernet.generate_key()
            cipher = Fernet(key)
            stored_data = cipher.encrypt(original_data)
            encoded_key = base64.urlsafe_b64encode(key).decode()
        else:
            stored_data = original_data
            encoded_key = ""

        with open(new_file_path, "wb") as file:
            file.write(stored_data)

        try:
            os.remove(file_path)
            print(f"Original file '{original_filename}' deleted after storing.")
        except Exception as e:
            print(f"Warning: Could not delete original file '{original_filename}': {e}")

        checksum = hashlib.sha256(stored_data).hexdigest()
        timestamp = datetime.datetime.now(datetime.UTC).isoformat()

        self.db.execute(
            """INSERT INTO artifacts (owner_id, title, file_path, checksum, encryption_key, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, new_file_name, str(new_file_path), checksum, encoded_key, timestamp, timestamp)
        )
        artifact_id = self.db.cursor.lastrowid
        print(f"File '{original_filename}' stored as '{new_file_name}' with Artifact ID {artifact_id}.")
        return (key if encrypt_choice else None, artifact_id)

    def retrieve_file(self, artifact_id, logged_in_user):
	    """
	    Retrieves a file based on its artifact ID.
	    Only the owner or an admin can retrieve the file.
	    """
	    if not self.can_modify_file(artifact_id, logged_in_user):
	        return False  # Block unauthorized access
	
	    artifact = self.db.fetch_one("SELECT file_path, encryption_key FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return False
	    file_path, encoded_key = artifact
	
	    with open(file_path, "rb") as f:
	        stored_data = f.read()
	
	    is_encrypted = bool(encoded_key.strip())
	    if is_encrypted:
	        cipher = Fernet(base64.urlsafe_b64decode(encoded_key))
	        decrypted_data = cipher.decrypt(stored_data)
	    else:
	        decrypted_data = stored_data
	
	    output_file_path = EXAMPLES_DIR / os.path.basename(file_path)
	    with open(output_file_path, "wb") as f:
	        f.write(decrypted_data)
	
	    print(f"File retrieved and saved to {output_file_path}.")
	    return True

    def delete_file(self, artifact_id, logged_in_user):
	    """
	    Deletes a file and its database record.
	    Only the owner or an admin can delete the file.
	    """
	    if not self.can_modify_file(artifact_id, logged_in_user):
	        return False  # Block unauthorized access
	
	    artifact = self.db.fetch_one("SELECT file_path FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return False
	
	    file_path = artifact[0]
	    if os.path.exists(file_path):
	        try:
	            os.remove(file_path)
	            print(f"File '{file_path}' deleted from disk.")
	        except Exception as e:
	            print(f"Error deleting file: {e}")
	            return False
	
	    self.db.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
	    print("Artifact record deleted from database.")
	    return True

    def encrypt_file(self, artifact_id, logged_in_user):
	    """
	    Encrypts an unencrypted file for the given artifact.
	    Only the owner or an admin can encrypt the file.
	    """
	    if not self.can_modify_file(artifact_id, logged_in_user):
	        return False  # Block unauthorized access
	
	    artifact = self.db.fetch_one("SELECT file_path, encryption_key FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return False
	
	    file_path, encoded_key = artifact
	    if encoded_key.strip():
	        print("File is already encrypted.")
	        return False
	
	    with open(file_path, "rb") as f:
	        data = f.read()
	
	    key = Fernet.generate_key()
	    cipher = Fernet(key)
	    encrypted_data = cipher.encrypt(data)
	    new_file_name = f"{Path(file_path).name}.enc"  # Extract just the filename and append .enc
	    new_file_path = STORAGE_DIR / new_file_name   # Ensure it's placed correctly in storage
	
	    with open(new_file_path, "wb") as f:
	        f.write(encrypted_data)
	
	    os.remove(file_path)
	
	    new_checksum = hashlib.sha256(encrypted_data).hexdigest()
	    timestamp = datetime.datetime.now(datetime.UTC).isoformat()
	    self.db.execute(
	        "UPDATE artifacts SET file_path = ?, encryption_key = ?, checksum = ?, updated_at = ? WHERE id = ?",
	        (str(new_file_path), base64.urlsafe_b64encode(key).decode(), new_checksum, timestamp, artifact_id)
	    )
	    print(f"File encrypted and updated to '{new_file_name}'.")
	    return True

    def decrypt_file(self, artifact_id, logged_in_user):
	    """
	    Decrypts an encrypted file for the given artifact.
	    Only the owner or an admin can decrypt the file.
	    """
	    if not self.can_modify_file(artifact_id, logged_in_user):
	        return False  # Block unauthorized access
	
	    artifact = self.db.fetch_one("SELECT file_path, encryption_key FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return False
	
	    file_path, encoded_key = artifact
	    if not encoded_key.strip():
	        print("File is not encrypted.")
	        return False
	
	    cipher = Fernet(base64.urlsafe_b64decode(encoded_key))
	    with open(file_path, "rb") as f:
	        encrypted_data = f.read()
	    decrypted_data = cipher.decrypt(encrypted_data)
	    
	    new_file_name = Path(file_path).name.replace(".enc", "")  # Extract filename and remove .enc
	    new_file_path = STORAGE_DIR / new_file_name
	
	    with open(new_file_path, "wb") as f:
	        f.write(decrypted_data)
	
	    os.remove(file_path)
	
	    new_checksum = hashlib.sha256(decrypted_data).hexdigest()
	    timestamp = datetime.datetime.now(datetime.UTC).isoformat()
	    self.db.execute(
	        "UPDATE artifacts SET file_path = ?, encryption_key = '', checksum = ?, updated_at = ? WHERE id = ?",
	        (str(new_file_path), new_checksum, timestamp, artifact_id)
	    )
	    print(f"File decrypted and updated to '{new_file_name}'.")
	    return True

    def check_file_integrity(self, artifact_id):
	    """
	    Recalculates the checksum of the stored file and compares it with the database value.
	    Prints the stored hash, the current file hash, and whether the integrity check passed.
	    Does NOT automatically update the database.
	    """
	    artifact = self.db.fetch_one("SELECT file_path, checksum FROM artifacts WHERE id = ?", (artifact_id,))
	    if not artifact:
	        print("Artifact not found.")
	        return
	    
	    file_path, stored_checksum = artifact
	
	    if not os.path.exists(file_path):
	        print(f"File does not exist on disk: {file_path}")
	        return
	
	    with open(file_path, "rb") as f:
	        current_data = f.read()
	    current_checksum = hashlib.sha256(current_data).hexdigest()
	
	    print("\n--- File Integrity Check ---")
	    print(f"Stored Hash:  {stored_checksum}")
	    print(f"Current Hash: {current_checksum}")
	
	    if current_checksum == stored_checksum:
	        print("File integrity check PASSED.")
	    else:
	        print("File integrity check FAILED.")
	
	    # No automatic database update; only checking integrity.

    def list_files(self, logged_in_user):
	    """
	    Lists stored files.
	    - For admins: returns all files (ID, Title, Owner ID, Hash).
	    - For regular users: returns only files stored by them (ID, Title, Hash).
	    """
	    if logged_in_user[3] == "admin":
	        return self.db.fetch_all("SELECT id, title, owner_id, checksum FROM artifacts")
	    else:
	        return self.db.fetch_all("SELECT id, title, checksum FROM artifacts WHERE owner_id = ?", (logged_in_user[0],))
