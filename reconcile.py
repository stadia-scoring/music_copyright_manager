# reconcile.py
import os
import hashlib
import datetime
from pathlib import Path
from db import DatabaseManager

# Define the storage directory (should match the STORAGE_DIR in storage.py)
STORAGE_DIR = Path("./storage")

def reconcile_files():
    """
    Scans STORAGE_DIR and the database to reconcile differences.
    Returns a tuple of two lists:
      - orphan_files: files present on disk (excluding system files) that have no corresponding DB record.
      - missing_records: list of tuples (artifact_id, file_path) for records whose file is missing on disk.
    """
    db = DatabaseManager()

    # Get all files in STORAGE_DIR, ignoring files starting with a dot.
    files_on_disk = set(
        str(file.resolve()) 
        for file in STORAGE_DIR.iterdir() 
        if file.is_file() and not file.name.startswith(".")
    )

    # Fetch all artifact records from the database.
    records = db.fetch_all("SELECT id, file_path FROM artifacts")
    db_files = {record[0]: record[1] for record in records}
    files_in_db = set(db_files.values())

    # Orphan files: files on disk not referenced in the database.
    orphan_files = [file for file in files_on_disk if file not in files_in_db]

    # Missing records: database records for which the file does not exist.
    missing_records = [(artifact_id, file_path) for artifact_id, file_path in db_files.items() if file_path not in files_on_disk]

    return orphan_files, missing_records

def add_orphan_file_record(file_path, owner_id):
    """
    Adds a new record in the artifacts table for an orphan file.
    Assumes the file is already in STORAGE_DIR.
    Computes its checksum and uses its filename as the title.
    """
    db = DatabaseManager()
    file_path_obj = Path(file_path)
    title = file_path_obj.name  # e.g., "example.txt.enc"
    with open(file_path, "rb") as f:
        file_data = f.read()
    checksum = hashlib.sha256(file_data).hexdigest()
    timestamp = datetime.datetime.utcnow().isoformat()
    # For simplicity, we'll set encryption_key as an empty string.
    encryption_key = ""
    db.execute(
        """INSERT INTO artifacts (owner_id, title, file_path, checksum, encryption_key, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (owner_id, title, str(file_path_obj), checksum, encryption_key, timestamp, timestamp)
    )
    print(f"Record for orphan file '{title}' added with owner ID {owner_id}.")

def process_reconciliation():
    orphan_files, missing_records = reconcile_files()
    db = DatabaseManager()

    # Process orphan files
    if orphan_files:
        print("Orphan Files (present on disk but not in DB):")
        for file in orphan_files:
            print(f"\nOrphan file: {file}")
            action = input("What do you want to do? [s]kip, [d]elete, or [r]estore: ").strip().lower()
            if action == "s":
                print("Skipping this file.")
            elif action == "d":
                try:
                    os.remove(file)
                    print(f"File {file} deleted from disk.")
                except Exception as e:
                    print(f"Error deleting file {file}: {e}")
            elif action == "r":
                owner_input = input("Enter the owner ID to assign this file to: ").strip()
                try:
                    owner_id = int(owner_input)
                    add_orphan_file_record(file, owner_id)
                except ValueError:
                    print("Invalid owner ID. Skipping this file.")
            else:
                print("Invalid option. Skipping this file.")
    else:
        print("No orphan files found.")

    # Process missing records
    if missing_records:
        print("\nMissing Records (DB record exists but file not found on disk):")
        for artifact_id, file_path in missing_records:
            print(f"\nArtifact ID {artifact_id}: {file_path}")
            action = input("What do you want to do? [s]kip or [d]elete the record: ").strip().lower()
            if action == "s":
                print("Skipping this record.")
            elif action == "d":
                db.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
                print(f"Record for artifact ID {artifact_id} deleted from database.")
            else:
                print("Invalid option. Skipping this record.")
    else:
        print("No missing records found.")

if __name__ == "__main__":
    process_reconciliation()