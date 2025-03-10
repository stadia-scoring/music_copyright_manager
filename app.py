# app.py
import sys
from db import DatabaseManager
from auth import UserManager
from storage import FileManager
from audit import AuditLogger
from reconcile import process_reconciliation  # Import the reconciliation function

def file_options_menu(logged_in_user, user_manager, file_manager, audit_logger):
    while True:
        print("\n--- File Options Menu ---")
        print("1. Store File")
        print("2. Retrieve File")
        print("3. Delete File")
        print("4. Encrypt File")
        print("5. Decrypt File")
        print("6. Check File Integrity")
        print("7. File Audit")
        print("8. List Stored Files")
        print("9. Return to Main Menu")
        choice = input("Enter your choice: ")
        try:
            if choice == "1":
                file_path = input("Enter path to file: ")
                enc_input = input("Encrypt file? (y/n): ").strip().lower()
                encrypt_choice = True if enc_input == "y" else False
                file_manager.store_file(logged_in_user[0], file_path, encrypt_choice)
                audit_logger.log_event(logged_in_user[0], "store_file", details=f"Stored file from '{file_path}' with encryption={encrypt_choice}")
            elif choice == "2":
                artifact_id = int(input("Enter artifact ID to retrieve: "))
                success = file_manager.retrieve_file(artifact_id, logged_in_user)
                if success:
                    audit_logger.log_event(logged_in_user[0], "retrieve_file", resource_id=artifact_id)
                else:
                    audit_logger.log_event(logged_in_user[0], "retrieve_file", resource_id=artifact_id, success=False, details="Permission denied or artifact not found")
            elif choice == "3":
                artifact_id = int(input("Enter artifact ID to delete: "))
                success = file_manager.delete_file(artifact_id, logged_in_user)
                if success:
                    audit_logger.log_event(logged_in_user[0], "delete_file", resource_id=artifact_id)
                else:
                    audit_logger.log_event(logged_in_user[0], "delete_file", resource_id=artifact_id, success=False, details="Permission denied or artifact not found")
            elif choice == "4":
                artifact_id = int(input("Enter artifact ID to encrypt: "))
                success = file_manager.encrypt_file(artifact_id, logged_in_user)
                if success:
                    audit_logger.log_event(logged_in_user[0], "encrypt_file", resource_id=artifact_id)
                else:
                    audit_logger.log_event(logged_in_user[0], "encrypt_file", resource_id=artifact_id, success=False)
            elif choice == "5":
                artifact_id = int(input("Enter artifact ID to decrypt: "))
                success = file_manager.decrypt_file(artifact_id, logged_in_user)
                if success:
                    audit_logger.log_event(logged_in_user[0], "decrypt_file", resource_id=artifact_id)
                else:
                    audit_logger.log_event(logged_in_user[0], "decrypt_file", resource_id=artifact_id, success=False)
            elif choice == "6":
                artifact_id = int(input("Enter artifact ID to check integrity: "))
                file_manager.check_file_integrity(artifact_id)
                audit_logger.log_event(logged_in_user[0], "check_integrity", resource_id=artifact_id)
            elif choice == "7":
                artifact_id = int(input("Enter artifact ID for file audit: "))
                logs = audit_logger.get_file_audit(artifact_id)
                print("\n--- File Audit Log ---")
                for log in logs:
                	log_details = f"Time: {log[1]}, Action: {log[2]}, User ID: {log[3]}"
                	if len(log) > 4:
                		log_details += f", Hash: {log[4]}"
                	print(log_details)
                
                audit_logger.log_event(logged_in_user[0], "file_audit", resource_id=artifact_id)
            elif choice == "8":
                files = file_manager.list_files(logged_in_user)
                if logged_in_user[3] == "admin":
                    print("\n--- All Stored Files ---")
                    for f in files:
                        print(f"ID: {f[0]}, Title: {f[1]}, Owner ID: {f[2]}, Hash: {f[3]}")
                else:
                    print("\n--- Your Stored Files ---")
                    for f in files:
                        print(f"ID: {f[0]}, Title: {f[1]}, Hash: {f[2]}")
                audit_logger.log_event(logged_in_user[0], "list_files")
            elif choice == "9":
                break
            else:
                print("Invalid option. Please try again.")
                audit_logger.log_event(logged_in_user[0], "file_options_invalid", details=f"Invalid file options selection: {choice}")
        except Exception as e:
            print("An unexpected error occurred:", e)
            audit_logger.log_event(logged_in_user[0] if logged_in_user else 0, "file_options_error", details=str(e))

def user_options_menu(logged_in_user, user_manager, audit_logger):
    while True:
        print("\n--- User Options Menu ---")
        print("1. List All Users")
        print("2. Create User")
        print("3. Delete User")
        print("4. Return to Main Menu")
        choice = input("Enter your choice: ")
        try:
            if choice == "1":
                users = user_manager.list_users()
                print("\n--- All Users ---")
                for u in users:
                    print(f"ID: {u[0]}, Username: {u[1]}, Role: {u[3]}")
                audit_logger.log_event(logged_in_user[0], "list_users")
            elif choice == "2":
                new_username = input("Enter new username: ")
                new_password = input("Enter new password: ")
                new_role = input("Enter role (user/admin): ")
                if user_manager.get_user(new_username):
                    print("Username already exists. Cannot create duplicate user.")
                    audit_logger.log_event(logged_in_user[0], "create_user", success=False, details="Attempted duplicate username creation.")
                else:
                    user_manager.create_user(new_username, new_password, new_role)
                    audit_logger.log_event(logged_in_user[0], "create_user", details=f"Created user '{new_username}'")
            elif choice == "3":
                user_id_to_delete = int(input("Enter user ID to delete: "))
                confirm = input("Delete all files of the user? (y/n): ").strip().lower()
                delete_files = True if confirm == "y" else False
                try:
                    user_manager.delete_user(user_id_to_delete, logged_in_user[0], delete_files)
                    audit_logger.log_event(logged_in_user[0], "delete_user", resource_id=user_id_to_delete, details=f"User deleted with delete_files={delete_files}")
                except Exception as e:
                    print("Error deleting user:", e)
                    audit_logger.log_event(logged_in_user[0], "delete_user", resource_id=user_id_to_delete, success=False, details=str(e))
            elif choice == "4":
                break
            else:
                print("Invalid option in User Options Menu.")
                audit_logger.log_event(logged_in_user[0], "user_options_invalid", details=f"Invalid user options selection: {choice}")
        except Exception as e:
            print("An unexpected error occurred in User Options:", e)
            audit_logger.log_event(logged_in_user[0], "user_options_error", details=str(e))
import sys

def main():
           
	try:
	    user_manager = UserManager()
	    file_manager = FileManager()
	    audit_logger = AuditLogger()
	
	    # Ensure default admin exists; if not, create one.
	    default_admin = user_manager.get_user("admin")
	    if not default_admin:
	        user_manager.create_user("admin", "admin", "admin")
	        print("Default admin created with username 'admin' and password 'admin'. Please change your password upon first login.")
	
	    # Login loop
	    logged_in_user = None
	    while not logged_in_user:
	        print("\nPlease log in:")
	        username = input("Username: ")
	        password = input("Password: ")
	        logged_in_user = user_manager.authenticate_user(username, password)
	        if logged_in_user:
	            audit_logger.log_event(logged_in_user[0], "login_success", details=f"User {username} logged in successfully.")
	            # Display last login info:
	            last_success = audit_logger.get_last_successful_login(logged_in_user[0])
	            last_failed = audit_logger.get_last_failed_login(username)
	            print(f"Last successful login: {last_success}")
	            print(f"Last failed login: {last_failed}")
	        else:
	            audit_logger.log_event(0, "login_failure", details=f"Invalid login attempt for {username}")
	            print("Invalid credentials. Please try again.")
	
	    # Force password change for default admin if using default credentials.
	    if logged_in_user[1] == "admin" and password == "admin":
	        print("Default admin password is in use. You must change your password now.")
	        new_password = input("Enter new password: ")
	        user_manager.change_password(logged_in_user[0], new_password)
	        logged_in_user = user_manager.authenticate_user("admin", new_password)
	        audit_logger.log_event(logged_in_user[0], "password_change", details="Admin changed default password.")
	
	    # Main menu loop for admins and non-admin users.
	    while True:
	        print("\n--- Main Menu ---")
	        print(f"Logged in as: {logged_in_user[1]} (ID: {logged_in_user[0]}, Role: {logged_in_user[3]})")
	        if logged_in_user[3] == "admin":
	            print("1. File Options")
	            print("2. User Options")
	            print("3. Show Audit Log")
	            print("4. Reconcile Files")
	            print("5. Logout")
	        else:
	            print("1. File Options")
	            print("2. Logout")
	        choice = input("Enter your choice: ")
	        try:
	            if logged_in_user[3] == "admin":
	                if choice == "1":
	                    file_options_menu(logged_in_user, user_manager, file_manager, audit_logger)
	                elif choice == "2":
	                    user_options_menu(logged_in_user, user_manager, audit_logger)
	                elif choice == "3":
	                    print("\n--- Audit Log Menu ---")
	                    print("1. Security Logs")
	                    print("2. Access Logs")
	                    print("3. Event Logs")
	                    print("4. All Logs")
	                    audit_choice = input("Enter your choice: ")
	                    if audit_choice == "1":
	                        logs = audit_logger.get_security_logs()
	                        print("\n--- Security Logs ---")
	                        for log in logs:
	                            print(log)
	                    elif audit_choice == "2":
	                        logs = audit_logger.get_access_logs()
	                        print("\n--- Access Logs ---")
	                        for log in logs:
	                            print(log)
	                    elif audit_choice == "3":
	                        logs = audit_logger.get_event_logs()
	                        print("\n--- Event Logs ---")
	                        for log in logs:
	                            print(log)
	                    elif audit_choice == "4":
	                        logs = audit_logger.get_all_logs()
	                        print("\n--- All Audit Logs ---")
	                        for log in logs:
	                            print(log)
	                    else:
	                        print("Invalid option in Audit Log Menu.")
	                        audit_logger.log_event(logged_in_user[0], "audit_menu_invalid", details=f"Invalid audit menu option: {audit_choice}")
	                elif choice == "4":
	                    process_reconciliation()  # Call the interactive reconciliation tool
	                    audit_logger.log_event(logged_in_user[0], "reconcile_files", details="Reconciliation performed.")
	                elif choice == "5":
	                    print("Logging out...")
	                    audit_logger.log_event(logged_in_user[0], "logout", details="User logged out successfully.")
	                    main()  # Restart the login process
	                    break
	                else:
	                    print("Invalid option. Please try again.")
	                    audit_logger.log_event(logged_in_user[0], "invalid_option", details=f"User selected invalid option: {choice}")
	            else:
	                if choice == "1":
	                    file_options_menu(logged_in_user, user_manager, file_manager, audit_logger)
	                elif choice == "2":
	                    print("Logging out...")
	                    audit_logger.log_event(logged_in_user[0], "logout", details="User logged out successfully.")
	                    main()  # Restart the login process
	                    break
	                else:
	                    print("Invalid option. Please try again.")
	                    audit_logger.log_event(logged_in_user[0], "invalid_option", details=f"User selected invalid option: {choice}")
	        except Exception as e:
	            print("An unexpected error occurred:", e)
	            audit_logger.log_event(logged_in_user[0] if logged_in_user else 0, "error", details=str(e))
	
	except KeyboardInterrupt:
		print("\n[INFO] Exiting application. Goodbye!")
		sys.exit(0)

if __name__ == "__main__":
    main()
    
    
    
    
    
    
    
    
    
    
    
    
    
    