# Music Copyright Manager

## Overview

The digital transformation of the music industry has amplified concerns about copyright infringement and unauthorised replication (Kumar & Mahajan, 2024). This application addresses these concerns by providing a secure digital environment that ensures the Confidentiality, Integrity, and Availability (CIA) of copyrighted music artefacts. It supports the secure storage, retrieval, and management of lyrics, musical scores, and audio recordings (MP3, FLAC) through encryption, checksums, audit logging, and comprehensive role-based access control (Zhang, 2024).

### Key Features
- **Encrypted File Storage** with automatic checksum verification
- **Role-Based Access Control (RBAC)** differentiating Administrator and User roles
- Complete **CRUD functionality** (Create, Read, Update, Delete)
- Robust **Audit Logging** for monitoring user interactions
- Brute force attack mitigation through login attempt tracking

## Installation

### Prerequisites

- Python 3.10+
- pip (Python package manager)

### Setup Instructions

1. Clone the repository:

```bash
git clone https://github.com/stadia-scoring/SSD_PCOM7E_JAN_2025/music_copyright_manager.git
cd music_copyright_manager
```

2. Create a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

### Available Functionalities

- Securely create, read, update, and delete music artefacts
- Encrypt and decrypt artefacts
- Verify file integrity via checksums
- Manage user roles and permissions
- Audit and review logged actions

# Application Testing Workflow

Below is a detailed workflow for testing the full functionality of the application, demonstrating user creation, secure file storage, encryption and decryption, role-based access control, integrity checking, and audit logging.

## Step 1: Launch Application

```bash
python3 app.py
```

- Upon initial launch, a default administrator account (`admin`) is created automatically.
- The system displays a message indicating that the default admin has been created.
- The admin is prompted to log in.

## Step 2: Admin Login and Password Change

Log in using the default administrator credentials (`admin/admin`):

```plaintext
Username: admin
Password: admin
```

The system confirms authentication and displays audit log details:

```plaintext
Authentication successful! Welcome, admin.
Audit log recorded: login_success by user 1.
Last successful login: No previous successful login found.
Last failed login: No previous failed login found.
Default admin password is in use. You must change your password now.
```

Change the password as required:

```plaintext
Enter new password: admin123
```

Confirmation message:

```plaintext
Password updated successfully.
Authentication successful! Welcome, admin.
Audit log recorded: password_change by user 1.
```

## Step 3: Navigate to User Options and Create a New User

Navigate to User Options:

```plaintext
--- Main Menu ---
1. File Options
2. User Options
3. Show Audit Log
4. Reconcile Files
5. Logout
Enter your choice: 2
```

List all users:

```plaintext
Enter your choice: 1

--- All Users ---
ID: 1, Username: admin, Role: admin
```

Create a new user:

```plaintext
Enter your choice: 2
Enter new username: user
Enter new password: user
Enter role (user/admin): user
User 'user' created successfully with ID 2!
Audit log recorded: create_user by user 1.
```

Verify user creation:

```plaintext
Enter your choice: 1

--- All Users ---
ID: 1, Username: admin, Role: admin
ID: 2, Username: user, Role: user
Audit log recorded: list_users by user 1.
```

## Step 4: Store a File as Administrator

Navigate to File Options:

```plaintext
--- Main Menu ---
Enter your choice: 1
```

Store a file:

```plaintext
--- File Options Menu ---
Enter your choice: 1
Enter path to file: examples/fortunate_son_ccr.mp3
Encrypt file? (y/n): n
Original file 'fortunate_son_ccr.mp3' deleted after storing.
File 'fortunate_son_ccr.mp3' stored as 'fortunate_son_ccr.mp3' with Artifact ID 1.
Audit log recorded: store_file by user 1.
```

List stored files:

```plaintext
Enter your choice: 8

--- All Stored Files ---
ID: 1, Title: fortunate_son_ccr.mp3, Owner ID: 1, Hash: b99da366817b0793c22becba43c25782a63b19034d7f85e19932cf87c69627ec
Audit log recorded: list_files by user 1.
```

## Step 5: Log in as a Standard User and Store a File

Log out:

```plaintext
Enter your choice: 5
Logging out...
Audit log recorded: logout by user 1.
```

Log in as the new user:

```plaintext
Username: user
Password: user
Authentication successful! Welcome, user.
Audit log recorded: login_success by user 2.
```

Store a file:

```plaintext
Enter your choice: 1
Enter path to file: examples/fortunate_son_ccr_lyrics.txt
Encrypt file? (y/n): n
Original file 'fortunate_son_ccr_lyrics.txt' deleted after storing.
File 'fortunate_son_ccr_lyrics.txt' stored as 'fortunate_son_ccr_lyrics.txt' with Artifact ID 2.
Audit log recorded: store_file by user 2.
```

Encrypt the file:

```plaintext
Enter your choice: 4
Enter artifact ID to encrypt: 2
File encrypted and updated to 'fortunate_son_ccr_lyrics.txt.enc'.
Audit log recorded: encrypt_file by user 2.
```

## Step 6: Check File Integrity

```plaintext
Enter your choice: 6
Enter artifact ID to check integrity: 2

--- File Integrity Check ---
Stored Hash:  a3fe6234d1d16b3a66dfaaaf254ab5050bafc7f1318f54b8e1e6b60d60466e7f
Current Hash: a3fe6234d1d16b3a66dfaaaf254ab5050bafc7f1318f54b8e1e6b60d60466e7f
File integrity check PASSED.
Audit log recorded: check_integrity by user 2.
```

## Step 7: Demonstrate Role-Based Access Control (RBAC) and Audit Logging

Attempt to decrypt a file owned by another user:

```plaintext
Enter your choice: 5
Enter artifact ID to decrypt: 1
Permission denied: You cannot modify this file.
Audit log recorded: decrypt_file by user 2.
```

Decrypt own file:

```plaintext
Enter your choice: 5
Enter artifact ID to decrypt: 2
File decrypted and updated to 'fortunate_son_ccr_lyrics.txt'.
Audit log recorded: decrypt_file by user 2.
```

View audit logs:

```plaintext
--- Main Menu ---
Enter your choice: 3

--- Audit Log ---
[Audit log details displayed here]
```

This comprehensive workflow ensures thorough testing of authentication, file security, encryption, role-based access control, and audit tracking.



## Design Patterns and Implementation

The application follows object-oriented best practices emphasizing modularity, extensibility, and security. The core design incorporates several software patterns, as initially proposed:

### Singleton Pattern
The Singleton pattern ensures that the `DatabaseManager` class maintains a single, consistent connection throughout the application's lifecycle, enhancing data integrity and performance (Gamma et al., 1995).

### Observer Pattern
Audit logging is implemented through the Observer pattern, where key actions such as file uploads, deletions, and user login attempts automatically trigger logging events. This pattern supports compliance with audit trails and simplifies tracking user activities (Freeman & Robson, 2004).

### Factory and Strategy Patterns
Encryption and file storage modules leverage the Factory and Strategy patterns, allowing interchangeable algorithms and implementations without altering existing code, adhering to the Open-Closed Principle (Martin, 2008; Freeman & Robson, 2004).

## Variations from Unit 3 Design

During implementation, certain design adjustments were necessary. These modifications and justifications are summarized as follows:

| Feature                | Original Design                    | Implemented Solution                | Justification                           |
|------------------------|------------------------------------|--------------------------------------|-----------------------------------------|
| Encryption             | SQLCipher Database Encryption      | File-level Encryption with cryptography | Easier setup and reduced complexity    |
| Brute Force Protection | Persistent Database Tracking       | In-memory Temporary Lockout System  | Efficiency and ease of implementation  |
| RBAC                   | Basic Permission Checks            | Detailed Per-Action Permissions     | Improved granularity and enhanced security |

## Libraries and External Sources

The project carefully limits external dependencies to maintain originality and compliance with the assignment requirement of less than 20% external library code:

- **bcrypt**: Secure password hashing ([bcrypt documentation](https://pypi.org/project/bcrypt/))
- **cryptography**: Robust AES encryption and decryption ([cryptography documentation](https://pypi.org/project/cryptography/))

These libraries were selected due to their robust security standards, widespread usage, strong community support, and proven reliability in secure applications.

## Evidence of Security and Functionality Testing

The application was rigorously tested to ensure functionality, security, and adherence to secure coding practices:

### Evidence of Security Testing

Bandit Security Testing
Automated security checks conducted using Bandit identified a single low-severity issue:

B105: Possible Hardcoded Password: Detected default admin password ('admin') which intentionally prompts immediate password change upon first login to enforce secure password usage.

### Injection Attack Testing

The system successfully rejected injection attack attempts (e.g., ' OR 1=1 --, admin'; SELECT * FROM users; --) with proper logging of failed attempts, ensuring protection against SQL injection.

### Brute Force Protection

Successfully tested account lockout after multiple unsuccessful login attempts. After multiple incorrect logins, the account locks temporarily (e.g., 300 seconds), with each attempt logged to maintain a comprehensive audit trail.


## Security Considerations

The application explicitly implements the following key security practices:

- **Authentication and Authorization**: Managed robustly through hashed passwords using bcrypt and enforced RBAC.
- **Encryption**: AES encryption provided by the cryptography library ensures data confidentiality.
- **Integrity Checking**: SHA-256 checksum generation verifies data integrity consistently.
- **Audit Logging**: Comprehensive logging mechanisms record significant actions, supporting compliance and traceability.

## Future Enhancements

Future iterations may include enhancements like cloud-based storage integration, advanced multi-factor authentication, and additional audit analytics features to further strengthen security and usability.

## References

Gamma, E., Helm, R., Johnson, R. & Vlissides, J. (1995) Design Patterns: Elements of Reusable Object-Oriented Software. Addison-Wesley.

Freeman, E. & Robson, E. (2004) Head First Design Patterns. Sebastopol, CA: O’Reilly Media.

Martin, R.C. (2008) Clean Code: A Handbook of Agile Software Craftsmanship. Upper Saddle River, NJ: Prentice Hall.

Python Software Foundation (2024) Python Documentation [Online]. Available at: https://docs.python.org/3/ (Accessed: 1 March 2025).

PyPI (2024a) bcrypt documentation [Online]. Available at: https://pypi.org/project/bcrypt/ (Accessed: 7 March 2025).

PyPI (2024b) cryptography documentation [Online]. Available at: https://pypi.org/project/cryptography/ (Accessed: 10 March 2025).

Kumar, R. & Mahajan, S. (2024) ‘Digital transformation in the music industry’, Digital Society, Springer [Online]. Available at: https://link.springer.com (Accessed: 5 March 2025).

Zhang, W.F. (2024) ‘Digital music resource management using blockchain’, in IEEE International Conference on Computer and Information Science, 2024 IEEE/ACIS, pp. xx-xx. IEEE [Online]. Available at: https://ieeexplore.ieee.org (Accessed: 5 March 2025).




