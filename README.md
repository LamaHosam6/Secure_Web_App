# Secure_Web_App
Project Overview
This is a secure Flask application developed to demonstrate common web vulnerabilities and their mitigations. The project covers key security areas including authentication, access control, and data encryption to ensure a safe user experience.

Team Members:

-Lama Abosaada (Team Leader)

-Tasnim Almassalma

-Tasnim Kamal

-atheer Alwably

Installation & Setup

1- Clone the repository:
git clone https://github.com/LamaHosam6/Secure_Web_App.git

2-Install required libraries:
pip install flask flask-bcrypt pyopenssl

3- Run the application:
python app.py

Note: The application is configured to run on HTTPS. When accessing it via https://127.0.0.1:5000, your browser will display a privacy warning due to the self-signed certificate. Click Advanced and then Proceed to view the site.

Security Testing Guide
You can verify the security features of this application using the following test cases:

1. SQL Injection Prevention
Implementation: Parameterized queries using ? placeholders in SQLite.
Test: On the Login page, try entering ' OR '1'='1 in the username field.
Result: The system will reject the attempt as it treats the input as a literal string, not an executable SQL command.

2. Secure Password Hashing
Implementation: Flask-Bcrypt (Salted Hashing).
Test: Access the database.db and view the users table.
Result: Passwords are stored as irreversible hashes, making them unreadable even if the database is compromised.

3. Stored XSS Prevention
Implementation: Automatic HTML escaping via Jinja2.
Test: Post a comment containing <script>alert('XSS')</script>.
Result: The script is rendered as harmless text on the dashboard and will not execute.

4. Broken Access Control (RBAC)
Implementation: Server-side session role verification.
Test: Log in as a 'user' and attempt to navigate directly to /admin.
Result: Access will be denied with a "403 Forbidden" status.

5. Secure Communication (HTTPS)
Implementation: SSL/TLS encryption.
Test: Observe the URL protocol in the browser.
Result: Data is transmitted over an encrypted channel, protecting it from interception.

Tech Stack

Backend: Python (Flask)

Security: Bcrypt, SSL/TLS (HTTPS)

Database: SQLite3
