from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
# Security: Secret key signs session cookies to prevent tampering
app.secret_key = 'security_project_key'
bcrypt = Bcrypt(app)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Security: 'IF NOT EXISTS' prevents re-creating tables and losing data
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
        content TEXT
    )''')

    conn.commit()
    conn.close()

# ---------------- HOME ----------------
@app.route('/')
def index():
    return render_template('login.html')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABILITY 1: Weak Password Storage
        # FIX: Using Bcrypt hashing (Salted) to store passwords securely
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        # VULNERABILITY 2: SQL Injection
        # FIX: Using Parameterized Queries (?) to treat input as data, not commands
        cursor.execute("INSERT INTO users VALUES (NULL, ?, ?, ?)",
                       (username, hashed, 'user'))
        conn.commit()
        conn.close()

        return redirect(url_for('index'))

    return render_template('register.html')

# ---------------- LOGIN ----------------
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Security: SQL Injection protection during login verification
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    # Security: Safe comparison between user input and hashed password
    if user and bcrypt.check_password_hash(user[2], password):
        session['username'] = user[1]
        session['role'] = user[3]
        return redirect(url_for('dashboard'))

    return "Login Failed"

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content FROM comments")
    comments = cursor.fetchall()
    conn.close()

    # VULNERABILITY 3: Stored XSS (Cross-Site Scripting)
    # FIX: Jinja2 auto-escapes 'comments', rendering them as text, not code
    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session['role'],
        comments=comments
    )
# ---------------- COMMENT ----------------
@app.route('/comment', methods=['POST'])
def comment():
    msg = request.form['comment']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Security: Safe insertion of user comments using parameterized queries
    cursor.execute("INSERT INTO comments VALUES (?)", (msg,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

# -------- ADMIN --------
@app.route('/admin')
def admin():
    # VULNERABILITY 4: Broken Access Control (IDOR/Unauthorized Access)
    # FIX: Verifying session['role'] to ensure only admins can view this page
    if session.get('role') != 'admin':
        return "Access Denied", 403

    return render_template("admin.html")

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    # Security: Proper session termination to prevent session fixation/hijacking
    session.clear()
    return redirect(url_for('index'))


# ---------------- RUN ----------------
if __name__ == '__main__':
    init_db()
    # VULNERABILITY 5: Insecure Communication (Plaintext Data)
    # FIX: Enabling HTTPS (SSL/TLS) to encrypt all data in transit
    app.run(debug=True, ssl_context='adhoc')