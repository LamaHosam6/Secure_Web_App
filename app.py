from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'security_project_key'
bcrypt = Bcrypt(app)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

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

        hashed = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
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
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

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

    return render_template(
        'dashboard.html',
        username=session['username'],
        role=session['role'],
        comments=comments
    )
# ---------------- COMMENT (XSS VULNERABLE) ----------------
@app.route('/comment', methods=['POST'])
def comment():
    msg = request.form['comment']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO comments VALUES (?)", (msg,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

# -------- ADMIN (After FIX) --------
@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        return "Access Denied", 403

    return render_template("admin.html")

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------- RUN ----------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)