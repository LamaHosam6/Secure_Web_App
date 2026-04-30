from flask import Flask, render_template, request, redirect, url_for, session 
import sqlite3 
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.secret_key = 'security_project_key' # For session encryption
bcrypt= Bcrypt(app)
# Database Setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'] # Stored as plain text (Weak Storage)
        role = 'user' # Default role
        
        # MITIGATION for Weak Password Storage:
        # Generate a secure Bcrypt hash of the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        #Vulnerable to SQL Injection (Direct string formatting)
        query = f"INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
        #We pass the hashed_password instead of the regular password
        cursor.execute(query,(username,hashed_password,role))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Use parameterized query for SQL Injection mitigation
    query = f"SELECT * FROM users WHERE username = ? "
    cursor.execute(query,(username,))
    user = cursor.fetchone()
    conn.close() 

    # Check if a user was found and verify the password hash
    # bcrypt.check_password_hash securely compares the plain text input 
    # with the stored hash in the database (user[2])
    if user and bcrypt.check_password_hash(user[2], password):
        session['username'] = user[1]
        session['role'] = user[3]
        return redirect(url_for('dashboard'))
    else:
        # If the user doesn't exist or hash doesn't match, access is denied
        return "Login Failed!"

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)