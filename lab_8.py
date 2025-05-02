#Name: Kamil Roginski
#Date: 2 MAY 2025
#Professor: Mark Babcock
#Course: CYOP 300

"""
Lab 8: Extend Flask application to add password update form, NIST SP 800-63B checks,
common-password blocking, and logging of failed login attempts.
"""

import os
import re
import logging
from functools import wraps
from datetime import datetime as dt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret')

# --------------------------------------------------
# Configure failed-login logger
# --------------------------------------------------
login_logger = logging.getLogger('failed_logins')
login_logger.setLevel(logging.WARNING)
fh = logging.FileHandler('failed_logins.log')
formatter = logging.Formatter('%(asctime)s - %(message)s')
fh.setFormatter(formatter)
login_logger.addHandler(fh)

# --------------------------------------------------
# Load common passwords list
# --------------------------------------------------
def load_common_passwords(filename='CommonPasswords.txt', folder = 'static'):
    path = os.path.join(app.root_path, folder, filename)
    try:
        with open(path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        app.logger.warning(f"Common passwords file not found at {path}; skipping compromise check.")
        return set()

common_passwords = load_common_passwords()

# --------------------------------------------------
# In-memory user store (for demo purposes)
# --------------------------------------------------
# users = { username: {'password': hashed_pw, ...} }
users = {}

# --------------------------------------------------
# Password complexity validator (NIST SP 800-63B + existing rules)
# --------------------------------------------------
def validate_password(pw):
    # Example: minimum length 8, at least one digit, one uppercase, one special,
    # Not in CommonPassword.txt
    if pw in load_common_passwords():
        return 'Password too common. Please choose a different one.'
    if len(pw) < 8:
        return False
    if not re.search(r'[A-Z]', pw):
        return False
    if not re.search(r'[a-z]', pw):
        return False
    if not re.search(r'\d', pw):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pw):
        return False
    return True

# Existing route definitions...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # reuse validate_password
        if not validate_password(password):
            flash('Password does not meet complexity requirements.')
            return render_template('register.html')
        # Check common passwords
        if password in common_passwords:
            flash('Password too common; choose a different one.')
            return render_template('register.html')
        # Store hashed password
        hashed = generate_password_hash(password)
        users[username] = {'password': hashed, 'created': dt.utcnow()}
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        # Log failed attempt
        ip = request.remote_addr
        login_logger.warning(f"Failed login attempt for user '{username}' from IP: {ip}")
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# --------------------------------------------------
# New: Password Update Route
# --------------------------------------------------
@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'username' not in session:
        flash('You must be logged in to update your password.')
        return redirect(url_for('login'))
    username = session['username']
    user = users.get(username)
    if not user:
        flash('User not found.')
        return redirect(url_for('logout'))

    if request.method == 'POST':
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        # Verify current password
        if not check_password_hash(user['password'], current):
            flash('Current password is incorrect.')
            return render_template('update_password.html')
        # Validate new password criteria
        if not validate_password(new):
            flash('New password does not meet complexity requirements.')
            return render_template('update_password.html')
        # Check against common passwords
        if new in common_passwords:
            flash('Chosen password is too common; please choose a different one.')
            return render_template('update_password.html')
        # Confirm match
        if new != confirm:
            flash('New password and confirmation do not match.')
            return render_template('update_password.html')
        # All checks passed; update
        users[username]['password'] = generate_password_hash(new)
        flash('Password updated successfully.')
        return redirect(url_for('home'))

    return render_template('update_password.html')

# --------------------------------------------------
# Protected home
# --------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@login_required
def home():
    now = dt.now()
    return render_template('home.html', now=now)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


# ... other routes (about, contact, etc.) remain unchanged

if __name__ == '__main__':
    app.run(debug=True)