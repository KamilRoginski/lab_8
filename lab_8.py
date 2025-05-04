#Name: Kamil Roginski
#Date: 4 MAY 2025
#Professor: Mark Babcock
#Course: CYOP 300

"""
Lab 8: Extends lab_7 Flask application to add password update form,
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
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

"""
Configure failed-login logger
"""
login_logger = logging.getLogger('failed_logins')
login_logger.setLevel(logging.WARNING)
fh = logging.FileHandler('failed_logins.log')
formatter = logging.Formatter('%(asctime)s - %(message)s')
fh.setFormatter(formatter)
login_logger.addHandler(fh)

def load_common_passwords(filename='CommonPasswords.txt', folder = 'static'):
    """
    Opens and reads from CommonPasswords.txt
    """
    path = os.path.join(app.root_path, folder, filename)
    try:
        with open(path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        app.logger.warning(f"Common passwords file not found at {path}; skipping compromise check.")
        return set()

common_passwords = load_common_passwords()


users = {}

# In-memory user store: {username: password_hash}

def password_complexity(pw):
    """
    Example: minimum length 8, at least one digit, one uppercase,
    one lowercase, and one special character.
    Not in CommonPassword.txt
    """
    if pw in load_common_passwords():
        return 'Password too common. Please choose a different one.'
    if len(pw) < 8:
        flash('Password must be at least 8 characters long.')
        return False
    if not re.search(r'[A-Z]', pw):
        flash('Password must include at least one uppercase letter.')
        return False
    if not re.search(r'[a-z]', pw):
        flash('Password must include at least one lowercase letter.')
        return False
    if not re.search(r'\d', pw):
        flash('Password must include at least one digit.')
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pw):
        flash('Password must include at least one special character.')
        return False
    return True

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    """Update the password for the current user while following password complexity rules."""
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
        if not password_complexity(new):
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

def login_required(f):
    """
    Decorator that redirects to login if no user is currently authenticated.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
@login_required
def home():
    """
    Render the home page showing the current date and time to a logged-in user.
    """
    now = dt.now()
    return render_template('home.html', now=now)

@app.route('/about')
def about():
    """
    Render the about page for authenticated users.
    """
    return render_template('about.html')

@app.route('/contact')
def contact():
    """
    Render the contact page for authenticated users.
    """
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user sign-up by validating inputs, storing a hashed password, and flashing status.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # reuse password_complexity()
        if not password_complexity(password):
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
    """
    Authenticate a user by verifying their credentials and starting a session.
    """
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
    """
    Log out the current user by clearing their session and redirecting to login.
    """
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
