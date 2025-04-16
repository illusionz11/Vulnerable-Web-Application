# auth.py: Handles user authentication routes (login, logout, sign-up) and insecure login demonstrations.
# Standard library imports
# Third-party imports

from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User # imports table User from database
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   # imports database from __init__.py
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import text 


auth = Blueprint('auth', __name__) # defining blueprint 


# === Login (Secure) ===
@auth.route('/login', methods=['GET', 'POST']) # route pointing to login page
def login():
    if request.method == 'POST':
        username = request.form.get('username') # Requests username input
        password = request.form.get('password') # Requests password input
        # queries database for username corresponding to input
        user = User.query.filter_by(username=username).first() 

        if user:
            # validates user inputted password matches hashed password in database to corresponding user
            if check_password_hash(user.password, password): 
                login_user(user, remember=True) 
                flash('Logged in.', category='success')
                return redirect(url_for('views.intro')) # if user = True redirects to intro page
            else:
                # if user inputted doesnt match corresponding password in database returns error message
                flash('Incorrect password, please try again.', category='error') 
                return render_template('login.html', user=current_user)
        else:
            # if user doesnt match corresponding user in database returns error message
            flash('Username does not exist.', category='error') 
            return render_template('login.html', user=current_user)
    return render_template('login.html', user=current_user)


# === Insecure Login Level 1: SQL Injection via LIKE operator (wildcard-based bypass) ===
# Example: username = %, password = %
@auth.route('/login_insecure', methods=['GET', 'POST']) # route pointing to login_insecure page
def login_insecure1():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password') 

        """
        # User input is directly inserted into the SQL query, allowing attackers to bypass authentication.
        # Example attack: username = "%", password = "%" (logs in as any user).
        """
        # raw SQL query allowing partials matches with LIKE operator
        query = text(f"SELECT * FROM User WHERE username LIKE '{username}' AND password LIKE '{password}'") 
        print(query)  # debugging print to verify the query
        result = db.session.execute(query) # executes query in database
        user = result.fetchone()

        if user:
            # assuming `user` is a SQLAlchemy result object with attributes corresponding to the User table
            user_obj = User.query.get(user.id)
            login_user(user_obj, remember=True)
            flash('Logged in!', category='success')
            return redirect(url_for('views.intro'))
        else:
            flash('Incorrect username or password, please try again.', category='error')
            return render_template('login_insecure.html', user=current_user)
    return render_template('login_insecure.html', user=current_user)


# === Insecure Login Level 2: SQL Injection via exact match + string termination ===
# Example: username = admin' --, password = anything
@auth.route('/login_insecure2', methods=['GET', 'POST']) # route pointing to login_insecure2 page
def login_insecure2():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        """
        # Example attack: username = "admin' --", password = "anything" (logs in without a valid password).
        """
        # = parameter requires exact match instead of partial
        query = text(f"SELECT * FROM User WHERE username = '{username}' AND password = '{password}'") 
        print(query)  # debugging print to verify the query
        result = db.session.execute(query)
        user = result.fetchone()

        if user:
            # assuming `user` is a SQLAlchemy result object with attributes corresponding to the User model
            user_obj = User.query.get(user.id)
            login_user(user_obj, remember=True)
            flash('Logged in!', category='success')
            return redirect(url_for('views.intro'))
        else:
            flash('Incorrect username or password, please try again.', category='error')
            return render_template('login_insecure2.html', user=current_user)
    return render_template('login_insecure2.html', user=current_user)


# === Insecure Login Level 3: Partial sanitization (removes --) but still injectable ===
# Example: username = ' OR '1'='1, password = anything
@auth.route('/login_insecure3', methods=['GET', 'POST']) # route pointing to login_insecure3 page
def login_insecure3():
        if request.method == 'POST':
            username = request.form.get('username')
            # replace function that replaces recursively any inputs with -- comment with whitespace
            sanitised_username = username.replace("--", "") 
            password = request.form.get('password')
            # replace function that replaces recursively any inputs with -- comment with whitespace
            sanitised_password = password.replace("--", "") 
            """
            # Removing "--" does not prevent injection attacks. Users can still inject SQL via other methods.
            # Example attack: username = "' OR '1'='1", password = "anything" (logs in without authentication).
            """

            # intentionally unsafe SQL query for demonstration
            query = text(f"SELECT * FROM User WHERE username = '{sanitised_username}' AND password = '{sanitised_password}'") 
            print(query)  # debugging print to verify the query
            result = db.session.execute(query)
            user = result.fetchone()

            if user:
                # assuming `user` is a SQLAlchemy result object with attributes corresponding to the User m odel
                user_obj = User.query.get(user.id)
                login_user(user_obj, remember=True)
                flash('Logged in!', category='success')
                return redirect(url_for('views.intro'))
            else:
                flash('Incorrect username or password, please try again.', category='error')
                return render_template('login_insecure3.html', user=current_user)
        return render_template('login_insecure3.html', user=current_user)


# === Logout (Secure) ===
@auth.route('/logout') # route pointing to logout page
@login_required # requires user to be logged in before allowing this route and function to be used
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# === Sign-Up (Secure, with basic validation) ===
@auth.route('/sign-up', methods=['GET', 'POST']) # route pointing to sign-up page
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first() # database check for username existing corresponding to user inputted username 

        if user: # filterisation of username and password
            flash('Username already exists.', category='error') 
        elif len(username) < 4:
            flash('Username must be greater than 3 characters.', category='error')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.', category='error')
        else:
            new_user = User(username=username, password=generate_password_hash(
                password, method='pbkdf2:sha256')) # encodes inputted password with sha256 before inserting into database
            db.session.add(new_user) 
            db.session.commit() # adds user to database
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)
