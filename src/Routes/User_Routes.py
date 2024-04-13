from flask import Blueprint, render_template, request, session, redirect, url_for, current_app
import sqlite3
import hashlib
from datetime import datetime
from werkzeug.utils import secure_filename
import os  # Add this line at the beginning of your file
from flask import Flask  # Add this line if it's not already there

app = Flask(__name__)

user_routes = Blueprint('user_routes', __name__)

DATABASE = 'SymptomDiagnoses.db'


class User:
    def __init__(self, id):
        self.id = id


@user_routes.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Collect form data
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        dob = request.form['dob']
        email = request.form['email']
        mobile = request.form['mobile']
        # Hash the password before storing
        password_hash = hashlib.sha256(request.form['password'].encode()).hexdigest()
        gender = request.form['gender']

        # Check if gender value is valid
        if gender not in ['Male', 'Female', 'Others']:
            return 'Invalid gender. Please select Male, Female, or Others.'

        # Add the current date and time as the registration date
        registration_date = datetime.now()

        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Insert the new user into the 'users' table
        cursor.execute(
            'INSERT INTO users (FirstName, Surname, Email, Gender, DateOfBirth, Password, mobile, RegistrationDate) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (first_name, last_name, email, gender, dob, password_hash, mobile, registration_date))
        conn.commit()  # Commit changes
        cursor.close()  # Close the cursor
        conn.close()  # Close the connection

        return render_template('homePage.html')
    else:
        # Render the registration form template
        return render_template('registration.html')


@user_routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Collect login form data
        email = request.form['email']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Retrieve user from the 'users' table by email and hashed password
        cursor.execute('SELECT * FROM users WHERE Email = ? AND Password = ?', (email, password_hash))
        account = cursor.fetchone()

        cursor.close()  # Close the cursor
        conn.close()  # Close the connection

        if account:
            # If the account exists, store user information in session
            session['logged_in'] = True
            session['user_id'] = account[0]  # Assuming the user ID is at index 0
            session['first_name'] = account[1]  # Assuming the first name is at index 1
            session['last_name'] = account[2]  # Assuming the last name is at index 2
            return redirect(url_for('home'))  # Redirect to home page or dashboard
        else:
            # If account does not exist or username/password incorrect
            return 'Login failed. Check your email and password.'

    # Render the login form template for GET requests
    return render_template('login.html')


@user_routes.route('/logout')
def logout():
    # Remove user information from session
    session.pop('logged_in', None)
    session.pop('first_name', None)
    return redirect(url_for('home'))


@user_routes.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user details
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE UserID = ?', (session['user_id'],))

        user_tuple = cursor.fetchone()

        # Get columns before closing the cursor
        columns = [column[0] for column in cursor.description]

        cursor.close()
        conn.close()

        # Check if user_tuple is None
        if user_tuple is None:
            # Handle the error here, e.g., return an error message
            return "Error: user_tuple is None"
        else:
            # Convert the tuple to a dictionary
            user = dict(zip(columns, user_tuple))

        if request.method == 'POST':
            # If the form has been submitted, update the user details
            # Only the profile picture can be updated, so we handle the file upload here
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file.filename != '':
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    # Update the profile picture path in the database
                    conn = sqlite3.connect(DATABASE)
                    cursor = conn.cursor()
                    cursor.execute('UPDATE Users SET profile_pic_path = ? WHERE UserID = ?',
                                   (filename, session['user_id']))
                    conn.commit()
                    cursor.close()
                    conn.close()

        return render_template('User/UserProfile.html', user=user)
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@user_routes.route('/user/security_logs')
def security_logs_user():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the security logs related to the user
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM SecurityLogs WHERE UserID = ?', (session['user_id'],))

        logs = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('User/UserSecurityLogs.html', logs=logs)
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@user_routes.route('/history')
def history():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user's history
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Diagnoses WHERE UserID = ? ORDER BY DiagnosisDate DESC',
                       (session['user_id'],))

        history = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('User/userHistory.html', history=history)
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))
