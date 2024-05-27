from flask import Blueprint, abort, request, redirect, url_for, render_template, session, flash
import sqlite3
import hashlib
from datetime import datetime
from .models import get_doctor_by_credentials, execute_query, get_db
from .utils import doctor_required

# Create a Blueprint for admin routes
doctor_routes = Blueprint('doctor_routes', __name__)

# Define the path to your SQLite database
DATABASE = 'SymptomDiagnoses.db'


# Define the Admin class
class Doctor:
    def __init__(self, id):
        self.id = id  # Set the admin ID


# Define the route for the doctor admin login page
@doctor_routes.route('/DoctorAdminLogin', methods=['GET', 'POST'])
def doctor_admin_login():
    if request.method == 'POST':
        # Handle form submission here
        pass
    else:
        # Render the DoctorAdminLogin.html template
        return render_template('DoctorAdminLogin.html')


# Define the route for the admin login page
@doctor_routes.route('/login_doctor', methods=['GET', 'POST'])
def login_doctor():
    warning = None  # Initialize a warning message
    if request.method == 'POST':
        # Collect login form data
        email = request.form.get('email')
        password = request.form['password']
        # Hash the password for secure storage
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Retrieve admin from the database
        account = get_doctor_by_credentials(email, password_hash)

        if account:
            # If the account exists, store admin information in session
            session['logged_in'] = True
            session['user_id'] = account[0]  # Store the admin ID in the session
            session['first_name'] = account[1]  # Store the first name in the session
            session['last_name'] = account[2]  # Store the last name in the session

            # Redirect to admin dashboard
            return redirect(url_for('doctor_routes.doctor_dashboard'))
        else:
            # Set the warning message
            warning = 'Invalid username or password.'
    # Render the AdminLogin.html template with the warning message
    return render_template('Doctor/DoctorLogin.html', warning=warning)


# Define the route for the admin dashboard
@doctor_routes.route('/doctor_dashboard')
def doctor_dashboard():
    # Check if the user is logged in and is an admin
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user's admin status
        try:
            # Connect to the SQLite database
            with sqlite3.connect(DATABASE) as conn:
                # Create a cursor object to execute SQL commands
                cursor = conn.cursor()
                # Execute an SQL command to select the admin ID from the Admins table where the admin ID matches the user ID in the session
                cursor.execute('SELECT DoctorID FROM Doctors WHERE DoctorID = ?', (session['user_id'],))
                # Fetch the first record from the result set
                admin = cursor.fetchone()
        except sqlite3.Error as e:
            # Print the error message if there's a database error
            print(e)
            # Redirect to the home page if there's a database error
            return redirect(url_for('home'))

        if admin:
            # If the admin exists, render the admin dashboard
            return render_template('Doctor/DoctorDashboard.html')
        else:
            # If the admin does not exist, redirect to the home page
            return redirect(url_for('home'))
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the admin profile page
@doctor_routes.route('/doctor_profile', methods=['GET', 'POST'])
def doctor_profile():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Execute an SQL command to select all columns from the Admins table where the admin ID matches the user ID in the session
        cursor.execute('SELECT * FROM Doctors WHERE DoctorID = ?', (session['user_id'],))
        # Fetch the first record from the result set
        doctor_tuple = cursor.fetchone()
        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        doctor = dict(zip(columns, doctor_tuple))
        # Close the cursor and the connection
        cursor.close()
        conn.close()
        # Render the AdminProfile.html template with the admin details
        return render_template('Doctor/DoctorProfile.html', doctor=doctor)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the edit admin profile form page
@doctor_routes.route('/edit_doctor_profile_form', methods=['GET'])
def edit_doctor_profile_form():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Execute an SQL command to select all columns from the Admins table where the admin ID matches the user ID in the session
        cursor.execute('SELECT * FROM Doctors WHERE DoctorID = ?', (session['user_id'],))
        # Fetch the first record from the result set
        doctor_tuple = cursor.fetchone()
        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        doctor = dict(zip(columns, doctor_tuple))
        # Close the cursor and the connection
        cursor.close()
        conn.close()
        # Render the EditAdminProfile.html template with the admin details
        return render_template('Doctor/DoctorProfile.html', doctor=doctor)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the edit admin profile page
@doctor_routes.route('/edit_doctor_profile', methods=['POST'])
def edit_doctor_profile():
    # Get the new email and mobile number from the form data
    new_email = request.form['email']
    new_mobile = request.form['mobile']
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select the email and mobile number from the Admins table where the admin ID matches the user ID in the session
    cursor.execute('SELECT Email, ContactInformation FROM Doctors WHERE DoctorID = ?', (session['user_id'],))
    # Fetch the first record from the result set
    old_email, old_mobile = cursor.fetchone()
    # If the new email is different from the old email, log the change

    # Execute an SQL command to update the email and mobile number in the Admins table where the admin ID matches the user ID in the session
    cursor.execute('UPDATE Doctors SET Email = ?, ContactInformation = ? WHERE DoctorID = ?',
                   (new_email, new_mobile, session['user_id']))
    # Commit the changes to the database
    conn.commit()
    # Close the cursor and the connection
    cursor.close()
    conn.close()
    # Redirect to the admin profile page
    return redirect(url_for('doctor_routes.doctor_profile'))


# Define the route for the users page
@doctor_routes.route('/usersDoctor')
def users():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select all columns from the Users table
    cursor.execute('SELECT * FROM Users')
    # Fetch all records from the result set
    users_tuples = cursor.fetchall()
    # Close the cursor and the connection
    cursor.close()
    conn.close()

    # Define the column names for the Users table
    columns = ['user_id', 'first_name', 'last_name', 'email', 'gender', 'date_of_birth', 'registration_date',
               'password', 'mobile']

    # Convert each tuple to a dictionary
    users = [dict(zip(columns, user_tuple)) for user_tuple in users_tuples]

    # Render the UsersTable.html template with the users data
    return render_template('Doctor/UsersTable.html', users=users)


from werkzeug.security import generate_password_hash, check_password_hash



@doctor_routes.route('/diagnosis')
def diagnosis():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select all columns from the Diagnoses table
    cursor.execute('SELECT * FROM Diagnoses')
    # Fetch all records from the result set
    diagnoses_tuples = cursor.fetchall()
    # Close the cursor and the connection
    cursor.close()
    conn.close()

    # Define the column names for the Diagnoses table
    columns = ['DiagnosisID', 'UserID', 'SymptomID', 'DiagnosisResult', 'DiagnosisDate']

    # Convert each tuple to a dictionary
    diagnoses = [dict(zip(columns, diagnosis_tuple)) for diagnosis_tuple in diagnoses_tuples]

    # Render the DiagnosesTable.html template with the diagnoses data
    return render_template('Doctor/Diagnosis.html', diagnoses=diagnoses)


# Define the route for the change password page
@doctor_routes.route('/change_doctor_password', methods=['GET', 'POST'])
@doctor_required
def change_doctor_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Validate input
        if not current_password or not new_password:
            flash('Current password and new password are required!', 'warning')
            return redirect(url_for('doctor_routes.change_password'))

        # Retrieve admin from the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT Password FROM Doctors WHERE DoctorID = ?', (session['user_id'],))
        password_hash = cursor.fetchone()[0]
        cursor.close()
        conn.close()

        # Check if current password is correct
        if not check_password_hash(password_hash, current_password):
            flash('Current password is incorrect.', 'warning')
            return redirect(url_for('doctor_routes.change_password'))

        # Update password in the database
        new_password_hash = generate_password_hash(new_password)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('UPDATE Doctors SET Password = ? WHERE DoctorID = ?', (new_password_hash, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Password changed successfully.', 'success')
        return redirect(url_for('doctor_routes.doctor_profile'))

    return render_template('Doctor/ChangePassword.html')
