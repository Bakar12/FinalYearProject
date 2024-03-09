from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import hashlib
import joblib
import pandas as pd
from flask_login import LoginManager, login_user
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__)

# Load the trained model and any necessary preprocessing objects
model = joblib.load('stroke_model.pkl')

DATABASE = 'SymptomDiagnoses.db'
login_manager = LoginManager()
login_manager.init_app(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

app.secret_key = 'BakarsSecretKey'


class User:
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/')
def home():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the latest result
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Diagnoses WHERE UserID = ? ORDER BY DiagnosisDate DESC LIMIT 1',
                       (session['user_id'],))

        latest_result = cursor.fetchone()
        cursor.close()
        conn.close()

        if latest_result is None:
            # If there are no diagnoses for the user, render the template without the latest result
            return render_template('homePage.html')
        else:
            # If there is a latest diagnosis for the user, pass it to the template
            return render_template('homePage.html', latest_result=latest_result)
    else:
        # User is not logged in, render the template without the latest result
        return render_template('homePage.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/register', methods=['POST', 'GET'])
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


@app.route('/login', methods=['GET', 'POST'])
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


@app.route('/logout')
def logout():
    # Remove user information from session
    session.pop('logged_in', None)
    session.pop('first_name', None)
    return redirect(url_for('home'))


@app.route('/DoctorAdminLogin', methods=['GET', 'POST'])
def doctorAdminLogin():
    if request.method == 'POST':
        # Handle form submission here
        pass
    else:
        # Render the DoctorAdminLogin.html template
        return render_template('DoctorAdminLogin.html')


@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        # Collect login form data
        email = request.form['email']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Retrieve admin from the 'Admins' table by email and hashed password
        cursor.execute('SELECT * FROM Admins WHERE Email = ? AND Password = ?', (email, password_hash))
        account = cursor.fetchone()

        cursor.close()  # Close the cursor
        conn.close()  # Close the connection

        if account:
            # If the account exists, store admin information in session
            session['logged_in'] = True
            session['user_id'] = account[0]  # Assuming the admin ID is at index 0
            session['first_name'] = account[1]  # Assuming the first name is at index 1
            session['last_name'] = account[2]  # Assuming the last name is at index 2
            return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
        else:
            # If account does not exist or username/password incorrect
            return 'Login failed. Check your email and password.'

    # Render the login form template for GET requests
    return render_template('Admin/AdminLogin.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in and is an admin
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user's admin status
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))

        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin:
            # User is an admin, render the admin dashboard
            return render_template('Admin/AdminDashboard.html')
        else:
            # User is not an admin, redirect to the home page
            return redirect(url_for('home'))
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the admin details
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))

        admin_tuple = cursor.fetchone()
        cursor.close()
        conn.close()

        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        admin = dict(zip(columns, admin_tuple))

        if request.method == 'POST':
            # If the form has been submitted, update the admin details
            # Only the profile picture can be updated, so we handle the file upload here
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file.filename != '':
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    # Update the profile picture path in the database
                    conn = sqlite3.connect(DATABASE)
                    cursor = conn.cursor()
                    conn.commit()
                    cursor.close()
                    conn.close()

        return render_template('Admin/AdminProfile.html', admin=admin)
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@app.route('/user_feedback')
def user_feedback():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Feedback')
    feedbacks = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('Admin/UserFeedback.html', feedbacks=feedbacks)


@app.route('/security_logs')
def security_logs():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM SecurityLogs')
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('Admin/SecurityLogs.html', logs=logs)


@app.route('/doctors')
def doctors():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Doctors')
    doctors = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('Admin/Doctors.html', doctors=doctors)


@app.route('/add_admin', methods=['GET', 'POST'])
def add_admin():
    # Check if the user is logged in and is an admin with full permissions
    if 'logged_in' in session and session['logged_in']:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (session['user_id'],))

        permissions = cursor.fetchone()
        cursor.close()
        conn.close()

        if permissions and all(permissions[1:]):  # Check if all permissions are True
            # The user is an admin with full permissions, perform the action
            if request.method == 'POST':
                # Collect form data
                first_name = request.form['firstName']
                last_name = request.form['lastName']
                email = request.form['email']
                mobile = request.form['mobile']
                password = hashlib.sha256(request.form['password'].encode()).hexdigest()
                gender = request.form['gender']
                dob = request.form['dob']
                registration_date = datetime.now()

                # Collect permissions
                can_see_feedback = bool(request.form['canSeeFeedback'])
                can_see_security_logs = bool(request.form['canSeeSecurityLogs'])
                can_add_view_doctors = bool(request.form['canAddViewDoctors'])
                can_delete_view_users = bool(request.form['canDeleteViewUsers'])
                can_add_delete_admins = bool(request.form['canAddDeleteAdmins'])

                # Connect to the SQLite database
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()

                # Insert the new admin into the 'Admins' table
                cursor.execute(
                    'INSERT INTO Admins (FirstName, Surname, Email, Gender, DateOfBirth, RegistrationDate, mobile,'
                    ' Password) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (first_name, last_name, email, gender, dob, registration_date, mobile, password))

                # Get the ID of the new admin
                admin_id = cursor.lastrowid

                # Insert the admin's permissions into the 'AdminPermissions' table
                cursor.execute(
                    'INSERT INTO AdminPermissions (AdminID, CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors,'
                    ' CanDeleteViewUsers, CanAddDeleteAdmins) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (admin_id, can_see_feedback, can_see_security_logs, can_add_view_doctors, can_delete_view_users,
                     can_add_delete_admins))

                conn.commit()  # Commit changes
                cursor.close()  # Close the cursor
                conn.close()  # Close the connection

                return 'Admin added successfully.'
            else:
                # If it's a GET request, you might want to render a form here
                return render_template('Admin/AddAdmin.html')
        else:
            # The user is not an admin with full permissions, show an error message
            return 'You do not have the permission to add admins.', 403
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@app.route('/confirm_admin', methods=['POST'])
def confirm_admin():
    # Collect form data but don't add the admin to the database yet
    admin = {
        'first_name': request.form['firstName'],
        'last_name': request.form['lastName'],
        'email': request.form['email'],
        'mobile': request.form['mobile'],
        'password': hashlib.sha256(request.form['password'].encode()).hexdigest(),
        'gender': request.form['gender'],
        'dob': request.form['dob'],
        'can_see_feedback': bool(request.form.get('canSeeFeedback')),
        'can_see_security_logs': bool(request.form.get('canSeeSecurityLogs')),
        'can_add_view_doctors': bool(request.form.get('canAddViewDoctors')),
        'can_delete_view_users': bool(request.form.get('canDeleteViewUsers')),
        'can_add_delete_admins': bool(request.form.get('canAddDeleteAdmins'))
    }
    # Render the confirmation template
    return render_template('Admin/ConfirmAdmin.html', admin=admin)


@app.route('/add_admin_confirmed', methods=['POST'])
def add_admin_confirmed():
    # Now add the admin to the database
    admin = request.form.to_dict()
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if an admin with the same email already exists
    cursor.execute('SELECT * FROM Admins WHERE Email = ?', (admin['email'],))
    existing_admin = cursor.fetchone()

    if existing_admin is not None:
        # An admin with the same email already exists
        cursor.close()
        conn.close()
        return 'An admin with this email already exists.'

    # Convert boolean values to 1 or 0
    for key in ['can_see_feedback', 'can_see_security_logs', 'can_add_view_doctors', 'can_delete_view_users',
                'can_add_delete_admins']:
        admin[key] = 1 if admin[key] == 'True' else 0

    cursor.execute(
        'INSERT INTO Admins (FirstName, Surname, Email, Gender, DateOfBirth, RegistrationDate, mobile, Password) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (admin['first_name'], admin['last_name'], admin['email'], admin['gender'], admin['dob'], datetime.now(),
         admin['mobile'], admin['password']))
    admin_id = cursor.lastrowid
    cursor.execute(
        'INSERT INTO AdminPermissions (AdminID, CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors,'
        ' CanDeleteViewUsers, CanAddDeleteAdmins) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (admin_id, admin['can_see_feedback'], admin['can_see_security_logs'], admin['can_add_view_doctors'],
         admin['can_delete_view_users'], admin['can_add_delete_admins']))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('admin_summary', admin_id=admin_id))


@app.route('/admin_list')
def admin_list():
    if 'logged_in' in session and session['logged_in']:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (session['user_id'],))

        permissions = cursor.fetchone()

        if permissions:
            session['permissions'] = permissions[1:]  # Exclude the AdminID

        cursor.execute('SELECT * FROM Admins')
        admins = cursor.fetchall()
        cursor.execute('SELECT * FROM AdminPermissions')
        permissions = cursor.fetchall()
        admin_permission_pairs = zip(admins, permissions)
        cursor.close()
        conn.close()
        return render_template('Admin/AdminList.html', admin_permission_pairs=admin_permission_pairs)
    else:
        return redirect(url_for('login'))


@app.route('/admin_summary/<int:admin_id>')
def admin_summary(admin_id):
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Retrieve admin from the 'Admins' table by admin_id
    cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (admin_id,))
    admin = cursor.fetchone()

    # Retrieve admin permissions from the 'AdminPermissions' table by admin_id
    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    permissions = cursor.fetchone()

    cursor.close()  # Close the cursor
    conn.close()  # Close the connection

    if admin and permissions:
        # If the admin exists, pass the admin details and permissions to the template
        return render_template('Admin/ConfirmAdmin.html', admin=admin, permissions=permissions)
    else:
        # If admin does not exist, redirect to the admin list page
        return redirect(url_for('admin_list'))


@app.route('/add_doctor', methods=['POST'])
def add_doctor():
    # Check if the admin has the permission to add doctors
    if 'permissions' in session and session['permissions'][2]:
        # The admin has the permission to add doctors, perform the action
        pass
    else:
        # The admin does not have the permission to add doctors, show an error message
        flash('You do not have the permission to add doctors.')
        return redirect(url_for('dashboard'))


@app.route('/login_doctor', methods=['POST'])
def login_doctor():
    password = request.form.get('password')
    user_id = request.form.get('DoctorID')

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM Doctors WHERE DoctorID = ?", (user_id,))

    user = c.fetchone()
    conn.close()

    if user is None:
        flash('Doctor does not exist.')
        return redirect(url_for('login_doctor'))
    else:
        if check_password_hash(user[2], password):
            login_user(User(user_id))
            return redirect(url_for('dashboard'))
        else:
            flash('Password is incorrect.')
            return redirect(url_for('login_doctor'))


@app.route('/symptom-checker')
def index():
    return render_template('symptomInput.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user details
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE UserID = ?', (session['user_id'],))

        user_tuple = cursor.fetchone()
        cursor.close()
        conn.close()

        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
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




@app.route('/admin/security_logs')
def security_logs_admin():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, check if they are an admin
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))

        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin:
            # User is an admin, fetch all the security logs
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM SecurityLogs')

            logs = cursor.fetchall()
            cursor.close()
            conn.close()

            return render_template('Admin/SecurityLogs.html', logs=logs)
        else:
            # User is not an admin, redirect to the home page
            return redirect(url_for('home'))
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))

@app.route('/user/security_logs')
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


@app.route('/history')
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


@app.route('/predict', methods=['POST'])
def predict():
    # Extract data from form
    input_data = [
        float(request.form['age']),
        int(request.form['hypertension']),
        int(request.form['heart_disease']),
        request.form['gender'],
        request.form['ever_married'],
        request.form['work_type'],
        request.form['Residence_type'],
        float(request.form['avg_glucose_level']),
        float(request.form['bmi']),
        request.form['smoking_status']
    ]

    # Define the feature names in the same order as they were used during training
    feature_names = ['gender', 'age', 'hypertension', 'heart_disease', 'ever_married', 'work_type', 'Residence_type',
                     'avg_glucose_level', 'bmi', 'smoking_status']

    # Convert input data to DataFrame
    user_input_df = pd.DataFrame([input_data], columns=feature_names)

    # Use the trained model to predict the stroke likelihood
    rf_proba = model.predict_proba(user_input_df)[0][1]  # Probability of class 1 (stroke)

    # Convert to percentage
    stroke_risk_percentage = round(rf_proba * 100, 2)

    # Render the result
    return render_template('result.html', prediction=stroke_risk_percentage)


if __name__ == '__main__':
    app.run(debug=True)
