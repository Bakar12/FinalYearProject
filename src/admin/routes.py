from flask import Blueprint, abort, request, redirect, url_for, render_template, session, flash
import sqlite3
import hashlib
from datetime import datetime
from .models import get_admin_by_credentials, execute_query, add_admin_to_db, \
    add_doctor_to_db, get_db
from .utils import admin_required
from .SecurityLogsAdmin import log_admin_action

# Create a Blueprint for admin routes
admin_routes = Blueprint('admin_routes', __name__)

# Define the path to your SQLite database
DATABASE = 'SymptomDiagnoses.db'


# Define the Admin class
class Admin:
    def __init__(self, id):
        self.id = id  # Set the admin ID


# Define the route for the doctor admin login page
@admin_routes.route('/DoctorAdminLogin', methods=['GET', 'POST'])
def doctor_admin_login():
    if request.method == 'POST':
        # Handle form submission here
        pass
    else:
        # Render the DoctorAdminLogin.html template
        return render_template('DoctorAdminLogin.html')


# Define the route for the admin login page
@admin_routes.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    warning = None  # Initialize a warning message
    if request.method == 'POST':
        # Collect login form data
        email = request.form['email']
        password = request.form['password']
        # Hash the password for secure storage
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Retrieve admin from the database
        account = get_admin_by_credentials(email, password_hash)

        if account:
            # If the account exists, store admin information in session
            session['logged_in'] = True
            session['user_id'] = account[0]  # Store the admin ID in the session
            session['first_name'] = account[1]  # Store the first name in the session
            session['last_name'] = account[2]  # Store the last name in the session
            session['is_first_login'] = account[9]  # Store the is_first_login status in the session

            # Log the admin action
            log_admin_action(session['user_id'], 'Login',
                             f'Admin {session["first_name"]} {session["last_name"]} logged in')

            # Check if this is the admin's first login
            if session['is_first_login']:
                # Redirect to the password change page
                return redirect(url_for('admin_routes.change_password'))
            else:
                # Redirect to admin dashboard
                return redirect(url_for('admin_routes.admin_dashboard'))
        else:
            # Set the warning message
            warning = 'Invalid username or password.'
    # Render the AdminLogin.html template with the warning message
    return render_template('Admin/AdminLogin.html', warning=warning)


# Define the route for the admin dashboard
@admin_routes.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in and is an admin
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user's admin status
        try:
            # Connect to the SQLite database
            with sqlite3.connect(DATABASE) as conn:
                # Create a cursor object to execute SQL commands
                cursor = conn.cursor()
                # Execute an SQL command to select the admin ID from the Admins table where the admin ID matches the
                # user ID in the session
                cursor.execute('SELECT AdminID FROM Admins WHERE AdminID = ?', (session['user_id'],))
                # Fetch the first record from the result set
                admin = cursor.fetchone()
        except sqlite3.Error as e:
            # Print the error message if there's a database error
            print(e)
            # Redirect to the home page if there's a database error
            return redirect(url_for('home'))

        if admin:
            # If the admin exists, render the admin dashboard
            return render_template('Admin/AdminDashboard.html')
        else:
            # If the admin does not exist, redirect to the home page
            return redirect(url_for('home'))
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the admin profile page
@admin_routes.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Execute an SQL command to select all columns from the Admins table where the admin ID matches the user ID
        # in the session
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))
        # Fetch the first record from the result set
        admin_tuple = cursor.fetchone()
        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        admin = dict(zip(columns, admin_tuple))
        # Close the cursor and the connection
        cursor.close()
        conn.close()
        # Render the AdminProfile.html template with the admin details
        return render_template('Admin/AdminProfile.html', admin=admin)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the edit admin profile form page
@admin_routes.route('/edit_admin_profile_form', methods=['GET'])
def edit_admin_profile_form():
    # Check if the user is logged in
    if 'logged_in' in session and session['logged_in']:
        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Execute an SQL command to select all columns from the Admins table where the admin ID matches the user ID in the session
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))
        # Fetch the first record from the result set
        admin_tuple = cursor.fetchone()
        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        admin = dict(zip(columns, admin_tuple))
        # Close the cursor and the connection
        cursor.close()
        conn.close()
        # Render the EditAdminProfile.html template with the admin details
        return render_template('Admin/EditAdminProfile.html', admin=admin)
    else:
        # If the user is not logged in, redirect to the login page
        return redirect(url_for('login'))


# Define the route for the edit admin profile page
@admin_routes.route('/edit_admin_profile', methods=['POST'])
def edit_admin_profile():
    # Get the new email and mobile number from the form data
    new_email = request.form['email']
    new_mobile = request.form['mobile']
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select the email and mobile number from the Admins table where the admin ID matches the user ID in the session
    cursor.execute('SELECT Email, mobile FROM Admins WHERE AdminID = ?', (session['user_id'],))
    # Fetch the first record from the result set
    old_email, old_mobile = cursor.fetchone()
    # If the new email is different from the old email, log the change
    if new_email != old_email:
        log_admin_action(session['user_id'], 'Edit Profile', f'Changed email from {old_email} to {new_email}')
    # If the new mobile number is different from the old mobile number, log the change
    if new_mobile != old_mobile:
        log_admin_action(session['user_id'], 'Edit Profile', f'Changed mobile from {old_mobile} to {new_mobile}')
    # Execute an SQL command to update the email and mobile number in the Admins table where the admin ID matches the user ID in the session
    cursor.execute('UPDATE Admins SET Email = ?, mobile = ? WHERE AdminID = ?',
                   (new_email, new_mobile, session['user_id']))
    # Commit the changes to the database
    conn.commit()
    # Close the cursor and the connection
    cursor.close()
    conn.close()
    # Redirect to the admin profile page
    return redirect(url_for('admin_routes.admin_profile'))


# Define the route for the users page
@admin_routes.route('/users')
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
    return render_template('Admin/UsersTable.html', users=users)


# Define the route for the confirm delete user page
@admin_routes.route('/delete_user/<int:user_id>', methods=['GET'])
@admin_required
def confirm_delete_user(user_id):
    # Render the ConfirmDeleteUser.html template with the user ID
    return render_template('Admin/ConfirmDelete/ConfirmDeleteUser.html', user_id=user_id)


# Define the route for the delete user confirmed page
@admin_routes.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user_confirmed(user_id):
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select the first name, surname, email, and mobile number from the Users table where the user ID matches the user ID in the URL
    cursor.execute('SELECT FirstName, Surname, Email, mobile FROM Users WHERE UserID = ?', (user_id,))
    # Fetch the first record from the result set
    user = cursor.fetchone()
    if user is None:
        # If the user does not exist, flash a message and redirect to the users page
        flash('User not found.')
        return redirect(url_for('admin_routes.users'))

    # Execute an SQL command to delete the user from the Users table where the user ID matches the user ID in the URL
    cursor.execute('DELETE FROM Users WHERE UserID = ?', (user_id,))
    # Close the cursor and commit the changes to the database
    cursor.close()
    conn.commit()
    conn.close()
    # Flash a success message
    flash('User deleted successfully.')

    # Log the admin action with the user details
    log_admin_action(session['user_id'], 'Delete User',
                     f'Deleted user with ID {user_id}, Name: {user[0]} {user[1]}, Email: {user[2]}, Number: {user[3]}')
    # Redirect to the users page
    return redirect(url_for('admin_routes.users'))


# Define the route for the user feedback page
@admin_routes.route('/user_feedback')
def user_feedback():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Feedback')
    feedbacks = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('Admin/UserFeedback.html', feedbacks=feedbacks)


# Define the route for the admin logs page
@admin_routes.route('/admin_logs')
def admin_logs():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select all columns from the SecurityLogs table
    cursor.execute('SELECT * FROM SecurityLogs')
    # Fetch all records from the result set
    security_logs = cursor.fetchall()
    # Execute an SQL command to select all columns from the AdminActions table
    cursor.execute('SELECT * FROM AdminActions')
    # Fetch all records from the result set
    admin_actions = cursor.fetchall()
    # Close the cursor and the connection
    cursor.close()
    conn.close()

    # Render the SecurityLogs.html template with the security logs and admin actions data
    return render_template('Admin/SecurityLogs.html', security_logs=security_logs, admin_actions=admin_actions)


# Define the route for the doctors page
@admin_routes.route('/doctors')
def doctors():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Execute an SQL command to select all columns from the Doctors table
    cursor.execute('SELECT * FROM Doctors')
    # Fetch all records from the result set
    doctors_tuples = cursor.fetchall()
    # Close the cursor and the connection
    cursor.close()
    conn.close()

    # Define the column names for the Doctors table
    columns = ['doctor_id', 'first_name', 'last_name', 'hospital_affiliation', 'specialization', 'qualifications',
               'state_license_number', 'contact_information', 'department', 'biography', 'email', 'password', 'gender']

    # Convert each tuple to a dictionary
    doctors = [dict(zip(columns, doctor_tuple)) for doctor_tuple in doctors_tuples]

    # Render the Doctors.html template with the doctors data
    return render_template('Admin/Doctors.html', doctors=doctors)


# Define the route for the add doctor form page
@admin_routes.route('/add_doctor', methods=['GET'])
@admin_required
def add_doctor_form():
    # Render the AddDoctor form
    return render_template('Admin/AddUser/AddDoctor.html')


# Define the route for the confirm doctor page
@admin_routes.route('/confirm_doctor', methods=['POST'])
def confirm_doctor():
    # Collect form data but don't add the doctor to the database yet
    doctor = {
        'first_name': request.form['firstName'],
        'last_name': request.form['lastName'],
        'email': request.form['email'],
        'password': hashlib.sha256(request.form['password'].encode()).hexdigest(),
        'gender': request.form['gender'],
        'hospital_affiliation': request.form['hospitalAffiliation'],
        'specialization': request.form['specialization'],
        'qualifications': request.form['qualifications'],
        'state_license_number': request.form['stateLicenseNumber'],
        'contact_information': request.form['contactInformation'],
        'department': request.form['department'],
        'biography': request.form['biography']
    }
    # Render the ConfirmDoctor.html template with the doctor data
    return render_template('Admin/ConfirmUser/ConfirmDoctor.html', doctor=doctor)


# Define the route for the add doctor confirmed page
@admin_routes.route('/add_doctor_confirmed', methods=['POST'])
def add_doctor_confirmed():
    # Now add the doctor to the database
    doctor = request.form.to_dict()
    doctor_id = add_doctor_to_db(doctor)
    if doctor_id is None:
        # Flash a message if a doctor with this email already exists
        flash('A doctor with this email already exists.')
        # Redirect to the add doctor form page
        return redirect(url_for('admin_routes.add_doctor_form'))

    # Log the admin action with doctor details
    log_admin_action(session['user_id'], 'Add Doctor',
                     f'Added doctor with ID {doctor_id}, Name: {doctor["first_name"]} {doctor["last_name"]}, '
                     f'Email: {doctor["email"]}, Gender: {doctor["gender"]}, '
                     f'Hospital Affiliation: {doctor["hospital_affiliation"]}, '
                     f'Specialization: {doctor["specialization"]}, '
                     f'State License Number: {doctor["state_license_number"]}, '
                     f'Contact Information: {doctor["contact_information"]}, Department: {doctor["department"]}')
    # Redirect to the doctors page
    return redirect(url_for('admin_routes.doctors'))


# Define the route for the confirm delete doctor page
@admin_routes.route('/delete_doctor/<int:doctor_id>', methods=['GET'])
@admin_required
def confirm_delete_doctor(doctor_id):
    # Render the ConfirmDeleteDoctor.html template with the doctor ID
    return render_template('Admin/ConfirmDelete/ConfirmDeleteDoctor.html', doctor_id=doctor_id)


# Define the route for the delete doctor confirmed page
@admin_routes.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
@admin_required
def delete_doctor_confirmed(doctor_id):
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Execute an SQL command to select the first name, last name, email, gender, hospital affiliation, specialization, state license number, contact information, and department from the Doctors table where the doctor ID matches the doctor ID in the URL
    cursor.execute(
        'SELECT FirstName, LastName, Email, Gender, HospitalAffiliation, Specialization, StateLicenseNumber, '
        'ContactInformation, Department FROM Doctors WHERE DoctorID = ?',
        (doctor_id,))
    # Fetch the first record from the result set
    doctor = cursor.fetchone()
    if doctor is None:
        # Flash a message if the doctor is not found
        flash('Doctor not found.')
        # Redirect to the doctors page
        return redirect(url_for('admin_routes.doctors'))

    # Execute an SQL command to delete the doctor from the Doctors table where the doctor ID matches the doctor ID in the URL
    cursor.execute('DELETE FROM Doctors WHERE DoctorID = ?', (doctor_id,))
    # Close the cursor and commit the changes to the database
    cursor.close()
    conn.commit()
    conn.close()
    # Flash a success message
    flash('Doctor deleted successfully.')

    # Log the admin action with doctor details
    log_admin_action(session['user_id'], 'Delete Doctor',
                     f'Deleted doctor with ID {doctor_id}, Name: {doctor[0]} {doctor[1]}, '
                     f'Email: {doctor[2]}, Gender: {doctor[3]}, '
                     f'Hospital Affiliation: {doctor[4]}, Specialization: {doctor[5]}, '
                     f'State License Number: {doctor[6]}, '
                     f'Contact Information: {doctor[7]}, Department: {doctor[8]}')
    # Redirect to the doctors page
    return redirect(url_for('admin_routes.doctors'))


# Define the route for the admin list page
@admin_routes.route('/admin_list')
def admin_list():
    # Check if the user is logged in
    if 'logged_in' not in session or not session['logged_in']:
        abort(401)  # Unauthorized access

    # Connect to the SQLite database
    conn = get_db()
    cursor = conn.cursor()
    # Fetch the admin permissions for the current user
    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (session['user_id'],))
    permissions = cursor.fetchone()
    # Check if the user has the permission to view the admin list
    if permissions:
        session['permissions'] = permissions[1:]  # Exclude the AdminID
    # Fetch all the admins
    cursor.execute('SELECT * FROM Admins')
    admins = cursor.fetchall()

    # Fetch all the admin permissions
    cursor.execute('SELECT * FROM AdminPermissions')
    permissions = cursor.fetchall()

    # Pair each admin with their permissions
    admin_permission_pairs = zip(admins, permissions)
    # Render the AdminList.html template with the admin permission pairs
    return render_template('Admin/AdminList.html', admin_permission_pairs=admin_permission_pairs)


# Define the route for the add admin form page
@admin_routes.route('/add_admin', methods=['GET'])
@admin_required
def add_admin_form():
    # Render the AddAdmin.html template
    return render_template('Admin/AddUser/AddAdmin.html')


# Define the route for the add admin page
@admin_routes.route('/add_admin', methods=['POST'])
@admin_required
def add_admin():
    # Collect form data
    first_name = request.form['firstName']
    last_name = request.form['lastName']
    email = request.form['email']
    mobile = request.form['mobile']
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()
    gender = request.form['gender']
    dob = request.form['dob']
    registration_date = datetime.now()

    # Collect admin permissions
    can_see_feedback = bool(request.form['canSeeFeedback'])
    can_see_security_logs = bool(request.form['canSeeSecurityLogs'])
    can_add_view_doctors = bool(request.form['canAddViewDoctors'])
    can_delete_view_users = bool(request.form['canDeleteViewUsers'])
    can_add_delete_admins = bool(request.form['canAddDeleteAdmins'])

    # Connect to the SQLite database
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Insert the new admin into the Admins table
        cursor.execute(
            'INSERT INTO Admins (FirstName, Surname, Email, Gender, DateOfBirth, RegistrationDate, mobile, Password) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (first_name, last_name, email, gender, dob, registration_date, mobile, password))
        admin_id = cursor.lastrowid
        # Insert the admin's permissions into the AdminPermissions table
        cursor.execute(
            'INSERT INTO AdminPermissions (AdminID, CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors,'
            ' CanDeleteViewUsers, CanAddDeleteAdmins) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (admin_id, can_see_feedback, can_see_security_logs, can_add_view_doctors, can_delete_view_users,
             can_add_delete_admins))
    # Return a success message
    return 'Admin added successfully.'


# Define the route for the confirm admin page
@admin_routes.route('/confirm_admin', methods=['POST'])
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
    # Render the ConfirmAdmin.html template with the admin data
    return render_template('Admin/ConfirmUser/ConfirmAdmin.html', admin=admin)


# Define the route for the add admin confirmed page
@admin_routes.route('/add_admin_confirmed', methods=['POST'])
def add_admin_confirmed():
    # Get the form data and add the admin to the database
    admin = request.form.to_dict()
    admin_id = add_admin_to_db(admin)
    # If the admin_id is None, an admin with this email already exists
    if admin_id is None:
        flash('An admin with this email already exists.')
        return redirect(url_for('admin_routes.add_admin_form'))

    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Fetch the admin details
    cursor.execute('SELECT FirstName, Surname, Email, Gender, mobile, DateOfBirth FROM Admins WHERE AdminID = ?',
                   (admin_id,))
    admin_details = cursor.fetchone()
    # Fetch the admin permissions
    cursor.execute(
        'SELECT CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors, CanDeleteViewUsers, '
        'CanAddDeleteAdmins FROM AdminPermissions WHERE AdminID = ?',
        (admin_id,))
    admin_permissions = cursor.fetchone()
    cursor.close()
    conn.close()

    # Log the admin action with admin details and permissions
    log_admin_action(session['user_id'], 'Add Admin',
                     f'Added admin with ID {admin_id}, Name: {admin_details[0]} {admin_details[1]}, '
                     f'Email: {admin_details[2]}, Gender: {admin_details[3]}, Mobile: {admin_details[4]}, '
                     f'DOB: {admin_details[5]}, '
                     f'Permissions: CanSeeFeedback={admin_permissions[0]}, CanSeeSecurityLogs={admin_permissions[1]}, '
                     f'CanAddViewDoctors={admin_permissions[2]}, '
                     f'CanDeleteViewUsers={admin_permissions[3]}, CanAddDeleteAdmins={admin_permissions[4]}')
    # Redirect to the admin list page
    return redirect(url_for('admin_routes.admin_list'))


# Define the route for the admin summary page
@admin_routes.route('/admin_summary/<int:admin_id>')
def admin_summary(admin_id):
    # Connect to the SQLite database
    conn = get_db()
    cursor = conn.cursor()

    # Fetch the admin details
    cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (admin_id,))
    admin_tuple = cursor.fetchone()

    # Fetch the admin permissions
    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    permissions_tuple = cursor.fetchone()

    # If the admin or permissions do not exist, redirect to the admin list page
    if not admin_tuple or not permissions_tuple:
        return redirect(url_for('.admin_list'))

    # Convert the tuples to dictionaries
    columns = [column[0] for column in cursor.description]
    admin = dict(zip(columns, admin_tuple))
    permissions = dict(zip(columns, permissions_tuple))

    # Render the ConfirmAdmin.html template with the admin and permissions data
    return render_template('Admin/ConfirmUser/ConfirmAdmin.html', admin=admin, permissions=permissions)


# Define the route for the confirm delete admin page
@admin_routes.route('/delete_admin/<int:admin_id>', methods=['GET'])
@admin_required
def confirm_delete_admin(admin_id):
    # Render the ConfirmDeleteAdmin.html template with the admin_id
    return render_template('Admin/ConfirmDelete/ConfirmDeleteAdmin.html', admin_id=admin_id)


# Define the route for the delete admin confirmed page
@admin_routes.route('/delete_admin/<int:admin_id>', methods=['POST'])
@admin_required
def delete_admin_confirmed(admin_id):
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Fetch the admin details before deleting
    cursor.execute('SELECT FirstName, Surname, Email, Gender, mobile, DateOfBirth FROM Admins WHERE AdminID = ?',
                   (admin_id,))
    admin = cursor.fetchone()
    # If the admin does not exist, flash a message and redirect to the admin list page
    if admin is None:
        flash('Admin not found.')
        return redirect(url_for('admin_routes.admin_list'))

    # Fetch the admin permissions before deleting
    cursor.execute(
        'SELECT CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors, CanDeleteViewUsers, '
        'CanAddDeleteAdmins FROM AdminPermissions WHERE AdminID = ?',
        (admin_id,))
    admin_permissions = cursor.fetchone()

    # Delete the admin from the Admins table
    cursor.execute('DELETE FROM Admins WHERE AdminID = ?', (admin_id,))
    cursor.close()
    conn.commit()
    conn.close()
    flash('Admin deleted successfully.')

    # Log the admin action with admin details and permissions
    log_admin_action(session['user_id'], 'Delete Admin',
                     f'Deleted admin with ID {admin_id}, Name: {admin[0]} {admin[1]}, '
                     f'Email: {admin[2]}, Gender: {admin[3]}, Mobile: {admin[4]}, DOB: {admin[5]}, '
                     f'Permissions: CanSeeFeedback={admin_permissions[0]}, CanSeeSecurityLogs={admin_permissions[1]}, '
                     f'CanAddViewDoctors={admin_permissions[2]}, CanDeleteViewUsers={admin_permissions[3]}, '
                     f'CanAddDeleteAdmins={admin_permissions[4]}')
    # Redirect to the admin list page
    return redirect(url_for('admin_routes.admin_list'))


# Define the route for the modify admin page
@admin_routes.route('/modify_admin/<int:admin_id>', methods=['GET'])
@admin_required
def modify_admin(admin_id):
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Fetch the admin permissions from the AdminPermissions table
    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    permissions = cursor.fetchone()
    cursor.close()
    conn.close()
    # Render the ModifyAdmin.html template with the admin_id and permissions
    return render_template('Admin/ModifyAdmin.html', admin_id=admin_id, permissions=permissions)


# Define the route for the update admin permissions page
@admin_routes.route('/update_admin_permissions', methods=['POST'])
@admin_required
def update_admin_permissions():
    # Get the admin_id from the form data
    admin_id = request.form['admin_id']
    # Get the permissions from the form data
    permissions = {
        'can_see_feedback': bool(request.form.get('canSeeFeedback')),
        'can_see_security_logs': bool(request.form.get('canSeeSecurityLogs')),
        'can_add_view_doctors': bool(request.form.get('canAddViewDoctors')),
        'can_delete_view_users': bool(request.form.get('canDeleteViewUsers')),
        'can_add_delete_admins': bool(request.form.get('canAddDeleteAdmins'))
    }
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Update the admin permissions in the AdminPermissions table
    cursor.execute("""
        UPDATE AdminPermissions
        SET CanSeeFeedback = ?, CanSeeSecurityLogs = ?, CanAddViewDoctors = ?, CanDeleteViewUsers = ?,
        CanAddDeleteAdmins = ?
        WHERE AdminID = ?
    """, (permissions['can_see_feedback'], permissions['can_see_security_logs'], permissions['can_add_view_doctors'],
          permissions['can_delete_view_users'], permissions['can_add_delete_admins'], admin_id))
    # Fetch the admin details from the Admins table
    cursor.execute('SELECT FirstName, Surname FROM Admins WHERE AdminID = ?', (admin_id,))
    admin = cursor.fetchone()
    # Fetch the old permissions from the AdminPermissions table
    cursor.execute(
        'SELECT CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors, CanDeleteViewUsers, '
        'CanAddDeleteAdmins FROM AdminPermissions WHERE AdminID = ?',
        (admin_id,))
    old_permissions = cursor.fetchone()
    conn.commit()
    cursor.close()
    conn.close()
    # Log the admin action with admin details and changed permissions
    log_admin_action(session['user_id'], 'Modify Admin',
                     f'Modified admin with ID {admin_id}, Name: {admin[0]} {admin[1]}, '
                     f'Changed permissions: CanSeeFeedback={old_permissions[0]}->{permissions["can_see_feedback"]}, '
                     f'CanSeeSecurityLogs={old_permissions[1]}->{permissions["can_see_security_logs"]}, '
                     f'CanAddViewDoctors={old_permissions[2]}->{permissions["can_add_view_doctors"]}, '
                     f'CanDeleteViewUsers={old_permissions[3]}->{permissions["can_delete_view_users"]}, '
                     f'CanAddDeleteAdmins={old_permissions[4]}->{permissions["can_add_delete_admins"]}')
    # Redirect to the admin list page
    return redirect(url_for('admin_routes.admin_list'))


from werkzeug.security import generate_password_hash, check_password_hash


# Define the route for the change password page
@admin_routes.route('/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Validate input
        if not current_password or not new_password:
            flash('Current password and new password are required!', 'warning')
            return redirect(url_for('admin_routes.change_password'))

        # Retrieve admin from the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT Password, is_first_login FROM Admins WHERE AdminID = ?', (session['user_id'],))
        password_hash, is_first_login = cursor.fetchone()
        cursor.close()
        conn.close()

        # Check if current password is correct
        if not check_password_hash(password_hash, current_password):
            flash('Current password is incorrect.', 'warning')
            return redirect(url_for('admin_routes.change_password'))

        # Update password and is_first_login in the database
        new_password_hash = generate_password_hash(new_password)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('UPDATE Admins SET Password = ?, is_first_login = 0 WHERE AdminID = ?',
                       (new_password_hash, session['user_id']))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Password changed successfully.', 'success')
        return redirect(url_for('admin_routes.admin_profile'))

    # If it's a GET request
    if session.get('is_first_login', False):
        flash('Since this is your first login, you need to enter a new password for yourself.', 'info')

    return render_template('Admin/ChangePassword.html')
