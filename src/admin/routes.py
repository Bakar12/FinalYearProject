from flask import Blueprint, abort, request, redirect, url_for, render_template, session, flash
import sqlite3
import hashlib
from datetime import datetime
from .models import get_admin_by_credentials, execute_query, add_admin_to_db, \
    add_doctor_to_db, get_db
from .utils import admin_required
from .SecurityLogsAdmin import log_admin_action

admin_routes = Blueprint('admin_routes', __name__)

DATABASE = 'SymptomDiagnoses.db'


class Admin:
    def __init__(self, id):
        self.id = id


@admin_routes.route('/DoctorAdminLogin', methods=['GET', 'POST'])
def doctor_admin_login():
    if request.method == 'POST':
        # Handle form submission here
        pass
    else:
        # Render the DoctorAdminLogin.html template
        return render_template('DoctorAdminLogin.html')


@admin_routes.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    warning = None
    """Handle admin login."""
    if request.method == 'POST':
        # Collect login form data
        email = request.form['email']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Retrieve admin from the database
        account = get_admin_by_credentials(email, password_hash)

        if account:
            # If the account exists, store admin information in session
            session['logged_in'] = True
            session['user_id'] = account[0]  # Assuming the admin ID is at index 0
            session['first_name'] = account[1]  # Assuming the first name is at index 1
            session['last_name'] = account[2]  # Assuming the last name is at index 2
            return redirect(url_for('admin_routes.admin_dashboard'))  # Redirect to admin dashboard
        else:
            warning = 'Invalid username or password.'
    return render_template('Admin/AdminLogin.html', warning=warning)


@admin_routes.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in and is an admin
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the user's admin status
        try:
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT AdminID FROM Admins WHERE AdminID = ?', (session['user_id'],))
                admin = cursor.fetchone()
        except sqlite3.Error as e:
            print(e)
            return redirect(url_for('home'))  # Redirect to home if there's a database error

        if admin:
            # User is an admin, render the admin dashboard
            return render_template('Admin/AdminDashboard.html')
        else:
            # User is not an admin, redirect to the home page
            return redirect(url_for('home'))
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@admin_routes.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    if 'logged_in' in session and session['logged_in']:
        # User is logged in, fetch the admin details
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        # Fetch the admin details
        cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (session['user_id'],))
        admin_tuple = cursor.fetchone()

        # Convert the tuple to a dictionary
        columns = [column[0] for column in cursor.description]
        admin = dict(zip(columns, admin_tuple))

        cursor.close()
        conn.close()
        # Render the AdminProfile.html template
        return render_template('Admin/AdminProfile.html', admin=admin)
    else:
        # User is not logged in, redirect to the login page
        return redirect(url_for('login'))


@admin_routes.route('/users')
def users():
    # Fetch the users data from the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users')
    users_tuples = cursor.fetchall()
    cursor.close()
    conn.close()

    # Define the column names for the Users table
    columns = ['user_id', 'first_name', 'last_name', 'email', 'gender', 'date_of_birth', 'registration_date',
               'password',
               'mobile']

    # Convert each tuple to a dictionary
    users = [dict(zip(columns, user_tuple)) for user_tuple in users_tuples]

    # Pass the users data to the template
    return render_template('Admin/UsersTable.html', users=users)


@admin_routes.route('/delete_user/<int:user_id>', methods=['GET'])
@admin_required
def confirm_delete_user(user_id):
    return render_template('Admin/ConfirmDelete/ConfirmDeleteUser.html', user_id=user_id)


@admin_routes.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user_confirmed(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Users WHERE UserID = ?', (user_id,))
    cursor.close()
    conn.commit()
    conn.close()
    flash('User deleted successfully.')
    return redirect(url_for('admin_routes.users'))


@admin_routes.route('/user_feedback')
def user_feedback():
    feedbacks = execute_query('SELECT * FROM Feedback')
    return render_template('Admin/UserFeedback.html', feedbacks=feedbacks)


@admin_routes.route('/security_logs')
def security_logs():
    logs = execute_query('SELECT * FROM SecurityLogs')
    return render_template('Admin/SecurityLogs.html', logs=logs)


@admin_routes.route('/doctors')
def doctors():
    # Fetch the doctors data from the database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Doctors')
    doctors_tuples = cursor.fetchall()
    cursor.close()
    conn.close()

    # Define the column names for the Doctors table
    columns = ['doctor_id', 'first_name', 'last_name', 'hospital_affiliation', 'specialization', 'qualifications',
               'state_license_number', 'contact_information', 'department', 'biography', 'email', 'password', 'gender']

    # Convert each tuple to a dictionary
    doctors = [dict(zip(columns, doctor_tuple)) for doctor_tuple in doctors_tuples]

    # Pass the doctors data to the template
    return render_template('Admin/Doctors.html', doctors=doctors)


@admin_routes.route('/add_doctor', methods=['GET'])
@admin_required
def add_doctor_form():
    # Render the AddDoctor form
    return render_template('Admin/AddUser/AddDoctor.html')


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
    # Render the confirmation template
    return render_template('Admin/ConfirmUser/ConfirmDoctor.html', doctor=doctor)


@admin_routes.route('/add_doctor_confirmed', methods=['POST'])
def add_doctor_confirmed():
    # Now add the doctor to the database
    doctor = request.form.to_dict()
    doctor_id = add_doctor_to_db(doctor)
    if doctor_id is None:
        flash('A doctor with this email already exists.')
        return redirect(url_for('admin_routes.add_doctor_form'))
    return redirect(url_for('admin_routes.doctors'))


@admin_routes.route('/delete_doctor/<int:doctor_id>', methods=['GET'])
@admin_required
def confirm_delete_doctor(doctor_id):
    return render_template('Admin/ConfirmDelete/ConfirmDeleteDoctor.html', doctor_id=doctor_id)


@admin_routes.route('/delete_doctor/<int:doctor_id>', methods=['POST'])
@admin_required
def delete_doctor_confirmed(doctor_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Doctors WHERE DoctorID = ?', (doctor_id,))
    cursor.close()
    conn.commit()
    conn.close()
    flash('Doctor deleted successfully.')
    return redirect(url_for('admin_routes.doctors'))


@admin_routes.route('/admin_list')
def admin_list():
    if 'logged_in' not in session or not session['logged_in']:
        abort(401)  # Unauthorized access

    conn = get_db()
    cursor = conn.cursor()
    # Fetch the admin permissions
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

    admin_permission_pairs = zip(admins, permissions)
    # Render the AdminList.html template
    return render_template('Admin/AdminList.html', admin_permission_pairs=admin_permission_pairs)


@admin_routes.route('/add_admin', methods=['GET'])
@admin_required
def add_admin_form():
    return render_template('Admin/AddUser/AddAdmin.html')


@admin_routes.route('/add_admin', methods=['POST'])
@admin_required
def add_admin():
    first_name = request.form['firstName']
    last_name = request.form['lastName']
    email = request.form['email']
    mobile = request.form['mobile']
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()
    gender = request.form['gender']
    dob = request.form['dob']
    registration_date = datetime.now()

    can_see_feedback = bool(request.form['canSeeFeedback'])
    can_see_security_logs = bool(request.form['canSeeSecurityLogs'])
    can_add_view_doctors = bool(request.form['canAddViewDoctors'])
    can_delete_view_users = bool(request.form['canDeleteViewUsers'])
    can_add_delete_admins = bool(request.form['canAddDeleteAdmins'])

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO Admins (FirstName, Surname, Email, Gender, DateOfBirth, RegistrationDate, mobile, Password) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (first_name, last_name, email, gender, dob, registration_date, mobile, password))
        admin_id = cursor.lastrowid
        cursor.execute(
            'INSERT INTO AdminPermissions (AdminID, CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors,'
            ' CanDeleteViewUsers, CanAddDeleteAdmins) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (admin_id, can_see_feedback, can_see_security_logs, can_add_view_doctors, can_delete_view_users,
             can_add_delete_admins))
    return 'Admin added successfully.'


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
    # Render the confirmation template
    return render_template('Admin/ConfirmUser/ConfirmAdmin.html', admin=admin)


@admin_routes.route('/add_admin_confirmed', methods=['POST'])
def add_admin_confirmed():
    # Now add the admin to the database
    admin = request.form.to_dict()
    admin_id = add_admin_to_db(admin)
    if admin_id is None:
        flash('An admin with this email already exists.')
        return redirect(url_for('admin_routes.add_admin_form'))

    # Log the admin action
    log_admin_action(session['user_id'], 'Add Admin', f'Added admin with ID {admin_id}')
    return redirect(url_for('admin_routes.admin_list'))


@admin_routes.route('/admin_summary/<int:admin_id>')
def admin_summary(admin_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM Admins WHERE AdminID = ?', (admin_id,))
    admin_tuple = cursor.fetchone()

    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    permissions_tuple = cursor.fetchone()

    if not admin_tuple or not permissions_tuple:
        return redirect(url_for('.admin_list'))

    # Convert the tuples to dictionaries
    columns = [column[0] for column in cursor.description]
    admin = dict(zip(columns, admin_tuple))
    permissions = dict(zip(columns, permissions_tuple))

    return render_template('Admin/ConfirmUser/ConfirmAdmin.html', admin=admin, permissions=permissions)


@admin_routes.route('/delete_admin/<int:admin_id>', methods=['GET'])
@admin_required
def confirm_delete_admin(admin_id):
    return render_template('Admin/ConfirmDelete/ConfirmDeleteAdmin.html', admin_id=admin_id)


@admin_routes.route('/delete_admin/<int:admin_id>', methods=['POST'])
@admin_required
def delete_admin_confirmed(admin_id):
    print(f"Deleting admin with ID: {admin_id}")  # Debug line

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM Admins WHERE AdminID = ?', (admin_id,))
    print(f"Admins affected: {cursor.rowcount}")  # Debug line

    cursor.execute('DELETE FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    print(f"AdminPermissions affected: {cursor.rowcount}")  # Debug line

    cursor.close()
    conn.commit()
    conn.close()

    flash('Admin deleted successfully.')
    return redirect(url_for('admin_routes.admin_list'))


@admin_routes.route('/modify_admin/<int:admin_id>', methods=['GET'])
@admin_required
def modify_admin(admin_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM AdminPermissions WHERE AdminID = ?', (admin_id,))
    permissions = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('Admin/ModifyAdmin.html', admin_id=admin_id, permissions=permissions)


@admin_routes.route('/update_admin_permissions', methods=['POST'])
@admin_required
def update_admin_permissions():
    admin_id = request.form['admin_id']
    permissions = {
        'can_see_feedback': bool(request.form.get('canSeeFeedback')),
        'can_see_security_logs': bool(request.form.get('canSeeSecurityLogs')),
        'can_add_view_doctors': bool(request.form.get('canAddViewDoctors')),
        'can_delete_view_users': bool(request.form.get('canDeleteViewUsers')),
        'can_add_delete_admins': bool(request.form.get('canAddDeleteAdmins'))
    }
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE AdminPermissions
        SET CanSeeFeedback = ?, CanSeeSecurityLogs = ?, CanAddViewDoctors = ?, CanDeleteViewUsers = ?, 
        CanAddDeleteAdmins = ?
        WHERE AdminID = ?
    """, (permissions['can_see_feedback'], permissions['can_see_security_logs'], permissions['can_add_view_doctors'],
          permissions['can_delete_view_users'], permissions['can_add_delete_admins'], admin_id))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('admin_routes.admin_list'))
