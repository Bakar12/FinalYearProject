import sqlite3
from datetime import datetime

from flask import g

DATABASE = 'SymptomDiagnoses.db'


class Admin:
    def __init__(self, id):
        self.id = id


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def get_admin_by_credentials(email, password_hash):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM Admins WHERE Email = ? AND Password = ?', (email, password_hash))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def execute_query(query):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
    return results


def add_admin_to_db(admin):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if an admin with the same email already exists
    cursor.execute('SELECT * FROM Admins WHERE Email = ?', (admin['email'],))
    existing_admin = cursor.fetchone()

    if existing_admin is not None:
        # An admin with the same email already exists
        cursor.close()
        conn.close()
        return None

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
    return admin_id


def add_doctor_to_db(doctor):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if a doctor with the same email already exists
    cursor.execute('SELECT * FROM Doctors WHERE Email = ?', (doctor['email'],))
    existing_doctor = cursor.fetchone()

    if existing_doctor is not None:
        # A doctor with the same email already exists
        cursor.close()
        conn.close()
        return None

    cursor.execute(
        'INSERT INTO Doctors (FirstName, LastName, Email, Gender, Password, HospitalAffiliation, Specialization, Qualifications, StateLicenseNumber, ContactInformation, Department, Biography) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (doctor['first_name'], doctor['last_name'], doctor['email'], doctor['gender'],
         doctor['password'], doctor['hospital_affiliation'], doctor['specialization'], doctor['qualifications'],
         doctor['state_license_number'], doctor['contact_information'], doctor['department'], doctor['biography']))
    doctor_id = cursor.lastrowid
    conn.commit()
    cursor.close()
    conn.close()
    return doctor_id
