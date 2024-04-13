import sqlite3
from flask import Flask, session, jsonify, url_for, redirect
app = Flask(__name__)
DATABASE = 'SymptomDiagnoses.db'
@app.route('/admin/security_logs/users')
def security_logs_users():
    if 'logged_in' in session and session['logged_in']:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM SecurityLogs WHERE UserID IS NOT NULL')
        logs = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(logs)
    else:
        return redirect(url_for('login'))

@app.route('/admin/security_logs/admins')
def security_logs_admins():
    if 'logged_in' in session and session['logged_in']:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM SecurityLogs WHERE AdminID IS NOT NULL')
        logs = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(logs)
    else:
        return redirect(url_for('login'))
def log_login_attempt(user_id, action_type, action_date, action_details, login_success):
    conn = sqlite3.connect('SymptomDiagnoses.db')
    cursor = conn.cursor()

    cursor.execute("""
            INSERT INTO SecurityLogs (UserID, ActionType, ActionDate, ActionDetails)
            VALUES (?, ?, ?, ?)
        """, (user_id, action_type, action_date, action_details))

    conn.commit()
    conn.close()

# Add more functions as needed to interact with the SecurityLogs table