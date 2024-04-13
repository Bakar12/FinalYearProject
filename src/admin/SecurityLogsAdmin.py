import sqlite3
from datetime import datetime

DATABASE = 'SymptomDiagnoses.db'


def log_admin_action(admin_id, action_type, action_details):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO SecurityLogs (AdminID, ActionType, ActionDate, ActionDetails) '
        'VALUES (?, ?, ?, ?)',
        (admin_id, action_type, datetime.now(), action_details))
    conn.commit()
    cursor.close()
    conn.close()
