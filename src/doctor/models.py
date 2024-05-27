import sqlite3
from datetime import datetime

from flask import g

DATABASE = 'SymptomDiagnoses.db'


class Doctor:
    def __init__(self, id):
        self.id = id


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def get_doctor_by_credentials(email, password_hash):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM Doctors WHERE Email = ? AND Password = ?', (email, password_hash))
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




