import sqlite3  # Import the sqlite3 module to work with SQLite databases
from datetime import datetime  # Import the datetime module to work with dates and times

DATABASE = 'SymptomDiagnoses.db'  # Define the path to your SQLite database


# Define a function to log admin actions
def log_admin_action(admin_id, action_type, action_details):
    conn = sqlite3.connect(DATABASE)  # Connect to your SQLite database
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands

    # Execute an SQL command to insert the admin action into the AdminActions table
    cursor.execute(
        'INSERT INTO AdminActions (AdminID, ActionType, ActionDate, ActionDetails) '
        'VALUES (?, ?, ?, ?)',
        (admin_id, action_type, datetime.now(),
         action_details))  # Use the datetime.now() function to get the current date and time

    conn.commit()  # Commit your changes to the database
    cursor.close()  # Close the cursor
    conn.close()  # Close the connection to the database
