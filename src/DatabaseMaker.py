import sqlite3
import sqlite3
import hashlib

# Connect to your SQLite database
conn = sqlite3.connect('SymptomDiagnoses.db')

# Create a cursor object
c = conn.cursor()

# Define the admin details
admin_id = 1
first_name = 'Admin'
last_name = 'Admin'
email = 'admin@example.com'
gender = 'Male'
dob = '1980-01-01'
registration_date = '2023-01-01'
mobile = '1234567890'
password = ('adminPassword')
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# Insert the admin into the Admins table
c.execute("""
INSERT INTO Admins (AdminID, FirstName, Surname, Email, Gender, DateOfBirth, RegistrationDate, mobile, Password)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (admin_id, first_name, last_name, email, gender, dob, registration_date, mobile, hashed_password))

# Insert the admin's permissions into the AdminPermissions table
c.execute("""
INSERT INTO AdminPermissions (AdminID, CanSeeFeedback, CanSeeSecurityLogs, CanAddViewDoctors, CanDeleteViewUsers, CanAddDeleteAdmins)
VALUES (?, 1, 1, 1, 1, 1);
""", (admin_id,))

# Commit your changes
conn.commit()

# Close the connection
conn.close()

c.execute("""
ALTER TABLE Users ADD COLUMN profile_pic_path VARCHAR(255);

""")

# Execute your SQL commands
c.execute("""
CREATE TABLE Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    FirstName TEXT NOT NULL,
    Surname TEXT NOT NULL,
    Email TEXT UNIQUE NOT NULL,
    Gender TEXT NOT NULL CHECK(Gender IN ('Male', 'Female', 'Others')),
    DateOfBirth DATE NOT NULL,
    RegistrationDate DATETIME NOT NULL,
    mobile varchar(10) NOT NULL,
    Password TEXT NOT NULL -- Assuming password will be stored in a hashed format
);
""")

c.execute("""
CREATE TABLE Roles (
    RoleID INTEGER PRIMARY KEY AUTOINCREMENT,
    RoleName TEXT NOT NULL
);
""")


c.execute("ALTER TABLE Doctors ADD COLUMN Gender TEXT CHECK(Gender IN ('Male', 'Female', 'Others'));")

# Drop the existing Doctors table
c.execute("DROP TABLE IF EXISTS Doctors;")

# Create the new Doctors table
c.execute("""
CREATE TABLE Doctors (
    DoctorID INTEGER PRIMARY KEY,
    FirstName TEXT NOT NULL,
    LastName TEXT NOT NULL,
    HospitalAffiliation TEXT,
    Specialization TEXT,
    Qualifications TEXT,
    StateLicenseNumber TEXT,
    ContactInformation TEXT,
    Department TEXT,
    Biography TEXT,
    Email TEXT UNIQUE NOT NULL,
    Password TEXT NOT NULL
);
""")

# Commit your changes
conn.commit()

# Delete the existing Admins table
c.execute("DROP TABLE IF EXISTS Admins;")

# Create the new Admins table
c.execute("""
CREATE TABLE Admins (
    AdminID INTEGER PRIMARY KEY AUTOINCREMENT,
    FirstName TEXT NOT NULL,
    Surname TEXT NOT NULL,
    Email TEXT UNIQUE NOT NULL,
    Gender TEXT NOT NULL CHECK(Gender IN ('Male', 'Female', 'Others')),
    DateOfBirth DATE NOT NULL,
    RegistrationDate DATETIME NOT NULL,
    mobile varchar(10) NOT NULL,
    Password TEXT NOT NULL
);
""")

# Delete the existing AdminPermissions table
c.execute("DROP TABLE IF EXISTS AdminPermissions;")

# Create the new AdminPermissions table
c.execute("""
CREATE TABLE AdminPermissions (
    AdminID INTEGER PRIMARY KEY,
    CanSeeFeedback BOOLEAN NOT NULL,
    CanSeeSecurityLogs BOOLEAN NOT NULL,
    CanAddViewDoctors BOOLEAN NOT NULL,
    CanDeleteViewUsers BOOLEAN NOT NULL,
    CanAddDeleteAdmins BOOLEAN NOT NULL,
    FOREIGN KEY (AdminID) REFERENCES Admins(AdminID)
);
""")

c.execute("""
CREATE TABLE Symptoms (
    SymptomID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER,
    SymptomDescription TEXT,
    InputDate DATETIME,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
""")

c.execute("""
CREATE TABLE Diagnoses (
    DiagnosisID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER,
    SymptomID INTEGER,
    DiagnosisResult TEXT,
    DiagnosisDate DATETIME,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (SymptomID) REFERENCES Symptoms(SymptomID)
);
""")

c.execute("""
CREATE TABLE Feedback (
    FeedbackID INTEGER PRIMARY KEY AUTOINCREMENT,
    DiagnosisID INTEGER,
    UserID INTEGER,
    FeedbackText TEXT,
    FeedbackDate DATETIME,
    FOREIGN KEY (DiagnosisID) REFERENCES Diagnoses(DiagnosisID),
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
""")

c.execute("""
CREATE TABLE AdminActions (
    ActionID INTEGER PRIMARY KEY AUTOINCREMENT,
    AdminID INTEGER,
    ActionType TEXT,
    ActionDate DATETIME,
    ActionDetails TEXT,
    FOREIGN KEY (AdminID) REFERENCES Admins(AdminID)
);
""")
# Delete the existing AdminPermissions table
c.execute("DROP TABLE IF EXISTS SecurityLogs;")

c.execute("""
CREATE TABLE SecurityLogs (
    LogID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER NULL,
    AdminID INTEGER NULL,
    ActionType TEXT,
    ActionDate DATE,
    ActionDetails TEXT,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY(AdminID) REFERENCES Admins(AdminID)
);
""")


c.execute("""
CREATE TABLE HealthRecords (
    RecordID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER,
    RecordDetails TEXT,
    RecordDate DATETIME,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);
""")


# Commit your changes
conn.commit()

# Close the connection
conn.close()

cursor = conn.cursor()
cursor.execute('ALTER TABLE Feedback ADD COLUMN read BOOLEAN DEFAULT 0')
cursor.execute('ALTER TABLE Feedback ADD COLUMN addressed BOOLEAN DEFAULT 0')
conn.commit()
cursor.close()
conn.close()
