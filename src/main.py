from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import hashlib
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model and any necessary preprocessing objects
model = joblib.load('stroke_model.pkl')

DATABASE = 'SystemDiagnoses'
app.secret_key = 'your_secret_key'


@app.route('/')
def home():
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

        # Connect to the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Insert the new user into the 'users' table
        cursor.execute(
            'INSERT INTO users (FirstName, Surname, Email, Gender, DateOfBirth, Password, mobile) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (first_name, last_name, email, gender, dob, password_hash, mobile))
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
            session['first_name'] = account[1]  # Assuming the first name is at index 1
            session['last_name'] = account[2]  # Assuming the first name is at index 1
            # When setting the session after login

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


@app.route('/DAchoice')
def dachoice():
    return render_template('DoctorAdminLogin.html')


@app.route('/Doclogin', methods=['GET', 'POST'])
def doclogin():
    return render_template('Doctor/DoctorLogin.html')


@app.route('/Adminlogin', methods=['GET', 'POST'])
def adminlogin():
    return render_template('Admin/AdminLogin.html')


@app.route('/symptom-checker')
def index():
    return render_template('symptomInput.html')


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
