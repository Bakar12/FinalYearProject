from flask import Flask, render_template, session
import sqlite3
import joblib
from flask_login import LoginManager
from Routes.User_Routes import user_routes, User
from admin.routes import admin_routes  # Import the admin_routes blueprint


app = Flask(__name__)
app.register_blueprint(user_routes)
app.register_blueprint(admin_routes)  # Register the admin_routes blueprint

# Load the trained model and any necessary preprocessing objects
model = joblib.load('stroke_model.pkl')

DATABASE = 'SymptomDiagnoses.db'
login_manager = LoginManager()
login_manager.init_app(app)
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

app.secret_key = 'BakarsSecretKey'


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE UserID = ?', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user[0])  # Assuming the user ID is at index 0
    return None


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


@app.route('/symptom-checker')
def index():
    return render_template('symptomInput.html')


if __name__ == '__main__':
    app.run(debug=True)
