import json
from datetime import datetime
import pandas as pd
from flask import request, render_template, Blueprint, abort, redirect, url_for
from sklearn.preprocessing import LabelEncoder
import sqlite3
from flask import session
from model_loader import model_1, model_2, model_3

symptom_diagnoses_app = Blueprint('symptom_diagnoses_app', __name__)
model1 = model_1()
model2 = model_2()
model3 = model_3()

DATABASE = 'SymptomDiagnoses.db'


# Function to get user data
def get_user(user_id):
    with sqlite3.connect(DATABASE) as conn:  # Use context manager for handling database connection
        cursor = conn.cursor()
        cursor.execute('SELECT Gender, DateOfBirth FROM Users WHERE UserID = ?', (user_id,))
        user = cursor.fetchone()
    if user is None:
        abort(404, "User not found")  # Raise HTTP error if user not found
    return user


# Function to calculate age from date of birth
def calculate_age(dob):
    dob_datetime = datetime.strptime(dob, '%Y-%m-%d')
    return datetime.now().year - dob_datetime.year


# Function to get input data from form
def get_input_data(form, fields):
    return [form.get(field, None) for field in fields]


# Function to create DataFrame and encode categorical variables
def create_dataframe(data, feature_names):
    df = pd.DataFrame([data], columns=feature_names)
    label_encoder = LabelEncoder()
    for variable in feature_names:
        df[variable] = label_encoder.fit_transform(df[variable])
    return df


@symptom_diagnoses_app.route('/predict', methods=['POST'])
def predict():
    user = get_user(session['user_id'])
    gender, dob = user
    age = calculate_age(dob)

    stroke_fields = ['hypertension', 'heart_disease', 'ever_married', 'work_type', 'Residence_type',
                     'avg_glucose_level', 'bmi', 'smoking_status']
    stroke_input_data = [gender, age] + get_input_data(request.form, stroke_fields)
    stroke_feature_names = ['gender', 'age', 'hypertension', 'heart_disease', 'ever_married', 'work_type',
                            'Residence_type', 'avg_glucose_level', 'bmi', 'smoking_status']
    stroke_input_df = create_dataframe(stroke_input_data, stroke_feature_names)

    lung_cancer_fields = ['smoking_status', 'yellow_fingers', 'anxiety', 'peer_pressure', 'chronic_disease', 'fatigue',
                          'allergy', 'wheeze', 'alcohol_consuming', 'cough', 'shortness_of_breath',
                          'swallowing_difficulty', 'chest_pain']
    lung_cancer_input_data = [gender, age] + get_input_data(request.form, lung_cancer_fields)
    lung_cancer_feature_names = ['GENDER', 'AGE', 'SMOKING', 'YELLOW_FINGERS', 'ANXIETY', 'PEER_PRESSURE',
                                 'CHRONIC DISEASE', 'FATIGUE ', 'ALLERGY ', 'WHEEZING', 'ALCOHOL CONSUMING', 'COUGHING',
                                 'SHORTNESS OF BREATH', 'SWALLOWING DIFFICULTY', 'CHEST PAIN']
    lung_cancer_input_df = create_dataframe(lung_cancer_input_data, lung_cancer_feature_names)

    CLA_fields = ['cough', 'muscle_aches', 'tiredness', 'sore_throat', 'runny_nose', 'stuffy_nose', 'fever', 'nausea',
                  'vomiting', 'diarrhea', 'shortness_of_breath', 'difficulty_breathing', 'loss_of_taste',
                  'loss_of_smell', 'itchy_nose',
                  'itchy_eyes', 'itchy_mouth', 'itchy_inner_ear', 'sneezing', 'pink_eye']
    CLA_input_data = get_input_data(request.form, CLA_fields)
    CLA_feature_names = [field.upper() for field in CLA_fields]
    CLA_input_df = create_dataframe(CLA_input_data, CLA_feature_names)
    CLA_probabilities = model3.predict_proba(CLA_input_df)[0]

    stroke_prediction = model1.predict_proba(stroke_input_df)[0][1]
    lung_cancer_prediction = model2.predict_proba(lung_cancer_input_df)[0][1]

    stroke_risk_percentage = round(stroke_prediction * 100, 2)
    lung_cancer_risk_percentage = round(lung_cancer_prediction * 100, 2)

    # A dictionary to map the probabilities to their corresponding diseases
    CLA_predictions = {
        'Flu': CLA_probabilities[0],
        'Allergy': CLA_probabilities[1],
        'Covid': CLA_probabilities[2],
        'Cold': CLA_probabilities[3]
    }

    # Find the disease with the highest probability
    CLA_disease = max(CLA_predictions, key=CLA_predictions.get)
    CLA_risk_percentage = round(CLA_predictions[CLA_disease] * 100, 2)

    # Create a dictionary to store the risk percentages and corresponding diseases
    predictions = {
        'Stroke': stroke_risk_percentage,
        'Lung Cancer': lung_cancer_risk_percentage,
        CLA_disease: CLA_risk_percentage  # Use the specific disease from the CLA model
    }
    # A dictionary to map the diseases to their descriptions
    disease_descriptions = {
        'Stroke': 'A stroke occurs when the blood supply to part of your brain is interrupted or reduced, preventing brain tissue from getting oxygen and nutrients.',
        'Lung Cancer': 'Lung cancer is a type of cancer that begins in the lungs. People who smoke have the greatest risk of lung cancer.',
        'Flu': 'Influenza is a viral infection that attacks your respiratory system — your nose, throat and lungs.',
        'Allergy': 'Allergies occur when your immune system reacts to a foreign substance.',
        'Covid': 'COVID-19 is a disease caused by a virus called SARS-CoV-2. Most people with COVID-19 have mild symptoms, but some people can become severely ill.',
        'Cold': 'The common cold is a viral infection of your nose and throat (upper respiratory tract).'
    }


    # Find the disease with the highest risk percentage
    disease = max(predictions, key=predictions.get)
    prediction = predictions[disease]
    disease_description = disease_descriptions.get(disease, '')

    symptom_fields = ['hypertension', 'heart_disease', 'ever_married', 'work_type', 'Residence_type',
                      'avg_glucose_level', 'bmi', 'smoking_status', 'yellow_fingers', 'anxiety', 'peer_pressure',
                      'chronic_disease', 'fatigue', 'allergy', 'wheeze', 'alcohol_consuming', 'cough',
                      'shortness_of_breath'
        , 'cough', 'muscle_aches',
                      'tiredness', 'sore_throat', 'runny_nose', 'stuffy_nose', 'fever', 'nausea',
                      'vomiting', 'diarrhea', 'shortness_of_breath', 'difficulty_breathing', 'loss_of_taste',
                      'loss_of_smell', 'itchy_nose', 'itchy_eyes', 'itchy_mouth', 'itchy_inner_ear', 'sneezing',
                      'pink_eye', 'swallowing_difficulty', 'chest_pain']

    symptoms = {field: request.form.get(field) for field in symptom_fields}
    # Convert the symptoms dictionary to a JSON string
    symptoms_json = json.dumps(symptoms)
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Insert the diagnosis into the 'Diagnoses' table
    cursor.execute("""
        INSERT INTO Diagnoses (UserID, Symptom, DiagnosisResult, DiagnosisDate)
        VALUES (?, ?, ?, ?)
        """, (session['user_id'], symptoms_json, disease, datetime.now()))

    # Commit your changes
    conn.commit()

    # Close the connection
    conn.close()

    return render_template('User/result.html', disease=disease, prediction=prediction, description=disease_description)


@symptom_diagnoses_app.route('/disclaimer', methods=['GET'])
def disclaimer():
    return render_template('User/disclaimer.html')


@symptom_diagnoses_app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        feedback_text = request.form.get('feedback_text')
        # Insert the feedback into the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Feedback (UserID, FeedbackText, FeedbackDate)
            VALUES (?, ?, ?)
            """, (session['user_id'], feedback_text, datetime.now()))
        conn.commit()
        conn.close()
        return redirect(url_for('symptom_diagnoses_app.thank_you'))
    return render_template('User/feedback.html')


@symptom_diagnoses_app.route('/thank_you', methods=['GET'])
def thank_you():
    return render_template('User/thank_you.html')


@symptom_diagnoses_app.route('/skip_feedback', methods=['GET'])
def skip_feedback():
    # Redirect to the desired page after skipping the feedback
    return redirect(url_for('home'))
