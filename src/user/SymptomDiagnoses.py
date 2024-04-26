import pandas as pd
from flask import request, render_template

from main import app, model

app.secret_key = 'BakarsSecretKey'


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
