# src/model_loader.py
import joblib

def model_1():
    # Load the trained model and any necessary preprocessing objects
    model1 = joblib.load('user/ModelFolder/stroke_model.pkl')
    return model1


def model_2():
    # Load the trained model and any necessary preprocessing objects
    model2 = joblib.load('user/ModelFolder/LungCancer_model.pkl')
    return model2

def model_3():
    # Load the trained model and any necessary preprocessing objects
    model3 = joblib.load('user/ModelFolder/COVID-FLU-ALLERGY-Model.pkl')
    return model3