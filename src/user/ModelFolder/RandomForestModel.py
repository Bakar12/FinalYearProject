import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from imblearn.over_sampling import SMOTE
import joblib

stroke_data = pd.read_excel('StrokeData.xlsx')

# Imputing missing values in 'bmi' based on the average BMI per gender
stroke_data['bmi'] = stroke_data.groupby('gender')['bmi'].transform(lambda x: x.fillna(x.mean()))

categorical_columns = ['gender', 'ever_married', 'work_type', 'Residence_type', 'smoking_status']
# %%
# Encoding categorical variables using Label Encoding
label_encoder = LabelEncoder()
for column in categorical_columns:
    stroke_data[column] = label_encoder.fit_transform(stroke_data[column])

# Display the updated DataFrame after imputation and encoding
stroke_data.head()

# Preparing the data for feature selection
X = stroke_data.drop(['stroke', 'id'], axis=1)  # Dropping 'id' as it's not a relevant feature
y = stroke_data['stroke']

# Splitting the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Apply SMOTE
smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)
rf_model_smote = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model_smote.fit(X_train_smote, y_train_smote)

joblib.dump(rf_model_smote, 'stroke_model.pkl')

model = joblib.load('stroke_model.pkl')
