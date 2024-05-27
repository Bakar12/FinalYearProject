import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from imblearn.over_sampling import SMOTE
import joblib


# Function to remove outliers
def remove_outliers(df, column):
    Q1 = df[column].quantile(0.25)
    Q3 = df[column].quantile(0.75)
    IQR = Q3 - Q1
    df_out = df[~((df[column] < (Q1 - 1.5 * IQR)) | (df[column] > (Q3 + 1.5 * IQR)))]
    return df_out


# Load the dataset
file_path = 'C:/Users/abuba/OneDrive/Desktop/Computer Science Degree/Final Year Project/FinalWork/SystemDiagnoses/src/Datasets/LungCancer.csv'
LungCancerData = pd.read_csv(file_path)

# Remove outliers from the 'AGE' column
LungCancerData = remove_outliers(LungCancerData, 'AGE')

# Define categorical columns
categorical_columns = ['GENDER', 'SMOKING', 'YELLOW_FINGERS', 'ANXIETY', 'PEER_PRESSURE', 'CHRONIC DISEASE', 'FATIGUE ',
                       'ALLERGY ', 'WHEEZING', 'ALCOHOL CONSUMING', 'COUGHING', 'SHORTNESS OF BREATH',
                       'SWALLOWING DIFFICULTY', 'CHEST PAIN', 'LUNG_CANCER']

# Encoding categorical variables using Label Encoding
label_encoder = LabelEncoder()
for column in categorical_columns:
    LungCancerData[column] = label_encoder.fit_transform(LungCancerData[column])

# Standardize 'AGE'
scaler = StandardScaler()
LungCancerData['AGE'] = scaler.fit_transform(LungCancerData[['AGE']])

# Define your features and target variable
X = LungCancerData.drop(['LUNG_CANCER'], axis=1)
y = LungCancerData['LUNG_CANCER']

# Split your data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize 'AGE' in train and test sets
X_train['AGE'] = scaler.transform(X_train[['AGE']])
X_test['AGE'] = scaler.transform(X_test[['AGE']])

# Apply SMOTE
sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)

# Create a Decision Tree classifier with the best parameters
dt = DecisionTreeClassifier(criterion='gini', max_depth=None)

# Fit the model to the training data
dt.fit(X_train_res, y_train_res)

# Save the model
joblib.dump(dt, 'LungCancer_model.pkl')
