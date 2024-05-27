import pandas as pd
import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedShuffleSplit
from imblearn.over_sampling import SMOTE

# Set constants
RANDOM_STATE = 42
FILE_PATH = 'src/Datasets/COVID-FLU-ALLERGY.csv'
MODEL_PATH = 'COVID-FLU-ALLERGY-Model.pkl'

# Load the dataset for Training
multiple_data_train = pd.read_csv(FILE_PATH)

# Instantiate the LabelEncoder
label_encoder = LabelEncoder()

# Fit the LabelEncoder on the 'TYPE' column of the training set
label_encoder.fit(multiple_data_train['TYPE'])

# Transform the 'TYPE' column of the training set
multiple_data_train['TYPE'] = label_encoder.transform(multiple_data_train['TYPE'])

# Instantiate the SMOTE object
smote = SMOTE(random_state=RANDOM_STATE)

# Define the features and target variable
X = multiple_data_train.drop(['TYPE'], axis=1).values
y = multiple_data_train['TYPE'].values

# Apply SMOTE
X_res, y_res = smote.fit_resample(X, y)

sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)

X_train, X_test, y_train, y_test = None, None, None, None


# Split the data into training and testing sets
for train_index, test_index in sss.split(X_res, y_res):
    X_train, X_test = X_res[train_index], X_res[test_index]
    y_train, y_test = y_res[train_index], y_res[test_index]


nb = GaussianNB()

nb.fit(X_train, y_train)

# Save the model
joblib.dump(nb, MODEL_PATH)

# Load the model to check if it's working fine
loaded_model = joblib.load(MODEL_PATH)
print(loaded_model)
