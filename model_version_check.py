import joblib
from joblib import dump

# Assuming `model` is your trained model or transformer

# Load the model
model = joblib.load('model\models url\scaler.joblib')
# dump(model, 'new_model_filename.joblib')
# Check if the version attribute exists
if hasattr(model, '__version__'):
    print(f"Model was trained with scikit-learn version: {model.__version__}")
else:
    print("Version information not found in the model.")


if hasattr(model, 'n_features_in_'):
    print(f"The model expects {model.n_features_in_} features as input.")
else:
    print("The model does not have the 'n_features_in_' attribute.")


vectorizer = joblib.load('model\models url\scaler(1).joblib')

# Get feature names
if hasattr(vectorizer, 'get_feature_names_out'):
    feature_names = vectorizer.get_feature_names_out()
    print("Feature names:", feature_names)
else:
    print("This vectorizer does not support feature name extraction.")