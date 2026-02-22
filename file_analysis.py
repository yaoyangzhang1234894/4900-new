import zipfile
import hashlib
import os
import fitz  # PyMuPDF
import math
import email
from email import policy
from email.parser import BytesParser
import numpy as np
import joblib

#################################################
## Models
#################################################

try:
    model = joblib.load('model/file models/stacking_model.joblib')
    scaler = joblib.load('model/file models/scaler.joblib')
    print("Loaded models using first path.")
except FileNotFoundError:
    # Attempt to load models with the second path
    try:
        model = joblib.load('CSI-4900\\model\\file models\\stacking_model.joblib')
        scaler = joblib.load('CSI-4900\\model\\file models\\scaler.joblib')
        print("Loaded models using second path.")
    except FileNotFoundError:
        print("Error: Unable to load models from either path.")

#################################################
## Feature extraction
#################################################

def calculate_entropy(data):
    """Calculate Shannon entropy for a file."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def check_for_javascript(doc):
    """Check if the PDF contains JavaScript."""
    try:
        # Check annotations on each page
        for page_num in range(len(doc)):
            page = doc[page_num]
            annotations = page.annots()
            if annotations:
                for annotation in annotations:
                    if annotation.type[0] in [19, 20]:  # JavaScript Action Types
                        return True

        # Check document catalog and objects for JavaScript keywords
        for i in range(1, doc.xref_length()):
            obj = doc.xref_object(i)
            if any(keyword in obj for keyword in ["/JavaScript", "/JS", "/AA", "/OpenAction"]):
                return True

        return False
    except Exception as e:
        # Check for specific exception message
        if "document closed or encrypted" in str(e).lower():
            return True
        else:
            print(f"Error checking JavaScript: {e}")
            return False


def process_file(file_content):
    """Extract information from a PDF file."""
    try:
        doc = fitz.open(stream=file_content, filetype="pdf")
        metadata = doc.metadata
        pages = len(doc)
        entropy = calculate_entropy(file_content)

        # Calculate MetadataSize and TitleCharacters
        metadata_size = len(str(metadata)) if metadata else 0
        title_chars = len(metadata.get("title", "")) if metadata and "title" in metadata else 0

        xref_length = doc.xref_length()
        is_encrypted = doc.is_encrypted
        contains_javascript = check_for_javascript(doc)  # Check for JavaScript

        # Additional Features
        linearized = doc.is_fast_webaccess  # Check if the PDF is linearized
        form = doc.is_form_pdf  

        return {
            "FileName": "",  # Placeholder for file name, will be filled later
            "isEncrypted": is_encrypted,
            "MetadataSize": metadata_size,
            "Pages": pages,
            "XrefLength": xref_length,
            "TitleCharacters": title_chars,
            "Entropy": entropy,
            "ContainsJavaScript": contains_javascript,
            "Linearized": linearized,
            "Form": form
        }
    except Exception as e:
        return {
            "FileName": "",
            "isEncrypted": None,
            "MetadataSize": None,
            "Pages": None,
            "XrefLength": None,
            "TitleCharacters": None,
            "Entropy": None,
            "ContainsJavaScript": None,
            "Linearized": None,
            "Form": None,
            "Error": str(e)
        }

def extract_features_from_eml(eml_file):
    """Extract features from all the PDF files in an EML file."""
    
    msg = BytesParser(policy=policy.default).parse(eml_file)

    results = []
    
    # Loop through each attachment in the email
    for part in msg.iter_attachments():
        file_name = part.get_filename()
        if file_name:
            file_content = part.get_payload(decode=True)
            
            # Check for PDF file and process it
            if file_name.lower().endswith('.pdf'):
                file_info = process_file(file_content)
                file_info.update({
                    "FileName": file_name,
                    "FileSize": len(file_content),
                    # "Hash": hashlib.sha256(file_content).hexdigest()  # Add file hash
                })
                
                # Apply transformations to the extracted features
                file_info['isEncrypted'] = 1 if file_info['isEncrypted'] else 0
                file_info['ContainsJavaScript'] = 1 if file_info['ContainsJavaScript'] else 0
                file_info['Form'] = -1 if file_info['Form'] in [None, 'False'] else int(file_info['Form'])
                file_info['Linearized'] = 1 if file_info['Linearized'] == '1' else 0

                results.append(file_info)

    return results

    # '''
    # #################################################
    # ## Example usage (get features from eml file)
    # #################################################

    # eml_file_path = r'C:\Users\Nassim\Downloads\phishing_pot\pdf_emls\sample-638.eml'  # Path to your EML file
    # features = extract_features_from_eml(eml_file_path)

    # '''

#################################################
## Get result
#################################################

import joblib
import numpy as np

def predict_malicious(eml_file_path):
    """
    Predict if the given .eml file is malicious or benign based on its features.

    Parameters:
    - eml_file_path: str, path to the .eml file.
    - model_path: str, path to the trained model (.joblib).
    - scaler_path: str, path to the trained scaler (.joblib).

    Returns:
    - predictions: list of dictionaries containing predictions and confidence scores for each file.
    """
    # Extract features from the .eml file
    features = extract_features_from_eml(eml_file_path)

    # Load the model and scaler
    # model = joblib.load(model_path)
    # scaler = joblib.load(scaler_path)

    predictions = []

    # Process each extracted feature dictionary
    for feature_dict in features:
        # Remove 'FileName' from the feature dictionary
        feature_values = [feature_dict[key] for key in feature_dict if key != 'FileName']

        # Convert to a 2D array for the model (shape: 1 row, n columns)
        feature_array = np.array([feature_values])

        # Scale the features using the loaded scaler
        scaled_features = scaler.transform(feature_array)

        # Make the prediction
        prediction = model.predict(scaled_features)

        # Get the confidence score (probability)
        confidence_score = model.predict_proba(scaled_features)

        # For binary classification, confidence_score will have two columns: class 0 and class 1
        predicted_class = np.argmax(confidence_score)
        predicted_confidence = confidence_score[0][predicted_class]

        # Append result to the predictions list
        predictions.append({
            "FileName": feature_dict['FileName'],
            "Prediction": int(prediction[0]),
            "ConfidenceScore": float(predicted_confidence)
        })

    return predictions


def analyze_file_predictions(predictions):
    """
    Calculate the average confidence score and determine the overall status.

    Parameters:
    - predictions: list of dictionaries, where each dictionary contains:
        - 'FileName': str, name of the file
        - 'Prediction': int, 0 (benign) or 1 (malicious)
        - 'ConfidenceScore': float, confidence score for the prediction

    Returns:
    - result: dict containing:
        - 'AverageConfidenceScore': float, average adjusted confidence score
        - 'OverallStatus': int, 1 (malicious) if average confidence > 50, otherwise 0 (benign)
    """


    # Calculate adjusted confidence scores and sum them
    total_score = 0
    for item in predictions:
        score = item['ConfidenceScore']
        if item['Prediction'] == 0:
            score = 1 - score  # Adjust score for benign predictions
        total_score += score

    # Calculate the average confidence score
    average_score = total_score / len(predictions)

    # Determine the overall status


    return average_score


    

    


    # '''
    # #################################################
    # ## Example of result
    # #################################################

    # eml_file_path = r'C:\Users\Nassim\Downloads\benign5.eml'
    # model_path = r"C:\Users\Nassim\OneDrive\Documents\University\Session 9\CSI 4900\Notebooks\file joblib\stacking_model.joblib"
    # scaler_path = r"C:\Users\Nassim\OneDrive\Documents\University\Session 9\CSI 4900\Notebooks\file joblib\scaler.joblib"

    # results = predict_malicious(eml_file_path, model_path, scaler_path)

    # for result in results: # Print the results from all PDF files in the EML file
    #     print(f"File: {result['FileName']}")
    #     print(f"Prediction: {result['Prediction']}")
    #     print(f"Confidence Score: {result['ConfidenceScore']:.4f}")

    # '''

# eml_file_path = 'eml tests\malicious\sample-62.eml'


# with open(eml_file_path, 'rb') as eml_file:
#     results = predict_malicious(eml_file)
# print(eml_file)
# print(results)

# for result in results: # Print the results from all PDF files in the EML file
#     print(f"File: {result['FileName']}")
#     print(f"Prediction: {result['Prediction']}")
#     print(f"Confidence Score: {result['ConfidenceScore']:.4f}")

# print(analyze_file_predictions(results))

