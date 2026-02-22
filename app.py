from flask import Flask, request, jsonify, send_file
import joblib
from preprocessing import preprocessing_content
from flask_cors import CORS
import numpy as np
from eml_feature import extract_eml,extract_eml_body
import logging
from get_URL_features import extract_links,extract_features
import pandas as pd
from get_scores import get_average_similarity, get_result_from_database,query_link_similarity  # database score and CBR
from file_analysis import  predict_malicious,analyze_file_predictions
from concurrent.futures import ThreadPoolExecutor
from lime.lime_text import LimeTextExplainer
import os
import shap
import matplotlib.pyplot as plt
from io import BufferedReader, BytesIO

app = Flask(__name__)
CORS(app)

try:
    model = joblib.load('model/new email models/stacking_model.joblib')
    vectorizer = joblib.load('model/new email models/vectorizer.joblib')
    scaler = joblib.load('model/new email models/scaler_model.joblib')
    model_url = joblib.load('model/models url/stacking_model(2).joblib')
    scaler_url = joblib.load('model/models url/scaler(2).joblib')

    print("Loaded models using first path.")
except FileNotFoundError:
    # Attempt to load models with the second path
    try:
        model = joblib.load('CSI-4900\\model\\new email models\\stacking_model.joblib')
        vectorizer = joblib.load('CSI-4900\\model\\new email models\\vectorizer.joblib')
        scaler = joblib.load('CSI-4900\\model\\new email models\\scaler_model.joblib')
        model_url = joblib.load('CSI-4900\\model\\models url\\stacking_model(2).joblib')
        scaler_url = joblib.load('CSI-4900\\model\\models url\\scaler(2).joblib')

        print("Loaded models using second path.")
    except FileNotFoundError:
        print("Error: Unable to load models from either path.")


# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/analyze_email', methods=['POST'])
def analyze_email():

    ############################################################################################################################################################
    ## GET Content from EML file
    ############################################################################################################################################################

    # Initialize email_body to prevent UnboundLocalError
    email_body = None

    # Check if a file is included in the request
    if 'eml_file' in request.files:
        logging.info(f'Working with eml file')
        file_flag = 1
        file = request.files['eml_file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        # Read and decode content from the file directly
        try:
            email_content = extract_eml_body(file)
            # Check if email_content is a dictionary
            if isinstance(email_content, dict):
                email_body = email_content.get("body_plain", "")
            else:
                email_body = email_content  # Assume it's a string if not a dictionary
            email_info = preprocessing_content(email_body)
        except Exception as e:
            logging.error(f"Error extracting email content: {e}")
            return jsonify({"error": "Failed to process the email file"}), 400
    
    ############################################################################################################################################################
    ## GET Content from Pasting
    ############################################################################################################################################################

    else:
        # Get the email content from JSON
        file_flag = 0 
        email_content = request.json.get("email_content", "").strip()
        if not email_content:
            return jsonify({"error": "No email content provided"}), 400
        email_info = preprocessing_content(email_content)
        email_body = email_info.get("body", "")

    if not email_body:
        return jsonify({"error": "Email body is empty after processing"}), 400
    
    ############################################################################################################################################################
    ## File analysis
    ############################################################################################################################################################
    file.seek(0)
    file_bytes_io = BytesIO(file.read())
    
    # Convert BytesIO to BufferedReader
    file_buffered_reader = BufferedReader(file_bytes_io)
    file_analysis_result = []
    logging.info(f'file: {file_buffered_reader}')
    if file_flag == 1:
        file_analysis_result = predict_malicious(file_buffered_reader)

    logging.info(f'file analysis: {file_analysis_result}')
        

    ############################################################################################################################################################
    ## GET THE LINKS From Email body
    ############################################################################################################################################################

    links = extract_links(email_body)
    logging.info(f'Extracted Email Body: {email_body}')
    logging.info(f'Contain links: {links}')
    
    ############################################################################################################################################################
    ## Link Prediction (old version)
    ############################################################################################################################################################
    
    predictions_url = []
    # Process URL predictions if there are links
    # if links:
    #     for url in links:


    #         db_results = get_result_from_database(url)  

    #         #Get the similarity score using CBR
    #         cbr_score = get_average_similarity(url) 

    #         if db_results is not None:
    #             if db_results == 1 :
    #                 # If any database score is phishing, return phishing and stop further checks
    #                 predictions_url.append({
    #                     'url': url,
    #                     'prediction_label': "Spam",
    #                     'accuracy_model': "100.00%",  # Database result is conclusive
    #                     'spam_rate': 1.0,
    #                     'db_score': 1,
    #                     'cbr': cbr_score
    #                 })
    #                 continue
    #             elif db_results == 0:
    #                 # If any database score is benign, return safe and stop further checks
    #                 predictions_url.append({
    #                     'url': url,
    #                     'prediction_label': "Not Spam",
    #                     'accuracy_model': "100.00%",  # Database result is conclusive
    #                     'spam_rate': 0.0,
    #                     'db_score': 0,
    #                     'cbr': cbr_score
    #                 })
    #                 continue

    #         else:
            




    #             features = extract_features(url)
    #             features_df = pd.DataFrame([features])
    #             X_scaled_url = scaler_url.transform(features_df)
    #             prediction_proba_model_url = model_url.predict_proba(X_scaled_url)[0]
    #             accuracy_model_url = prediction_proba_model_url[1]
    #             prediction_label_url = "Spam" if accuracy_model_url > 0.5 else "Not Spam"
    #             predictions_url.append({
    #                 'url': url,
    #                 'prediction_label': prediction_label_url,
    #                 'accuracy_model': f"{max(prediction_proba_model_url[0], prediction_proba_model_url[1]) * 100:.2f}%",
    #                 'spam_rate': accuracy_model_url,
    #                 'db_score':db_results,
    #                 'cbr': cbr_score
    #             })

    # logging.info(f'PD: {predictions_url}')


    ############################################################################################################################################################
    ## Parallel running for link prediction 
    ############################################################################################################################################################
    
    #define three functions for url analysis
    def get_db_score(url):
        
        return get_result_from_database(url)
    
    def get_cbr_score(url):
       
        return get_average_similarity(url)

    def get_url_prediction(url):
        
        features = extract_features(url)
        features_df = pd.DataFrame([features])
        X_scaled_url = scaler_url.transform(features_df)
        prediction_proba_model_url = model_url.predict_proba(X_scaled_url)[0]
        accuracy_model_url = prediction_proba_model_url[1]
        prediction_label_url = "Spam" if accuracy_model_url > 0.5 else "Not Spam"
        return {
            'prediction_label': prediction_label_url,
            'accuracy_model': f"{max(prediction_proba_model_url[0], prediction_proba_model_url[1]) * 100:.2f}%",
            'spam_rate': accuracy_model_url
        }
    def get_similar_links(url, top_k=3):
        """
        Retrieve similar links for a given URL.
        """
        return query_link_similarity(url, top_k=top_k)
    def generate_similar_links_html(predictions):
        """
        Generate an HTML file with a table of similar links for all URLs.
        """
        html_file_path = "shap_explanation.html"
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Similar Links Analysis</title>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                    text-align: left;
                }}
                tr:hover {{background-color: #f5f5f5;}}
            </style>
        </head>
        <body>
            <h1>Similar Links Analysis</h1>
            <table>
                <tr>
                    <th>Original Link</th>
                    <th>Accuracy</th>
                    <th>Status</th>
                </tr>
        """
        for prediction in predictions:
            original_link = prediction['url']
            similar_links = prediction.get('similar_links', [])
            for similar in similar_links:
                similarity_percentage = f"{similar['similarity_score'] * 100:.2f}%"
                html_content += f"""
                    <tr>
                        <td>{original_link}</td>
                        <td>{similarity_percentage}</td>
                        
                        <td>{"Phishing" if similar['status'] == 1 else "Benign"}</td>
                    </tr>
                """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(html_file_path, "w", encoding="utf-8") as html_file:
            html_file.write(html_content)


    def process_url_parallel(url):
        #run code parallel
        with ThreadPoolExecutor() as executor:
            db_future = executor.submit(get_db_score, url)
            cbr_future = executor.submit(get_cbr_score, url)
            url_prediction_future = executor.submit(get_url_prediction, url)
            similar_links_future = executor.submit(get_similar_links, url, top_k=3)
            
            db_results = db_future.result()
            cbr_score = cbr_future.result()
            url_prediction = url_prediction_future.result()
            similar_links = similar_links_future.result()

        # Combine results based on priority
        if db_results is not None:
            if db_results == 1:
                return {
                    'url': url,
                    'prediction_label': "Spam",
                    'accuracy_model': "100.00%",
                    'spam_rate': 1.0,
                    'db_score': 1,
                    'cbr': cbr_score,
                    'similar_links': similar_links
                }
            elif db_results == 0:
                return {
                    'url': url,
                    'prediction_label': "Not Spam",
                    'accuracy_model': "100.00%",
                    'spam_rate': 0.0,
                    'db_score': 0,
                    'cbr': cbr_score,
                    'similar_links': similar_links
                }

        # Fallback to model prediction if no db_results
        return {
            'url': url,
            'prediction_label': url_prediction['prediction_label'],
            'accuracy_model': url_prediction['accuracy_model'],
            'spam_rate': url_prediction['spam_rate'],
            'db_score': db_results,
            'cbr': cbr_score,
            'similar_links': similar_links
        }
    
    if links:
        with ThreadPoolExecutor() as executor:
            predictions_url = list(executor.map(process_url_parallel, links))
        
        generate_similar_links_html(predictions_url)

    ############################################################################################################################################################
    ## Content Prediction
    ############################################################################################################################################################

    X_text = vectorizer.transform([email_body])
    X_scaled = scaler.transform(X_text.toarray())
    prediction_proba_model = model.predict_proba(X_scaled)[0]
    accuracy_model = prediction_proba_model[1]
    prediction_label = "Spam" if accuracy_model > 0.5 else "Not Spam"

    ############################################################################################################################################################
    ## LIME 
    ############################################################################################################################################################

    def predict_proba_with_reshape(X):
    

        # Ensure X is a list of strings (raw email content)
        if isinstance(X, np.ndarray) or isinstance(X, list):
            # Convert raw email content into numerical features using vectorizer
            X = vectorizer.transform(X)  # Outputs a sparse matrix

        # Convert sparse matrix to dense if necessary
        if not isinstance(X, np.ndarray):
            X = X.toarray()  # Ensure compatibility with scaler and model

        # Reshape if input is 1D
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        # Scale the data (if scaler is used)
        X = scaler.transform(X)

        # Return prediction probabilities
        return model.predict_proba(X)
    
    explainer = LimeTextExplainer(class_names=["Not Spam", "Spam"])
    explanation = explainer.explain_instance(
        email_body,  # Raw email text
        predict_proba_with_reshape,  # Prediction function
        num_features=10  # Number of features to highlight
    )
    explanation_file = "lime_explanation.html"
    explanation.save_to_file(explanation_file)
    ############################################################################################################################################################
    ## SHAP
    ############################################################################################################################################################

#######################################################################################################################################################################
#     # Function to tokenize and vectorize the email
#     def tokenize_and_vectorize(email_body):
#         """
#         Tokenizes the email and maps the SHAP values to the corresponding words.
#         """
#         # Vectorize the email body
#         X_vectorized = vectorizer.transform([email_body])
#         feature_names = vectorizer.get_feature_names_out()  # Get feature names (words/tokens)

#         # Convert the sparse matrix to dense
#         X_dense = X_vectorized.toarray()

#         return X_dense, feature_names

#     # SHAP-compatible prediction function
#     def predict_proba_for_shap(scaled_features):
#         """
#         Model prediction function for SHAP using scaled features.
#         """
#         return model.predict_proba(scaled_features)

    

#     # Step 1: Vectorize and scale the email
#     X_dense, feature_names = tokenize_and_vectorize(email_body)
#     X_scaled = scaler.transform(X_dense)

#     # Step 2: Initialize SHAP KernelExplainer
#     reference_data = np.zeros_like(X_scaled)  # Use a baseline of zeros
#     explainer = shap.KernelExplainer(predict_proba_for_shap, reference_data)

#     # Step 3: Compute SHAP values
#     shap_values = explainer.shap_values(X_scaled)
#     shap_values_class_1 = shap_values[0][:, 1]

#     # Step 4: Map SHAP values to tokens
#     tokens = email_body.split()  # Tokenize the email body
#     token_shap_values = []

#     logging.info(shap_values)
#     logging.info(shap_values.shape)
#     # Match tokens to SHAP values from vectorizer
#     for token in tokens:
#         if token in feature_names:
#             idx = list(feature_names).index(token)  # Find index of the token in feature names
#             token_shap_values.append(shap_values_class_1[idx])  # Append SHAP value for class 1 (Spam)
#         else:
#             token_shap_values.append(0)  # If token not in vectorizer, assign 0 SHAP value
            
#     # Convert token SHAP values to NumPy array
#     token_shap_values = np.array(token_shap_values)

#     # Step 5: Generate SHAP Explanation with Tokens
#     shap_explanation = shap.Explanation(
#         values=token_shap_values,  # SHAP values for tokens
#         data=tokens,               # Actual tokens from the email
#         base_values=explainer.expected_value[1]  # Baseline for Spam class
#     )
#     logging.info(feature_names)
#     # Step 6: Visualize and Save SHAP Explanation
    

# # Save the plot as an image
#     waterfall_plot_path=shap.waterfall_plot(shap_explanation)
#     plt.savefig(waterfall_plot_path, bbox_inches="tight")
#     plt.close()

    

#     # Step 5: Embed the Plot into an HTML File
#     html_file_path = "shap_explanation.html"
#     with open(html_file_path, "w", encoding="utf-8") as html_file:
#         html_file.write(f"""
#         <!DOCTYPE html>
#         <html>
#         <head>
#             <title>SHAP Waterfall Plot</title>
#         </head>
#         <body>
#             <h1>SHAP Waterfall Plot</h1>
#             <img src="{waterfall_plot_path}" alt="SHAP Waterfall Plot" style="width:80%;height:auto;">
#         </body>
#         </html>
#         """)



# # Save the force plot to an HTML file
#     shap.save_html("shap_explanation.html", force_plot)



    
    
    ############################################################################################################################################################
    ## Combine Result 
    ############################################################################################################################################################

    # Final output calculation

    if predictions_url:
    # Check if any URL in the list has a db_score of 1 or 0
        db_scores = [item.get('db_score', -1) for item in predictions_url]
        
        if 1 in db_scores:
            # If any db_score is 1, final label is Spam with 100% accuracy
            final_label = "Spam"
            final_accuracy = 1.0
        elif 0 in db_scores:
            # If any db_score is 0, final label is Not Spam with 100% accuracy
            final_label = "Not Spam"
            final_accuracy = 1.0
        else:
            # Extract values for accuracies, cbr, and db_score
            accuracies = [float(item['spam_rate']) for item in predictions_url]
            cbr_final = [float(item['cbr']) for item in predictions_url]
            db_final = [float(item['db_score']) for item in predictions_url if item.get('db_score') is not None]

            # Calculate averages for the respective lists
            average_db_list = sum(db_final) / len(db_final) if db_final else None
            average_cbr_list = sum(cbr_final) / len(cbr_final) if cbr_final else 0
            average_accuracy_list = sum(accuracies) / len(accuracies) if accuracies else 0

            if file_flag == 1 and len(file_analysis_result) >0:
                # Extract confidence scores and calculate the average
                file_confidences = analyze_file_predictions(file_analysis_result)
            

            # Final score calculation based on the presence of db scores
            if average_db_list is not None:
                if file_flag ==1 and len(file_analysis_result) >0:
                    final_output = (
                        0.3 * average_accuracy_list +
                        0.2 * accuracy_model +
                        0.1 * average_cbr_list +
                        0.1 * average_db_list +
                        0.3 * file_confidences
                    )
                else:
                    final_output = (
                        0.6 * average_accuracy_list +
                        0.2 * accuracy_model +
                        0.1 * average_cbr_list +
                        0.1 * average_db_list
                    )
            else:
                # Adjust formula if db scores are missing
                if file_flag ==1 and len(file_analysis_result) >0:
                    final_output = (
                        0.4 * average_accuracy_list +
                        0.2 * accuracy_model +
                        0.1 * average_cbr_list +
                        0.3 * file_confidences
                    )
                else:
                    final_output = (
                        0.7 * average_accuracy_list +
                        0.2 * accuracy_model +
                        0.1 * average_cbr_list 
                        
                    )

            # Determine final label and accuracy
            final_label = "Spam" if final_output > 0.5 else "Not Spam"
            final_accuracy = final_output if final_label == 'Spam' else 1 - final_output
    else:
        # Fallback if predictions_url is empty
        if file_flag == 1 and len(file_analysis_result) >0:
                # Extract confidence scores and calculate the average
                file_confidences = analyze_file_predictions(file_analysis_result)

                final_label = "Spam" if (0.1*accuracy_model+0.9* file_confidences) > 0.5 else "Not Spam"
                final_accuracy = 0.1*accuracy_model+0.9* file_confidences if final_label == 'Spam' else 1 - (0.1*accuracy_model+0.9* file_confidences)
        else:
            final_label = "Spam" if accuracy_model > 0.5 else "Not Spam"
            final_accuracy = accuracy_model if final_label == 'Spam' else 1 - accuracy_model




    # logging.info(f'DB: {db_final}, CBR: {cbr_final}')

    ############################################################################################################################################################
    ## Return Data
    ############################################################################################################################################################

    response_data = {
        "Model_Accuracy": f"{max(prediction_proba_model[0], prediction_proba_model[1]) * 100:.2f}%",
        "Prediction": prediction_label,
        "links": predictions_url,
        "output": f"{final_accuracy * 100:.2f}%",
        "OutputLabel": final_label,
        "LIME_Explanation_URL": f"http://127.0.0.1:5000/lime_explanation",
        "SHAP_Explanation_URL": f"http://127.0.0.1:5000/shap_explanation",
        "file_analysis": file_analysis_result
    }
    logging.info(f'Response Data: {response_data}')
    return jsonify(response_data)

@app.route('/lime_explanation', methods=['GET'])
def lime_explanation():
    return send_file("lime_explanation.html", mimetype="text/html")

@app.route('/shap_explanation', methods=['GET'])
def shap_explanation():
    return send_file("shap_explanation.html", mimetype="text/html")

if __name__ == '__main__':
    app.run(debug=True)