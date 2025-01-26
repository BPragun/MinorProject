# # from flask import Flask, request, jsonify

# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import joblib
# import pandas as pd

# # Initialize Flask app
# app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes

# # Load the phishing detection model
# model = joblib.load("phishing_detection_model.pkl")  # Replace with your model's filename

# # Define a route for predicting phishing URLs
# @app.route('/predict', methods=['POST'])
# def predict():
#     try:
#         # Get the URL data from the request
#         data = request.get_json()
#         url = data.get('url')

#         if not url:
#             return jsonify({"error": "No URL provided"}), 400

#         # Preprocess the input (convert to a DataFrame or vectorize as needed)
#         # Assuming your model accepts a DataFrame
#         features = pd.DataFrame([{"url": url}])  # Update this as per your preprocessing pipeline

#         # Make prediction
#         prediction = model.predict(features)[0]
#         result = "Phishing" if prediction == 1 else "Legitimate"

#         # Return the result
#         return jsonify({"result": result})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# # Run the Flask app
# if __name__ == '__main__':
#     app.run(debug=True)


# app = Flask(__name__)

# @app.route('/')
# def home():
#     return 'Welcome to the Phishing Website Detection System!'

# @app.route('/check_url', methods=['POST'])
# def check_url():
#     # Get the URL from the POST request
#     url = request.json.get('url')
    
#     if url:
#         # Mock phishing detection for now
#         # Replace with your model later
#         is_phishing = "http" in url  # Simple check (replace with real model logic)
#         result = "Phishing detected" if is_phishing else "Safe site"
#         return jsonify({"url": url, "result": result}), 200
    
#     return jsonify({"message": "No URL provided"}), 400

# if __name__ == '__main__':
#     app.run(debug=True)





# from flask import Flask, render_template

# app = Flask(__name__)

# @app.route('/')
# def home():
#     return render_template('hp.html')  # Replace 'index.html' with your file name

# if __name__ == "__main__":
#     app.run(debug=True)

import re
from urllib.parse import urlparse
import pickle
from flask import Flask, render_template, request, jsonify
import joblib

app = Flask(__name__)

# Load the trained model
with open("phishing_detection_model.pkl", "rb") as file:
    model = pickle.load(file)  # Replace 'model.pkl' with your actual model file name

@app.route('/')
def home():
    return render_template('final.html')  # Load the frontend HTML

@app.route('/predict', methods=['POST'])
def predict():
    # Get the input URL from the form
    input_url = request.form.get('url')  # Assuming input field name is "url" in the HTML form
    
    # Perform feature extraction on the input (implement your feature extraction logic)
    features = extract_features(input_url)  # Replace with your actual feature extraction function
    
    # Make prediction
    prediction = model.predict([features])
    prediction_label = "Phishing" if prediction == 1 else "Legitimate"
    if prediction_label == "Phishing":
        return render_template('Phishing.html')
    else:
        return render_template('Legitimate.html')
    # Return the result to the frontend
    #return jsonify({'result': prediction_label})

def extract_features(url):
    """
    Define the feature extraction logic here.
    It should convert the input URL into a feature vector compatible with the model.
    """
    # Example: Replace with your real feature extraction logic
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query
    tld = domain.split('.')[-1] if '.' in domain else ""
    
    # Compute features
    features = [  len(url),  # Total length of the URL
         url.count('.'),  # Number of dots in the URL
         url.count('-'),  # Number of hyphens in the URL
         url.count('/'),  # Number of slashes in the URL
         domain.count('.'),  # Number of dots in the domain (TLD included)
         len(domain),  #t Length of the domain
         path.count('.'),  # Number of dots in the directory (path)
         1 if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", url) else 0  # Email present
    ]
    # Add your feature extraction code here
    return features

if __name__ == "__main__":
    app.run(debug=True)
