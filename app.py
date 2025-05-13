import re
from urllib.parse import urlparse
import pickle
from flask import Flask, render_template, request, jsonify
import numpy as np
import mysql.connector
import urllib.parse
import tldextract

app = Flask(__name__)

# Database configuration
db_config = {
    'host': 'localhost',          # Replace with your MySQL host
    'user': 'root',               # Replace with your MySQL username
    'password': 'password',     # Replace with your MySQL password
    'database': 'phishing_detection_system'  # Replace with your database name
}

# Function to connect to the database
def get_db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

# Load the trained model
with open("phishing_detection_model.pkl", "rb") as file:
    model = pickle.load(file)  # Replace 'model.pkl' with your actual model file name

# Function to add a URL and result to the database
def add_url_to_db(url, result):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert into the Phishing table
        query = "INSERT INTO Phishing (URL, Result) VALUES (%s, %s)"
        cursor.execute(query, (url, result))
        conn.commit()

        cursor.close()
        conn.close()

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# Function to get all URLs from the database
def get_urls_from_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch all records from the Phishing table
        query = "SELECT * FROM Phishing"
        cursor.execute(query)
        records = cursor.fetchall()

        cursor.close()
        conn.close()

        return records
    except Exception as e:
        print(f"Error: {e}")
        return []

# Route to check if a URL is phishing or legitimate
@app.route('/check', methods=['POST'])
def check_url():
    # Get the URL from the user input
    user_url = request.form.get('url')

    if not user_url:
        return jsonify({'error': 'URL is required'}), 400

    # Fetch all URLs from the database
    database_urls = get_urls_from_db()

    # Compare the user's URL with the URLs in the database
    for record in database_urls:
        if record['URL'] == user_url:
            # If the URL matches, check the result
            if record['Result'] == 1:
                return render_template('Phishing.html',url=user_url)  # Phishing URL
            else:
                return render_template('Legitimate.html',url=user_url)  # Legitimate URL

    # If the URL is not found in the database
    return render_template('Unknown.html')  # Unknown URL

# Route for the home page
@app.route('/')
def home():
    return render_template('final.html')  # Load the frontend HTML

# Route for about us page
@app.route('/about_us')
def about_us():
    return render_template('aboutus.html')


@app.route('/project_resources')
def resources():
    return render_template('resources.html')

@app.route('/project_info')
def project_info():
    return render_template('project_info.html')

# Route to predict if a URL is phishing or legitimate
@app.route('/predict', methods=['POST'])
def predict():
    # Get the input URL from the form
    input_url = request.form.get('url')  # Assuming input field name is "url" in the HTML form

    if not input_url:
        return jsonify({'error': 'URL is required'}), 400

    # Fetch all URLs from the database
    database_urls = get_urls_from_db()

    # Compare the user's URL with the URLs in the database
    for record in database_urls:
        if record['URL'] == input_url:
            # If the URL matches, check the result
            if record['Result'] == 1:
                return render_template('Phishing.html',url=input_url)  # Phishing URL
            else:
                return render_template('Legitimate.html',url=input_url)  # Legitimate URL

    # If the URL is not found in the database, extract features and predict
    features = extract_features(input_url)
    features = np.array(features).reshape(1, -1)  # Reshape for the model

    # Make prediction
    prediction = model.predict(features)[0]  # Get the prediction result
    add_url_to_db(input_url, prediction)  # Add the URL and prediction to the database

    # Return the appropriate template based on the prediction
    if prediction == 1:
        return render_template('Phishing.html',url=input_url)
    else:
        return render_template('Legitimate.html',url=input_url)

# Function to extract features from a URL
def extract_features(url_entered):
    """
    Parse a URL and extract features for phishing detection.
    
    Args:
        url_entered (str): The URL to parse.
    
    Returns:
        list: A list of feature values.
    """
    # Handle URLs without 'https://' or 'http://'
    if '://' not in url_entered:
        url_entered = 'https://' + url_entered

    # Extract the part after 'https://' or 'http://'
    url = url_entered.split('://')[1] if '://' in url_entered else url_entered

    parsed_url = urllib.parse.urlparse(url)
    extracted_domain = tldextract.extract(url)
    
    features = [
        url.count('/'),  # qty_slash_url
        len(url),  # length_url
        url.count('='),  # qty_equal_url
        url.count(extracted_domain.suffix),  # qty_tld_url
        url.count('-'),  # qty_hyphen_url
        url.count('_'),  # qty_underline_url
        url.count('&'),  # qty_and_url
        extracted_domain.domain.count('.'),  # qty_dot_domain
        extracted_domain.domain.count('-'),  # qty_hyphen_domain
        len(re.findall(r'[aeiouAEIOU]', extracted_domain.domain)),  # qty_vowels_domain
        1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', extracted_domain.domain) else 0,  # domain_in_ip
        len(extracted_domain.domain),  # domain_length
        extracted_domain.domain.count('_'),  # qty_underline_domain
        1 if 'server' in extracted_domain.domain or 'client' in extracted_domain.domain else 0,  # server_client_domain
        parsed_url.path.count('/'),  # qty_slash_directory
        parsed_url.path.count('?'),  # qty_questionmark_directory
        parsed_url.path.count('#'),  # qty_hashtag_directory
        parsed_url.path.count('!'),  # qty_exclamation_directory
        parsed_url.path.count(','),  # qty_comma_directory
        parsed_url.path.count('~'),  # qty_tilde_directory
        parsed_url.path.count(' '),  # qty_space_directory
        parsed_url.path.count('@'),  # qty_at_file
        parsed_url.path.count('!'),  # qty_exclamation_file
        parsed_url.path.count('&'),  # qty_and_file
        parsed_url.query.count('*'),  # qty_asterisk_params
        parsed_url.query.count('~'),  # qty_tilde_params
        parsed_url.query.count(' '),  # qty_space_params
        parsed_url.query.count('$'),  # qty_dollar_params
        parsed_url.query.count(','),  # qty_comma_params
        parsed_url.query.count('!'),  # qty_exclamation_params
    ]
    return features

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)