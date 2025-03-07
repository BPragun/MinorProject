# URL Phishing Detection System

## Overview
The **URL Phishing Detection System** is a machine learning-based solution designed to identify potentially malicious URLs. It analyzes various URL features and predicts whether a given website is legitimate or a phishing attempt. The system is built using Python and incorporates a database for storing URL records and detection results.

## Features
- Extracts key features from URLs for analysis.
- Utilizes machine learning algorithms to classify URLs.
- Stores analyzed URLs and results in a database.
- Provides a user-friendly interface for input and output.


## Installation
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/BPragun/MinorProject.git
   cd phishing-detection
   ```
2. **Install Dependencies**:
   ```sh
   pip install -r requirements.txt
   ```
3. **Set Up the Database**:
   - Ensure MySQL (or your preferred database) is installed.
   - Create a database and update the database configuration in the script.
   - Run database initialization scripts if provided.

4. **Run the Application**:
   ```sh
   python app.py
   ```

## Usage
1. **Input a URL**: Enter a website URL to analyze.
2. **Feature Extraction**: The system extracts key attributes of the URL.
3. **Prediction**: The trained machine learning model predicts whether the URL is phishing or legitimate.
4. **Results**: The classification result is displayed and stored in the database.



## Contributing
Feel free to fork the repository and submit pull requests for improvements.




