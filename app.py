from flask import Flask, request, jsonify
import pandas as pd
import numpy as np
from flask_cors import CORS
import joblib
from translate import Translator
import nltk
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import CountVectorizer
import re
import os
import requests
import urllib.parse

app = Flask(__name__)
CORS(app)

# Ensure nltk resources are downloaded
nltk.download('stopwords')

# Load the data and the trained model using relative paths
data_path = os.path.join(os.path.dirname(__file__), 'Data', '1.csv')
model_path = os.path.join(os.path.dirname(__file__), 'Models', 'stack.sav')

data = pd.read_csv(data_path, encoding='latin')
data.rename(columns={'v1': 'Class', 'v2': 'Text'}, inplace=True)
data['numClass'] = data['Class'].map({'ham': 0, 'spam': 1})
data['Count'] = data['Text'].apply(len)

# Define stop words
stopset = set(stopwords.words("english"))

# Initialize CountVectorizer without stop words
vectorizer = CountVectorizer(stop_words=None, binary=True)
vectorizer.fit(data['Text'])

loaded_model = joblib.load(model_path)

def translate_to_english(text):
    try:
        translator = Translator(to_lang='en')
        translated_text = translator.translate(text)
        return translated_text
    except Exception as e:
        print(f"Translation error: {e}")
        return text

def extract_urls(text):
    # Regular expression pattern to match URLs
    url_pattern = r'https?://\S+|www\.\S+'
    # Find all URLs in the text
    urls = re.findall(url_pattern, text)
    for url in urls:
        text = text.replace(url, '')
    return urls

@app.route('/spam-detection', methods=['POST'])
def predict():
    try:
        # Get the message from the request
        message1 = str(request.json.get('message', ''))
        print("Input message:", message1)
        message2 = translate_to_english(message1)
        
        # Transform the message
        message_vectorized = vectorizer.transform([message2])
        
        # Predict whether the message is spam or legitimate
        prediction = loaded_model.predict(message_vectorized)
        
        # Return the prediction
        result = "1" if prediction == 1 else "0"
        urls = extract_urls(message1)
        print("Extracted URLs:", urls)
        
        return jsonify({'translated_message': result, 'extracted_urls': urls})
    
    except KeyError as ke:
        print(f"KeyError: {ke}")
        return jsonify({'error': 'Invalid request format'}), 400
    except Exception as e:
        print(f"Exception: {e}")
        return jsonify({'error': 'An error occurred during prediction'}), 500

@app.route("/url-content-analyze", methods=['POST'])
def url_content_analyze():
    key = 'OfkP2146kTwMTTGU5h28OvhacBj6HSVV'
    def malicious_url_scanner_api(url: str, vars: dict = {}) -> dict:
        api_url = f'https://www.ipqualityscore.com/api/json/url/{key}/{urllib.parse.quote_plus(url)}'
        response = requests.get(api_url, params=vars)
        return response.json()

    URL = request.json.get('url', '')
    strictness = 0
    additional_params = {'strictness': strictness}
    result = malicious_url_scanner_api(URL, additional_params)
    
    if 'success' in result and result['success'] == True:
        print(result)
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4000)