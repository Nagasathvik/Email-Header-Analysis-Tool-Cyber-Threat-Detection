#!/usr/bin/env python3
import os
import sys
import json
import re
import quopri
import hashlib
from datetime import datetime
from argparse import ArgumentParser
from email.parser import HeaderParser, BytesParser
from email import policy
import requests
import time
from html_generator import generate_table_from_json, verify_ip_address

import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from collections import defaultdict
import numpy as np
import joblib

# Add to imports
from virustotal_service import VirusTotalService
from config import ATTACHMENTS_DIR, LOGS_DIR
from db_handler import DatabaseHandler

# Download required NLTK data
try:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('wordnet')
except:
    pass

# Global Values
SUPPORTED_FILE_TYPES = ["eml"]
SUPPORTED_OUTPUT_TYPES = ["json", "html"]
LINK_REGEX = r'href=\"(https?:\/\/(?:\S)*)\"'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
DATE_FORMAT = "%B %d, %Y - %H:%M:%S"
TER_COL_SIZE = 60

class EnhancedSpamClassifier:
    def __init__(self):
        self.word_spam_probs = defaultdict(float)
        self.spam_indicators = {
            'urgency': r'urgent|immediately|hurry|limited time|act now|today only',
            'money': r'cash|money|\$|prize|win|won|offer|free|discount',
            'pressure': r'password|account|bank|verify|login|suspend|validate|cancel',
            'suspicious': r'click here|verify account|confirm identity|security alert'
        }
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.threshold = 0.5
        self.spam_prior = 0.0
        self.ham_prior = 0.0

    def extract_features(self, text):
        if not isinstance(text, str):
            return {}
        features = {
            'text_length': len(text),
            'caps_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'exclamation_count': text.count('!'),
            'url_count': len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
        }
        for category, pattern in self.spam_indicators.items():
            features[f'{category}_words'] = len(re.findall(pattern, text.lower()))
        return features

    def preprocess_text(self, text):
        if not isinstance(text, str):
            return []
        text = text.lower()
        text = re.sub(r'http\S+|www\S+|https\S+', '[URL]', text)
        text = re.sub(r'\S+@\S+', '[EMAIL]', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        words = word_tokenize(text)
        words = [self.lemmatizer.lemmatize(word) 
                for word in words 
                if word not in self.stop_words and len(word) > 2]
        return words

    def predict_probability(self, text):
        words = self.preprocess_text(text)
        features = self.extract_features(text)
        
        if not words:
            return 0.5
            
        score = np.log(max(self.spam_prior, 0.01) / max(self.ham_prior, 0.01))
        for word in words:
            if word in self.word_spam_probs:
                score += self.word_spam_probs[word]
        
        text_prob = 1 / (1 + np.exp(-score))
        
        feature_score = (
            features['caps_ratio'] * 0.3 +
            min(features['exclamation_count'], 3) * 0.2 +
            min(features['url_count'], 2) * 0.3 +
            sum(features[f'{cat}_words'] for cat in self.spam_indicators.keys()) * 0.2
        )
        
        combined_prob = (text_prob * 0.7 + feature_score * 0.3)
        confidence = min(len(words) / 10, 1.0)
        final_prob = combined_prob * confidence + 0.5 * (1 - confidence)
        
        return float(np.clip(final_prob, 0.01, 0.99))

def load_spam_model():
    try:
        model_dir = os.path.join(os.path.dirname(__file__), "saved_model")
        model_path = os.path.join(model_dir, "spam_classifier.pkl")
        
        if not os.path.exists(model_path):
            print("Warning: Model file not found")
            return None
            
        return joblib.load(model_path)
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

def predict_message(text):
    try:
        model = load_spam_model()
        if not model or not text:
            return "Unknown", 0.5, 0.5
            
        spam_prob = model.predict_probability(text)
        ham_prob = 1 - spam_prob
        prediction = "Spam" if spam_prob > model.threshold else "Ham"
        
        return prediction, spam_prob, ham_prob
    except Exception as e:
        print(f"Prediction error: {str(e)}")
        return "Unknown", 0.5, 0.5

def get_headers(mail_data: str, investigation):
    '''Get Headers from mail data'''
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    data = {"Headers": {"Data": {}, "Investigation": {}}}
    
    # Extract headers and get subject for prediction
    subject = None
    for k, v in headers.items():
        header_value = v.replace('\t', '').replace('\n', ' ')
        data["Headers"]["Data"][k.lower()] = header_value
        
        if k.lower().strip() == 'subject':
            subject = str(header_value)
            
    # Make prediction using subject
    if subject:
        try:
            prediction_label, spam_prob, ham_prob = predict_message(subject)
            
            # Format probabilities for better display
            spam_prob = float(spam_prob)
            ham_prob = float(ham_prob)
            
            # Store both in Investigation and ModelPrediction
            data["Headers"]["Investigation"]["Model Analysis"] = {
                "Prediction": prediction_label,
                "Spam Probability": spam_prob,
                "Ham Probability": ham_prob
            }
            
            # Store for HTML visualization
            data["ModelPrediction"] = {
                "prediction": prediction_label,
                "spam_prob": spam_prob,
                "ham_prob": ham_prob,
                "confidence_level": "High" if abs(spam_prob - ham_prob) > 0.5 else "Medium"
            }
            
        except Exception as e:
            print(f"Warning: Model prediction failed: {str(e)}")
    
    if data["Headers"]["Data"].get('received'):
        data["Headers"]["Data"]["x-received"] = ' '.join(headers.get_all('Received')).replace('\t', ' ').replace('\n', ' ')
    
    if investigation:
        if "x-received" in data["Headers"]["Data"]:
            ip_matches = re.findall(r'\d+\.\d+\.\d+\.\d+', data["Headers"]["Data"]["x-received"])
            if ip_matches:
                x_sender_ip = ip_matches[0]
                ip_details = verify_ip_address(x_sender_ip)
                if ip_details:
                    data["Headers"]["Investigation"]["X-Sender-Ip"] = ip_details
                else:
                    data["Headers"]["Investigation"]["X-Sender-Ip"] = {"IP": x_sender_ip, "Status": "Could not verify IP address"}
        
        # Example spoof check
        if data["Headers"]["Data"].get("reply-to") and data["Headers"]["Data"].get("from"):
            reply_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za.z0-9.-]+\.[A-Za.z]{2,7}\b', data["Headers"]["Data"]["reply-to"])
            from_matches = re.findall(r'\b[A-Za.z0-9._%+-]+@[A-Za.z0-9.-]+\.[A-Za.z]{2,7}\b', data["Headers"]["Data"]["from"])
            if reply_matches and from_matches:
                replyto = reply_matches[0]
                mailfrom = from_matches[0]
                conclusion = "Reply and From addresses are the same." if replyto == mailfrom else "Addresses differ. This mail may be SPOOFED."
                data["Headers"]["Investigation"]["Spoof Check"] = {
                    "Reply-To": replyto,
                    "From": mailfrom,
                    "Conclusion": conclusion
                }
    return data
def generate_sha256_hash(input_string):
    # Create a new sha256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the bytes of the input string
    sha256_hash.update(input_string.encode('utf-8'))
    
    # Get the hexadecimal representation of the hash
    hex_digest = sha256_hash.hexdigest()
    
    return hex_digest


def get_links(mail_data: str, investigation):
    '''Get Links from mail data'''
    if "Content-Transfer-Encoding" in mail_data:
        mail_data = str(quopri.decodestring(mail_data))
    links = re.findall(LINK_REGEX, mail_data)
    links = list(dict.fromkeys(links))
    links = list(filter(None, links))
    data = json.loads('{"Links":{"Data":{},"Investigation":{}}}')
    for index, link in enumerate(links, start=1):
        data["Links"]["Data"][str(index)] = link
    if investigation:
        for index, link in enumerate(links, start=1):
            # if "://" in link:
                # link = link.split("://")[-1]
            data["Links"]["Investigation"][str(index)] = {"Virustotal": f"https://www.virustotal.com/gui/url/{generate_sha256_hash(link)}"}
    return data


def get_attachments(filename: str, investigation: bool):
    """Get Attachments from eml file with investigation data"""
    with open(filename, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    data = {"Attachments": {"Data": {}, "Investigation": {}}}
    
    # Create attachments directory if it doesn't exist
    attachments_dir = os.path.join(os.path.dirname(__file__), ATTACHMENTS_DIR)
    os.makedirs(attachments_dir, exist_ok=True)

    # Initialize VirusTotal service
    vt_service = VirusTotalService()

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        attachment_filename = part.get_filename()
        
        if not attachment_filename or not payload:
            continue

        # Clean filename and save attachment
        safe_filename = os.path.basename(attachment_filename)
        sha256 = hashlib.sha256(payload).hexdigest()
        attachment_path = os.path.join(attachments_dir, f"{sha256}_{safe_filename}")
        
        with open(attachment_path, 'wb') as f:
            f.write(payload)
        
        # Add to Data section
        data["Attachments"]["Data"][safe_filename] = {
            "Filename": safe_filename,
            "Content Type": part.get_content_type(),
            "Size": len(payload),
            "SHA256": sha256,
            "Stored Path": attachment_path
        }
        
        if investigation:
            try:
                vt_results = vt_service.process_file(attachment_path, safe_filename, sha256)
                data["Attachments"]["Investigation"][safe_filename] = {
                    "VirusTotal": vt_results
                }
            except Exception as e:
                print(f"Error processing {safe_filename}: {str(e)}")
                data["Attachments"]["Investigation"][safe_filename] = {
                    "VirusTotal": {
                        "Status": "Error",
                        "Error": str(e)
                    },
                    # "Links": {
                    #     "VirusTotal Search": f"https://www.virustotal.com/gui/search/{sha256}"
                    # }
                }
    
    return data

def write_to_file(filename, data):
    file_format = filename.split('.')[-1].lower()
    if file_format == "json":
        with open(filename, 'w', encoding="utf-8") as file:
            json.dump(data, file, indent=4)
    elif file_format == "html":
        with open(filename, 'w', encoding="utf-8") as file:
            html_data = generate_table_from_json(data)
            file.write(html_data)
    else:
        print(f"{filename} file format not supported for output")
        sys.exit(-1)

if __name__ == '__main__':
    parser = ArgumentParser(description="")
    parser.add_argument("-f", "--filename", type=str, help="Name of the EML file", required=True)
    parser.add_argument("-H", "--headers", help="To get the Headers of the Email", required=False, action="store_true")
    parser.add_argument("-d", "--digests", help="To get the Digests of the Email", required=False, action="store_true")
    parser.add_argument("-l", "--links", help="To get the Links from the Email", required=False, action="store_true")
    parser.add_argument("-a", "--attachments", help="To get the Attachments from the Email", required=False, action="store_true")
    parser.add_argument("-i", "--investigate", help="Activate if you want an investigation", required=False, action="store_true")
    parser.add_argument("-o", "--output", type=str, help="Name of the Output file (Only HTML or JSON format supported)", required=False)
    parser.add_argument("--history", type=int, help="Show N most recent analyses", required=False)
    args = parser.parse_args()

    if sys.stdout.isatty():
        terminal_size = os.get_terminal_size()
        TER_COL_SIZE = terminal_size.columns

    filename = str(args.filename)
    file_format = filename.split('.')[-1]
    if file_format not in SUPPORTED_FILE_TYPES:
        print(f"File type {file_format} not supported.")
        sys.exit(-1)

    with open(filename, "r", encoding="utf-8") as file:
        data = file.read().rstrip()

    app_data = json.loads('{"Information": {}, "Analysis":{}}')
    app_data["Information"]["Project"] = {
        "Name": "EmailAnalyzer",
        "Url": "https://github.com/Nagasathvik",
        "Version": "2.0"
    }
    app_data["Information"]["Scan"] = {
        "Filename": filename.split("\\")[-1],
        "Generated": datetime.now().strftime(DATE_FORMAT)
    }
    
    investigate = True
    headers = get_headers(data, investigate)
    app_data["Analysis"].update(headers)
    
    # Save complete analysis data
    try:
        log_dir = os.path.join(os.path.dirname(__file__), LOGS_DIR)
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "headers_data.txt")
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write("\nComplete Headers Analysis:\n")
            f.write("=" * 50 + "\n")
            if "Model Analysis" in headers["Headers"]["Investigation"]:
                f.write("\nSpam Detection Results:\n")
                f.write("-" * 30 + "\n")
                model_analysis = headers["Headers"]["Investigation"]["Model Analysis"]
                f.write(f"Prediction: {model_analysis['Prediction']}\n")
                f.write(f"Spam Probability: {model_analysis['Spam Probability']:.4f}\n")
                f.write(f"Ham Probability: {model_analysis['Ham Probability']:.4f}\n\n")
            
            f.write("\nInvestigation Results:\n")
            f.write("-" * 30 + "\n")
            for k, v in headers["Headers"]["Investigation"].items():
                if k != "Model Analysis":
                    f.write(f"\n{k}:\n")
                    if isinstance(v, dict):
                        for sub_k, sub_v in v.items():
                            f.write(f"  {sub_k}: {sub_v}\n")
                    else:
                        f.write(f"  {v}\n")
    except Exception as e:
        print(f"Warning: Could not append analysis to log file: {str(e)}")

    # Extract prediction data for HTML generation
    model_prediction = None
    if "Model Analysis" in headers["Headers"]["Investigation"]:
        model_analysis = headers["Headers"]["Investigation"]["Model Analysis"]
        model_prediction = {
            "prediction": model_analysis["Prediction"],
            "spam_prob": model_analysis["Spam Probability"],
            "ham_prob": model_analysis["Ham Probability"]
        }
    app_data["Analysis"]["ModelPrediction"] = model_prediction

    links = get_links(data, investigate)
    app_data["Analysis"].update(links)
    
    attachments = get_attachments(filename, investigate)
    app_data["Analysis"].update(attachments)

    # Initialize database handler
    db = DatabaseHandler()

    # Store analysis in database
    email_id = db.store_analysis(app_data)
    if email_id:
        print(f"\nAnalysis stored in database with ID: {email_id}")

    if args.output:
        out_filename = args.output
        file_format = out_filename.split('.')[-1].lower()
        if file_format == "json":
            with open(out_filename, 'w', encoding="utf-8") as file:
                json.dump(app_data, file, indent=4)
        elif file_format == "html":
            html_content = generate_table_from_json(app_data)
            with open(out_filename, 'w', encoding="utf-8") as file:
                file.write(html_content)
        else:
            print(f"{out_filename} file format not supported for output")
            sys.exit(-1)
    else:
        print(generate_table_from_json(app_data))

    if args.history:
        history = db.get_analysis_history(args.history)
        print("\nRecent Email Analysis History:")
        print("=" * 80)
        for entry in history:
            print(f"Analysis ID: {entry[0]}")
            print(f"File: {entry[1]}")
            print(f"Subject: {entry[2]}")
            print(f"From: {entry[3]} -> To: {entry[4]}")
            print(f"Analysis Date: {entry[7]}")
            print(f"Spam Probability: {entry[8]:.2f}")
            print(f"Status: {entry[10]} (Confidence: {entry[11]})")
            if entry[12]:  # spoof check
                print(f"Spoof Check: {entry[12]}")
            print(f"Sender IP: {entry[13]} ({entry[15]})")
            print(f"Attachments: {entry[-3]}")
            print(f"Links: {entry[-2]}")
            print(f"Analysis Duration: {entry[-1]:.2f}s")
            print("-" * 80)
