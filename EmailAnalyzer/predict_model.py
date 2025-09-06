# predict_model.py
import os
import re
import email
from email import policy
import joblib
import numpy as np
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import nltk
from collections import defaultdict

try:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('wordnet')
except:
    pass

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
        
        # Calculate text-based score using log probabilities
        score = np.log(max(self.spam_prior, 0.01) / max(self.ham_prior, 0.01))
        for word in words:
            if word in self.word_spam_probs:
                score += self.word_spam_probs[word]
        
        # Convert log score to probability using logistic function
        text_prob = 1 / (1 + np.exp(-score))
        
        # Calculate feature-based probability
        feature_score = (
            features['caps_ratio'] * 0.3 +
            min(features['exclamation_count'], 3) * 0.2 +
            min(features['url_count'], 2) * 0.3 +
            sum(features[f'{cat}_words'] for cat in self.spam_indicators.keys()) * 0.2
        )
        
        # Combine probabilities with weights
        combined_prob = (text_prob * 0.7 + feature_score * 0.3)
        
        # Adjust confidence based on text length
        confidence = min(len(words) / 10, 1.0)
        final_prob = combined_prob * confidence + 0.5 * (1 - confidence)
        
        return float(np.clip(final_prob, 0.01, 0.99))

def load_model():
    try:
        model_dir = os.path.join(os.path.dirname(__file__), "saved_model")
        model_path = os.path.join(model_dir, "spam_classifier.pkl")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError("Model not found. Please run train_model.py first")
        
        model = joblib.load(model_path)
        print("Model loaded successfully")
        return model
        
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

def predict_spam(text, model):
    """Make spam prediction using loaded model"""
    try:
        if not model:
            return "Unknown", 0.5, 0.5
            
        # Get raw prediction
        spam_prob = model.predict_probability(text)
        ham_prob = 1 - spam_prob
        prediction = "Spam" if spam_prob > model.threshold else "Ham"
        
        # Print analysis 
        features = model.extract_features(text)
        print("\nText Analysis:")
        print(f"Length: {features['text_length']}")
        print(f"Caps Ratio: {features['caps_ratio']:.2f}")
        print(f"URLs: {features['url_count']}")
        print(f"Exclamation Marks: {features['exclamation_count']}")
        
        return prediction, spam_prob, ham_prob
        
    except Exception as e:
        print(f"Prediction error: {str(e)}")
        return "Unknown", 0.5, 0.5

# Load model once when module is imported
MODEL = load_model()

def predict_message(text):
    """Main prediction function to be used by other modules"""
    try:
        if not text or not MODEL:
            return "Unknown", 0.5, 0.5
            
        # Get prediction
        spam_prob = MODEL.predict_probability(text)
        ham_prob = 1 - spam_prob
        prediction = "Spam" if spam_prob > MODEL.threshold else "Ham"
        
        return prediction, spam_prob, ham_prob
        
    except Exception as e:
        print(f"Prediction error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return "Unknown", 0.5, 0.5

def extract_header_text(eml_path):
    """Extract text from email headers and body"""
    try:
        with open(eml_path, "r", encoding="utf-8") as f:
            msg = email.message_from_file(f, policy=policy.default)
        
        # Extract headers
        headers = []
        important_headers = ['subject', 'from', 'to', 'reply-to']
        for header in important_headers:
            value = msg.get(header, '')
            if value:
                headers.append(f"{header}: {value}")
        
        # Extract body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode()
                        break
                    except:
                        continue
        else:
            try:
                body = msg.get_payload(decode=True).decode()
            except:
                pass
        
        # Combine headers and body
        text = " ".join(headers)
        if body:
            text += f" {body}"
        
        return text
        
    except Exception as e:
        print(f"Error extracting email content: {str(e)}")
        return ""

if __name__ == "__main__":
    try:
        # Verify model exists
        model_dir = os.path.join(os.path.dirname(__file__), "saved_model")
        if not os.path.exists(os.path.join(model_dir, "spam_classifier.pkl")):
            print("Error: Model file not found. Please train the model first.")
            print("Run: python train_model.py")
            exit(1)

        # Test messages
        test_messages = [
            "Hello, how are you? Let's meet tomorrow.",
            "Hello Nihal, Good afternoon!", 
            "Your account will be suspended. Verify now: http://suspicious-link.com",
            "Here's the report you requested for the meeting.",
            "FREE VIAGRA! Best prices guaranteed! Click now!!!"
        ]

        print("\nTesting model with sample messages:")
        for msg in test_messages:
            pred, spam_prob, ham_prob = predict_message(msg)
            print("\n" + "="*50)
            print(f"Message: {msg[:100]}...")
            print(f"Prediction: {pred}")
            print(f"Spam Probability: {spam_prob:.4f}")
            print(f"Ham Probability: {ham_prob:.4f}")
            
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        print("Make sure you have:")
        print("1. Trained the model (python train_model.py)")
        print("2. Have the required packages installed")
        print("3. Have the spam_dataset.csv file in place")
