# train_model.py
import os
import re
import json
import pandas as pd
import numpy as np
from datetime import datetime  # Add this import
from collections import defaultdict
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import nltk
import joblib
# Download required NLTK data
try:
    nltk.download('punkt')
    nltk.download('punkt_tab')
    nltk.download('stopwords')
    nltk.download('wordnet')
except:
    pass

class EnhancedSpamClassifier:
    def __init__(self):
        self.word_spam_probs = defaultdict(float)  # Changed from word_weights
        self.spam_indicators = {
            'urgency': r'urgent|immediately|hurry|limited time|act now|today only',
            'money': r'cash|money|\$|prize|win|won|offer|free|discount',
            'pressure': r'password|account|bank|verify|login|suspend|validate|cancel',
            'suspicious': r'click here|verify account|confirm identity|security alert'
        }
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        self.threshold = 0.5
        self.spam_prior = 0.0  # Added prior probability
        self.ham_prior = 0.0   # Added prior probability
        
    def save(self, model_dir):
        """Save the trained model"""
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, "spam_classifier.pkl")
        joblib.dump(self, model_path)
        print(f"Model saved to {model_path}")
        
        # Save metadata
        metadata = {
            'model_type': 'EnhancedSpamClassifier',
            'threshold': self.threshold,
            'vocab_size': len(self.word_spam_probs),
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(os.path.join(model_dir, "model_metadata.json"), 'w') as f:
            json.dump(metadata, f, indent=4)
    
    @staticmethod
    def load_model(model_dir):
        """Load a trained model"""
        model_path = os.path.join(model_dir, "spam_classifier.pkl")
        return joblib.load(model_path)

    def extract_features(self, text):
        """Extract comprehensive features from text"""
        if not isinstance(text, str):
            return {}
            
        features = {
            'text_length': len(text),
            'caps_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'exclamation_count': text.count('!'),
            'question_count': text.count('?'),
            'digit_ratio': sum(c.isdigit() for c in text) / max(len(text), 1),
            'url_count': len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)),
            'email_count': len(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))
        }
        
        # Add spam indicator matches
        for category, pattern in self.spam_indicators.items():
            features[f'{category}_words'] = len(re.findall(pattern, text.lower()))
        
        return features

    def preprocess_text(self, text):
        """Enhanced text preprocessing"""
        if not isinstance(text, str):
            return []
        
        # Basic cleaning
        text = text.lower()
        text = re.sub(r'http\S+|www\S+|https\S+', '[URL]', text)
        text = re.sub(r'\S+@\S+', '[EMAIL]', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # Tokenization and lemmatization
        words = word_tokenize(text)
        words = [self.lemmatizer.lemmatize(word) 
                for word in words 
                if word not in self.stop_words and len(word) > 2]
        
        return words

    def train(self, df):
        """Train using Naive Bayes with feature enhancement"""
        print("Training Bayesian spam classifier...")
        
        # Calculate prior probabilities
        total_messages = len(df)
        spam_messages = len(df[df['Category'].str.lower() == 'spam'])
        ham_messages = total_messages - spam_messages
        
        self.spam_prior = spam_messages / total_messages
        self.ham_prior = ham_messages / total_messages
        
        # Count word occurrences
        word_spam_count = defaultdict(int)
        word_ham_count = defaultdict(int)
        spam_words_total = 0
        ham_words_total = 0
        
        for _, row in df.iterrows():
            words = self.preprocess_text(row['Message'])
            is_spam = row['Category'].lower() == 'spam'
            
            for word in set(words):  # Use set for unique words per message
                if is_spam:
                    word_spam_count[word] += 1
                    spam_words_total += 1
                else:
                    word_ham_count[word] += 1
                    ham_words_total += 1
        
        # Calculate word probabilities using Laplace smoothing
        vocab_size = len(set(word_spam_count.keys()) | set(word_ham_count.keys()))
        
        for word in set(word_spam_count.keys()) | set(word_ham_count.keys()):
            # Calculate P(word|spam) and P(word|ham) with Laplace smoothing
            p_word_spam = (word_spam_count[word] + 1) / (spam_words_total + vocab_size)
            p_word_ham = (word_ham_count[word] + 1) / (ham_words_total + vocab_size)
            
            # Store log probabilities to prevent underflow
            self.word_spam_probs[word] = np.log(p_word_spam / p_word_ham)
        
        return self

    def predict_probability(self, text):
        """Predict spam probability using Naive Bayes and features"""
        words = self.preprocess_text(text)
        features = self.extract_features(text)
        
        if not words:
            return 0.5
        
        # Calculate text-based score using log probabilities
        score = np.log(self.spam_prior / self.ham_prior)  # Start with prior ratio
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
        
        # Apply confidence adjustment
        confidence = min(len(words) / 10, 1.0)
        final_prob = combined_prob * confidence + 0.5 * (1 - confidence)
        
        # Adjust extreme probabilities
        if any(indicator in text.lower() for indicator in [
            'viagra', 'lottery', 'won', 'click here', 'prize', 'credit card'
        ]):
            final_prob = max(final_prob, 0.8)
        elif all(x.isalpha() or x.isspace() for x in text):
            final_prob = min(final_prob, 0.3)
        
        return float(np.clip(final_prob, 0.01, 0.99))

def train_and_save_model(dataset_path):
    """Train and save the spam classifier"""
    try:
        # Load dataset
        print("Loading dataset...")
        df = pd.read_csv(dataset_path)
        
        # Print dataset statistics
        total = len(df)
        spam_count = len(df[df['Category'].str.lower() == 'spam'])
        ham_count = len(df[df['Category'].str.lower() == 'ham'])
        
        print(f"\nDataset Statistics:")
        print(f"Total emails: {total}")
        print(f"Spam emails: {spam_count} ({spam_count/total*100:.2f}%)")
        print(f"Ham emails: {ham_count} ({ham_count/total*100:.2f}%)")
        
        # Train classifier
        classifier = EnhancedSpamClassifier()
        classifier.train(df)
        
        # Save model with new method
        model_dir = os.path.join(os.path.dirname(__file__), "saved_model")
        classifier.save(model_dir)
        
        return classifier
        
    except Exception as e:
        print(f"Error during training: {str(e)}")
        raise

if __name__ == "__main__":
    try:
        dataset_path = "spam_dataset.csv"
        classifier = train_and_save_model(dataset_path)
        
        # Test the trained model
        test_messages = [
            "Hello, how are you? Let's meet tomorrow.",
            "CONGRATULATIONS! You've won $1,000,000! Click here now!",
            "Your account will be suspended. Verify now: http://suspicious-link.com",
            "Here's the report you requested for the meeting.",
            "FREE VIAGRA! Best prices guaranteed! Click now!!!"
        ]
        
        print("\nTesting model with sample messages:")
        for msg in test_messages:
            prob = classifier.predict_probability(msg)
            pred = "Spam" if prob > 0.5 else "Ham"
            print(f"\nMessage: {msg[:100]}...")
            print(f"Prediction: {pred}")
            print(f"Spam Probability: {prob:.4f}")
            print(f"Ham Probability: {(1-prob):.4f}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
