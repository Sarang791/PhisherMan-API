import re
from bs4 import BeautifulSoup
from nltk.tokenize import word_tokenize


def clean_email_content(text,common_words):
    """Clean and preprocess email content."""
    if not text:
        return ""
    try:
        text = BeautifulSoup(text, "html.parser").get_text()  # Remove HTML tags
        text = re.sub(r'http\S+|www\S+', '[http]', text)  # Replace URLs
        text = re.sub(r'\S+@\S+', '[email]', text)  # Replace email addresses
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip]', text)  # Replace IPs
        text = re.sub(r'[^\w\s]', '', text)  # Remove punctuation
        words = word_tokenize(text.lower())  # Lowercase and tokenize
        filtered_words = [word for word in words if word in common_words]
        return ' '.join(filtered_words)
    except Exception as e:
        print(f"Error cleaning text: {e}")
        return ""




def parse_eml_file(file_path):
    """Parse the .eml file and extract subject and body."""
    try:
        #with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        msg = file_path
        subject = msg.get("subject", "")
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break
                elif content_type == "text/html" and not body:
                    html_content = part.get_payload(decode=True).decode(errors='ignore')
                    body = BeautifulSoup(html_content, "html.parser").get_text()
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                body = msg.get_payload(decode=True).decode(errors='ignore')
            elif content_type == "text/html":
                html_content = msg.get_payload(decode=True).decode(errors='ignore')
                body = BeautifulSoup(html_content, "html.parser").get_text()

        return subject, body
    except Exception as e:
        print(f"Error parsing .eml file: {e}")
        return None, None


