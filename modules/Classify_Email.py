from nltk.tokenize import word_tokenize
from tensorflow.keras.preprocessing.sequence import pad_sequences
from modules.Email_Cleaning import clean_email_content
from modules.Email_Cleaning import parse_eml_file



def classify_email(file_path,model,threshold,common_words,word_to_index):
    """Classify an email as phishing or legitimate."""
    # Extract email subject and body
    subject, body = parse_eml_file(file_path)

    # print("Subject: ",subject)
    # print("Body: ",body)
    
    if not (subject or body):
        return "Unable to process email content."

    # Clean and preprocess
    cleaned_subject = clean_email_content(subject,common_words)
    cleaned_body = clean_email_content(body,common_words)
    combined_content = cleaned_subject + " " + cleaned_body
    #print("Content:\n"+combined_content)
    # Tokenize and convert to indices
    tokens = word_tokenize(combined_content)
    token_indices = [word_to_index[word] for word in tokens if word in word_to_index]
    padded_sequence = pad_sequences([token_indices], maxlen=200, padding='post', truncating='post')

    # Predict using the trained model
    prediction_prob = model.predict(padded_sequence)[0][0]
    label = "Phishing" if prediction_prob <= threshold else "Legitimate"

    print("Prediction: ",label,", Confidence: ",prediction_prob)
    return label

