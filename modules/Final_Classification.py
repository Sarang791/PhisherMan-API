"""
    Combines all module results to classify the email based on defined logic.

    Args:
    - phishing_prediction (str): 'Phishing' or 'Legitimate'
    - phishing_reason (str): Reason for phishing prediction

    - spf_dkim_dmarc_result (str): 'Safe', 'Suspicious', or 'Malicious'
    - spf_dkim_dmarc_reason (str): Explanation for SPF/DKIM/DMARC result

    - certificate_status (str): 'Valid' or 'Invalid'
    - certificate_reason (str): Reason for certificate validation result

    - reply_to_status (str): 'Valid' or 'Invalid'
    - reply_to_reason (str): Explanation for Reply-To address validation

    - sender_domain_result (str): 'Safe', 'Suspicious', or 'Malicious'
    - sender_domain_reason (str): Explanation for sender domain result

    - url_analysis_result (str): 'Safe', 'Suspicious', or 'Malicious'
    - url_analysis_reason (str): Explanation for URL analysis

    - attachment_analysis_result (str): 'Safe', 'Suspicious', or 'Malicious'
    - attachment_analysis_reason (str): Explanation for attachment analysis

    Returns:
    - final_decision (str): Final classification as 'Legitimate', 'Suspicious', or 'Phishing'
    - reason (str): Combined detailed explanation for the final decision
    """
import pandas as pd


file_path = "D:\PhisserMan1Api\Phisherman_Decision_Table.xlsx"
decision_table = pd.read_excel(file_path)

# Create a hash-based dictionary for O(1) lookup
decision_lookup = {
    tuple(row[:-1]): row[-1] for row in decision_table.values
}


def classify_final(phishing_prediction, 
                   spf_dkim_dmarc_result, spf_dkim_dmarc_reason,
                   certificate_status, certificate_reason,
                   reply_to_status, reply_to_reason,
                   sender_domain_result, sender_domain_reason,
                   url_analysis_result, url_analysis_reason):
    
    # Define weights for each factor (excluding attachments)
    # weights = {
    #     'phishing_prediction': 0.3,
    #     'spf_dkim_dmarc_result': 0.2,
    #     'certificate_status': 0.2,
    #     'reply_to_status': 0.1,
    #     'sender_domain_result': 0.2,
    #     'url_analysis_result': 0.2
    # }
    
    # Define scores for each possible result
    # scores = {
    #     'Phishing': -1,
    #     'Legitimate': 1,
    #     'Malicious': -1,
    #     'Suspicious': -0.5,
    #     'Safe': 1,
    #     'Invalid': -1,
    #     'Valid': 1
    # }
    
    # Calculate the weighted score
    # total_score = 0
    reasons = []
    
    # # Phishing Prediction
    # total_score += weights['phishing_prediction'] * scores[phishing_prediction]
    
    # # SPF, DKIM, and DMARC Verification
    # total_score += weights['spf_dkim_dmarc_result'] * scores[spf_dkim_dmarc_result]
    if spf_dkim_dmarc_result in ['Malicious', 'Suspicious']:
         reasons.append(spf_dkim_dmarc_reason)
    
    # # Certificate Validation
    # total_score += weights['certificate_status'] * scores[certificate_status]
    if certificate_status == 'Invalid':
         reasons.append(certificate_reason)
    
    # # Reply-To Address Validation
    # total_score += weights['reply_to_status'] * scores[reply_to_status]
    if reply_to_status == 'Invalid':
        reasons.append(reply_to_reason)
    
    # # Sender Domain Verification
    # total_score += weights['sender_domain_result'] * scores[sender_domain_result]
    if sender_domain_result in ['Malicious', 'Suspicious']:
        reasons.append(sender_domain_reason)
    
    # # URL Analysis
    # total_score += weights['url_analysis_result'] * scores[url_analysis_result]
    if url_analysis_result in ['Malicious', 'Suspicious']:
        reasons.append(url_analysis_reason)

    # print("total score....",total_score)
    
    # # Determine the final decision based on the total score
    # if total_score <= -0.5:
    #     final_decision = "Malicious"
    # elif total_score > 0.5:
    #     final_decision = "Safe"
    # else:
    #     final_decision = "Suspicious"
        # Create a tuple key based on the current results (aligned with table format)
    key = (phishing_prediction, spf_dkim_dmarc_result, sender_domain_result, 
           url_analysis_result, certificate_status, reply_to_status)
    
    # Lookup in decision table
    final_decision = decision_lookup.get(key)
    print("final decision....",final_decision)
    if(final_decision == "Safe"):
        reasons = ["No issues detected based on current checks."]
    # If no specific reasons were found, provide a default message
    if not reasons:
        default_reasons = {
            "Safe": "No issues detected based on current checks.",
            "Suspicious": "Some factors indicate potential risk, but not enough to classify as malicious.",
            "Malicious": "This email exhibits strong signs of phishing or malicious intent."
        }
        reasons.append(default_reasons[final_decision])

    print("reasons....","\n".join(reasons))
    
    # Return the final decision and reasons
    return final_decision, "\n".join(reasons)