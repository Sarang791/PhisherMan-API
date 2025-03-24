import imaplib
import email
import dkim
import dns.resolver
import hashlib
import re
from email.policy import default
from modules import Extract_Sender_Domain as ESD

dns.resolver.default_resolver = dns.resolver.Resolver()
dns.resolver.default_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS


# ========== Verify SPF ==========
def verify_spf(eml_content):
    """Check SPF records via DNS and validate the sender's domain."""
    sender_domain = ESD.extract_sender_domain(eml_content)
    if not sender_domain:
        return "Failed", "No valid sender domain found."

    try:
        spf_record = dns.resolver.resolve(sender_domain, "TXT")
        for record in spf_record:
            if "v=spf1" in record.to_text():
                return "Passed", "SPF record found and validated."
        return "Failed", f"No SPF record found for {sender_domain}."
    except dns.resolver.NoAnswer:
        return "Failed", f"No SPF record found for {sender_domain}."
    except Exception as e:
        return "Failed", f"SPF verification error: {e}"

# ========== Verify DKIM ==========
def verify_dkim(eml_content):
    """Validate DKIM signature using DNS public key lookup."""
    try:
        msg = email.message_from_bytes(eml_content, policy=default)
        dkim_header = msg.get("DKIM-Signature")
        if not dkim_header:
            return "Failed", "No DKIM signature found."

        selector_match = re.search(r"s=([\w]+)", dkim_header)
        domain_match = re.search(r"d=([\w.]+)", dkim_header)

        if not selector_match or not domain_match:
            return "Failed", "DKIM signature missing required fields."

        selector = selector_match.group(1)
        domain = domain_match.group(1)

        dkim_query = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_query, "TXT")
            for record in answers:
                if "p=" in record.to_text():
                    return "Passed", "DKIM public key found and validated."
            return "Failed", f"No DKIM record found for {domain}."
        except dns.resolver.NoAnswer:
            return "Failed", f"No DKIM record found for {domain}."
        except Exception as e:
            return "Failed", f"DKIM verification error: {e}"
    except Exception as e:
        return "Failed", f"Error in DKIM verification: {e}"

# ========== Verify DMARC ==========
def verify_dmarc(eml_content):
    """Check DMARC policy by querying DNS records."""
    sender_domain = ESD.extract_sender_domain(eml_content)
    if not sender_domain:
        return "Failed", "No valid sender domain found."

    dmarc_record = f"_dmarc.{sender_domain}"
    try:
        answers = dns.resolver.resolve(dmarc_record, "TXT")
        for record in answers:
            if "v=DMARC1" in record.to_text():
                return "Passed", "DMARC policy found and validated."
        return "Failed", f"No DMARC policy found for {sender_domain}."
    except dns.resolver.NoAnswer:
        return "Failed", f"No DMARC policy found for {sender_domain}."
    except Exception as e:
        return "Failed", f"DMARC verification error: {e}"

def classify_spf_dkim_dmarc(email_bytes):
    """
    Combines SPF, DKIM, and DMARC results to classify the email.

    Args:
    - spf_result (str): 'Passed' or 'Failed'
    - spf_message (str): Explanation for SPF result
    - dkim_result (str): 'Passed' or 'Failed'
    - dkim_message (str): Explanation for DKIM result
    - dmarc_result (str): 'Passed' or 'Failed'
    - dmarc_message (str): Explanation for DMARC result

    Returns:
    - classification (str): 'Legitimate', 'Suspicious', or 'Malicious'
    - reason (str): Detailed explanation for classification
    """
    if not email_bytes:
        return "Error", "Email content could not be retrieved."

    spf_result, spf_message = verify_spf(email_bytes)
    dkim_result, dkim_message = verify_dkim(email_bytes)
    dmarc_result, dmarc_message = verify_dmarc(email_bytes)

    # **Classification Logic**:
    if spf_result == "Passed" and dkim_result == "Passed" and dmarc_result == "Passed":
        classification = "Safe"
        reason = "All authentication checks (SPF, DKIM, DMARC) passed. Email is legitimate."

    elif spf_result == "Failed" and dkim_result == "Failed" and dmarc_result == "Failed":
        classification = "Malicious"
        reason = "All authentication mechanisms (SPF, DKIM, DMARC) failed. High risk of spoofing or phishing."

    elif spf_result == "Passed" and dkim_result == "Passed" and dmarc_result == "Failed":
        classification = "Suspicious"
        reason = "SPF and DKIM passed, but no DMARC policy found. Spoofing still possible."

    elif spf_result == "Failed" and dkim_result == "Passed" and dmarc_result == "Failed":
        classification = "Suspicious"
        reason = "DKIM passed, but SPF and DMARC failed. Sender integrity uncertain."

    elif spf_result == "Passed" and dkim_result == "Failed" and dmarc_result == "Failed":
        classification = "Suspicious"
        reason = "SPF passed, but DKIM and DMARC failed. Email integrity is weak."

    elif spf_result == "Failed" and dkim_result == "Failed" and dmarc_result == "Passed":
        classification = "Malicious"
        reason = "DMARC passed, but SPF and DKIM failed. High risk of email spoofing."

    else:
        classification = "Suspicious"
        reason = "Unusual authentication result pattern. Email integrity uncertain."

    # Combine all reasons into a detailed message
    detailed_reason = reason

    return classification, detailed_reason




   
