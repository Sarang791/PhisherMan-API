
# ========== Imports ==========
from email import message_from_bytes
from email.policy import default



# ========== Extract Sender's Domain ==========
def extract_sender_domain(eml_content):
    """Extract sender's domain from the 'From' header."""
    try:
        msg = message_from_bytes(eml_content, policy=default)
        from_header = msg["From"]
        if from_header:
            from_address = from_header.split('<')[-1].split('>')[0].strip()
            domain = from_address.split('@')[-1].strip()
            print(f"Extracted Sender Domain: {domain}")  # Debugging
            return domain
        return None
    except Exception:
        return None
