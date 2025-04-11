import imaplib
import email
import base64
import dns.resolver
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone


# ==========================================
# 🔹 EXTRACT CERTIFICATE FROM EMAIL
# ==========================================
def extract_certificate_from_eml(eml_content):
    """Extracts a certificate from email content."""
    msg = email.message_from_bytes(eml_content)

    for header, value in msg.items():
        if 'CERTIFICATE' in value.upper():
            try:
                cert_data = base64.b64decode(value.strip())
                return cert_data, 'pem'
            except Exception as e:
                print(f"Error decoding certificate from header {header}: {str(e)}")

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            filename = part.get_filename()
            payload = part.get_payload(decode=True)

            if (content_type in ['application/x-x509-ca-cert', 'application/pkcs7-mime'] or
                (filename and filename.endswith(('.cer', '.der', '.pfx')))):
                return payload, 'attachment'

            try:
                decoded_payload = base64.b64decode(payload.strip())
                if b'-----BEGIN CERTIFICATE-----' in decoded_payload:
                    return decoded_payload, 'pem'
                elif decoded_payload.startswith(b'0\x82'):
                    return decoded_payload, 'der'
            except Exception:
                continue

    return None, None

# ==========================================
# 🔹 VALIDATE EMAIL CERTIFICATE
# ==========================================
def validate_email_certificate(eml_content):
    """Validates the certificate from an email."""
    cert_data, cert_location = extract_certificate_from_eml(eml_content)
    if not cert_data:
        return False, "❌ No certificate found in email."

    cert_format = 'pem' if b'-----BEGIN CERTIFICATE-----' in cert_data else \
                  'der' if cert_data.startswith(b'0\x82') else 'pfx'

    try:
        certificates = load_certificates(cert_data, cert_format)
    except Exception as e:
        return False, f"❌ Failed to load certificate: {e}"

    # 🔸 Verify Certificate Chain
    is_valid_chain, chain_message = verify_certificate_chain(certificates)
    if not is_valid_chain:
        return False, f"❌ Certificate chain invalid: {chain_message}"

    # 🔸 Verify Email Match
    sender_email = extract_sender_email(eml_content)
    cert = certificates[0]

    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if sender_email == common_name:
            email_match = True
            email_message = "✅ Email address matches certificate (Common Name)."
        else:
            email_match = False
            email_message = "❌ Email address does not match certificate."

        if not email_match:
            return False, email_message
    except Exception as e:
        return False, f"❌ Email verification failed: {e}"

    # 🔸 Check Expiration
    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not_after < datetime.now(timezone.utc):
        return False, f"❌ Certificate expired on {not_after}."

    return True, "✅ Certificate is valid and email matches."


# ==========================================
# 🔹 EXTRACT SENDER EMAIL
# ==========================================
def extract_sender_email(eml_content):
    """Extracts the sender's email address."""
    msg = email.message_from_bytes(eml_content)
    sender = msg.get('From')
    return email.utils.parseaddr(sender)[1]

# ==========================================
# 🔹 VERIFY REPLY-TO ADDRESS
# ==========================================
def validate_reply_to(eml_content):
    """Checks if the Reply-To address differs from the sender's email."""
    msg = email.message_from_bytes(eml_content)
    sender_email = extract_sender_email(eml_content)
    reply_to_email = msg.get("Reply-To")

    if reply_to_email:
        reply_to_email = email.utils.parseaddr(reply_to_email)[1]
        if reply_to_email and sender_email and reply_to_email.lower() != sender_email.lower():
            return False, f"❌ Reply-To address ({reply_to_email}) is different from sender ({sender_email}). Possible phishing attempt."

    return True, "✅ Reply-To address matches sender."

# ==========================================
# 🔹 LOAD CERTIFICATES
# ==========================================
def load_certificates(cert_data, cert_format):
    """Loads certificates from extracted certificate data."""
    certificates = []

    if cert_format == 'pem':
        for cert in cert_data.split(b'-----END CERTIFICATE-----'):
            cert = cert.strip()
            if cert:
                cert = cert + b'-----END CERTIFICATE-----'
                certificates.append(x509.load_pem_x509_certificate(cert, default_backend()))

    elif cert_format == 'der':
        certificates.append(x509.load_der_x509_certificate(cert_data, default_backend()))

    elif cert_format == 'pfx':
        pfx = OpenSSL.crypto.load_pkcs12(cert_data)
        certificates.append(pfx.get_certificate())

    return certificates

# ==========================================
# 🔹 VERIFY CERTIFICATE CHAIN
# ==========================================
def verify_certificate_chain(certificates):
    """Verifies the certificate chain."""
    for i in range(len(certificates) - 1):
        cert = certificates[i]
        issuer_cert = certificates[i + 1]

        try:
            cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm
            )
        except Exception as e:
            return False, f"Verification failed for certificate {i}: {e}"

        if cert.issuer != issuer_cert.subject:
            return False, f"Certificate {i} issuer does not match subject of certificate {i+1}"

    return True, "Certificate chain is valid."

# ==========================================
# 🔹 CLASSIFY CERTIFICATE AND REPLY-TO
# ==========================================
def classify_certificate_and_reply_to(cert_validation, reply_to_validation):
    if "No certificate found" in cert_validation:
        cert_result = "Valid"
        cert_reason = "No certificate found, but email is still valid."
    elif "Certificate is valid" in cert_validation:
        cert_result = "Valid"
        cert_reason = cert_validation
    else:
        cert_result = "Invalid"
        cert_reason = cert_validation

    if "matches sender" in reply_to_validation:
        reply_to_result = "Valid"
        reply_to_reason = reply_to_validation
    else:
        reply_to_result = "Invalid"
        reply_to_reason = reply_to_validation

    return cert_result, cert_reason, reply_to_result, reply_to_reason

# ==========================================
# 🔹 MAIN FUNCTION
# ==========================================
def analyze_email_certificate(raw_email):

    if not raw_email:
        return {
            "Fetch Status": "❌ No email content found.",
            "Certificate Result": "Invalid",
            "Certificate Reason": "No email content found.",
            "Reply-To Result": "Invalid",
            "Reply-To Reason": "No email content found."
        }

    # 🔹 Validate Certificate and Reply-To Address
    is_valid, cert_validation = validate_email_certificate(raw_email)
    is_valid_reply_to, reply_to_validation = validate_reply_to(raw_email)

    # 🔹 Classify certificate and reply-to validation
    cert_result, cert_reason, reply_to_result, reply_to_reason = classify_certificate_and_reply_to(
        cert_validation, reply_to_validation
    )

    return {
        "Certificate Result": cert_result,
        "Certificate Reason": cert_reason,
        "Reply-To Result": reply_to_result,
        "Reply-To Reason": reply_to_reason
    }

