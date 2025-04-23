import os
import time
import requests
import imaplib
from email import policy
from email.parser import BytesParser

VIRUSTOTAL_API_KEY = "0bee3a39ad009e41691a3fbadac75808525a07b7abc73d6c58ba5ecf9e90c82c"

# ==========================================
# 🔹 EXTRACT & SCAN ATTACHMENTS
# ==========================================
def extract_attachments(raw_email):
    """
    Extracts attachments from the email without saving them.

    Returns:
    - attachments (list): List of tuples (filename, file_bytes)
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    attachments = []

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            file_bytes = part.get_payload(decode=True)
            attachments.append((filename, file_bytes))

    return attachments

def classify_attachment(scan_results):
    """Classifies an attachment as Safe, Suspicious, or Malicious."""
    if scan_results.get("malicious", 0) > 0:
        return "Malicious"
    elif scan_results.get("suspicious", 0) > 0:
        return "Suspicious"
    else:
        return "Safe"

def scan_attachment_virustotal(filename, file_bytes):
    """Uploads an attachment (as bytes) to VirusTotal and waits for results."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    files = {"file": (filename, file_bytes)}
    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        return check_virustotal_scan(scan_id)
    else:
        return {"error": f"❌ Failed to upload {filename} to VirusTotal."}

def check_virustotal_scan(scan_id):
    """Waits for VirusTotal scan to complete and retrieves results."""
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    print(f"🔄 Waiting for VirusTotal scan results (Scan ID: {scan_id})...")

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                stats = result["data"]["attributes"]["stats"]
                return stats
            time.sleep(10)  # Wait for 10 seconds before checking again
        else:
            return {"error": "❌ Failed to retrieve scan results."}

# ==========================================
# 🔹 CLASSIFY ATTACHMENTS
# ==========================================
def classify_attachments(attachment_results):
    """
    Classifies attachments based on VirusTotal results.

    Returns:
    - result (str): Final classification ('✅ Safe', '⚠️ Suspicious', '🛑 Malicious')
    - reason (str): Detailed reason for classification with attachment names.
    """
    malicious_attachments = []
    suspicious_attachments = []

    for filename, status in attachment_results.items():
        if status == "Malicious":
            malicious_attachments.append(filename)
        elif status == "Suspicious":
            suspicious_attachments.append(filename)

    if malicious_attachments:
        reason = "Malicious attachments found:\n" + "\n".join(f" - {name}" for name in malicious_attachments)
        return "Malicious", reason.strip()

    if suspicious_attachments:
        reason = "Suspicious attachments found:\n" + "\n".join(f" - {name}" for name in suspicious_attachments)
        return "Suspicious", reason.strip()

    return "Safe", "All attachments are safe."

# ==========================================
# 🔹 MAIN FUNCTION
# ==========================================
def analyze_email(raw_email):

    # 🔸 Extract and scan attachments
    attachments = extract_attachments(raw_email)
    attachment_results = {}
    print("🔎 Scanning attachments using VirusTotal...")
    for filename, file_bytes in attachments:
        result = scan_attachment_virustotal(filename, file_bytes)
        if "error" in result:
            attachment_results[filename] = "❌ Failed to analyze"
        else:
            classification = classify_attachment(result)
            attachment_results[filename] = classification
    # 🔸 Classify attachments using the combined result
    attachment_classification, attachment_reason = classify_attachments(attachment_results)

    return {
        "Attachment Classification": attachment_classification,
        "Attachment Reason": attachment_reason,
        "Attachments": attachment_results
    }

# ==========================================
# 🔹 EXECUTE SCRIPT
# ==========================================
