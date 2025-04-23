import os
import time
import requests
from email import policy
from email.parser import BytesParser


# 🔹 VirusTotal API Key
VIRUSTOTAL_API_KEY = "0bee3a39ad009e41691a3fbadac75808525a07b7abc73d6c58ba5ecf9e90c82c"

# ==========================================
# 🔹 EXTRACT & SCAN ATTACHMENTS
# ==========================================
def extract_attachments(raw_email, save_dir="attachments"):
    """Extracts and saves all attachments from the email."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    attachments = []

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            filepath = os.path.join(save_dir, filename)
            with open(filepath, "wb") as f:
                f.write(part.get_payload(decode=True))
            attachments.append(filepath)

            print(f"📎 Attachment saved: {filename}")

    return attachments

def classify_attachment(scan_results):
    """Classifies an attachment as Safe, Suspicious, or Malicious."""
    if scan_results.get("malicious", 0) > 0:
        return "🛑 Malicious"
    elif scan_results.get("suspicious", 0) > 0:
        return "⚠️ Suspicious"
    else:
        return "✅ Safe"

def scan_attachment_virustotal(file_path):
    """Uploads an attachment to VirusTotal and waits for results."""
    print("scanning attachment............")
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        print("Scan ID : ",scan_id)
        return check_virustotal_scan(scan_id)
    else:
        return {"error": f"❌ Failed to upload {os.path.basename(file_path)} to VirusTotal."}

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
# 🔹 MAIN FUNCTION
# ==========================================
def analyze_email(raw_email):
    print("\n🔍 Analyzing email attachment...")
    if not raw_email:
        return {"Fetch Status": "❌ No email content found."}

    # 🔸 Extract and scan attachments
    attachments = extract_attachments(raw_email)
    attachment_results = {}

    if attachments:
        print("🔎 Scanning attachments using VirusTotal...")
        for attachment in attachments:
            result = scan_attachment_virustotal(attachment)
            if "error" in result:
                attachment_results[os.path.basename(attachment)] = "❌ Failed to analyze"
            else:
                classification = classify_attachment(result)
                attachment_results[os.path.basename(attachment)] = classification
    else:
        attachment_results = {"No Attachments": "✅ No attachments found."}

    return {
        "Fetch Status": "✅ Email content analyzed.",
        "Attachments": attachment_results
    }

