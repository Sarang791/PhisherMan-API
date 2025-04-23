import dns.resolver
import requests
import re
import base64
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser
from modules import Extract_Sender_Domain as ESD

# 🔹 VirusTotal API Key
VIRUSTOTAL_API_KEY = "cbe1f031cd7dcedd81334c71447e6ff6f54caee4e059f89fa7de7d87f55fdbdd"


def check_mx_records(domain):
    """Checks if the sender's domain has valid MX records."""
    try:
        dns.resolver.resolve(domain, "MX")
        return True, f"✅ MX record found for {domain}. Domain is capable of sending emails."
    except Exception:
        return False, f"❌ No valid MX record found for {domain}. This could indicate a spoofed domain."

def check_domain_virustotal(domain):
    """Checks if the sender's domain is blacklisted on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        if stats.get("malicious", 0) > 0:
            return "Malicious", f"❌ Domain {domain} is flagged as malicious on VirusTotal."
        elif stats.get("suspicious", 0) > 0:
            return "Suspicious", f"⚠️ Domain {domain} has suspicious activity on VirusTotal."
        else:
            return "Safe", f"✅ Domain {domain} is not flagged on VirusTotal."
    else:
        return "Suspicious", f"⚠️ VirusTotal lookup failed for {domain}."

def verify_sender_domain(domain):
    """Combines MX record verification and VirusTotal lookup for classification."""
    if not domain:
        return "Suspicious", "❌ No sender domain found. Possible email spoofing."
    
    if domain.lower() == "gmail.com":
        return "Safe", "✅ Gmail domain is considered safe."

    mx_valid, mx_message = check_mx_records(domain)
    vt_status, vt_message = check_domain_virustotal(domain)

    if vt_status == "Malicious" or (not mx_valid and vt_status == "Malicious"):
        return "Malicious", f"{mx_message}, {vt_message}"
    elif not mx_valid or vt_status == "Suspicious":
        return "Suspicious", f"{mx_message}, {vt_message}"
    else:
        return "Safe", f"{mx_message}, {vt_message}"

# ✅ Classification for Sender Domain
def classify_sender_domain(domain_status, domain_message, sender_domain):
    if not sender_domain:
        return "Suspicious", "No sender domain found. Possible email spoofing."

    if domain_status == "Malicious":
        return "Malicious", f"Sender domain '{sender_domain}' is flagged as malicious.\n{domain_message}"

    if domain_status == "Suspicious":
        return "Suspicious", f"Sender domain '{sender_domain}' is flagged as suspicious.\n{domain_message}"

    return "Safe", f"Sender domain '{sender_domain}' is legitimate.\n{domain_message}"

# ==========================================
# 🔹 EXTRACT & ANALYZE URLs
# ==========================================
def extract_urls(raw_email):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    urls = set()

    subject = msg["Subject"]
    if subject:
        urls.update(re.findall(r"https?://[^\s<>\"']+", subject))

    for part in msg.walk():
        content_type = part.get_content_type()
        try:
            payload = part.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
                urls.update(re.findall(r"https?://[^\s<>\"']+", body))

                if "html" in content_type:
                    soup = BeautifulSoup(body, "html.parser")
                    for link in soup.find_all("a", href=True):
                        urls.add(link["href"])
        except Exception:
            pass

    return list(urls)

def analyze_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(vt_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        if stats.get("malicious", 0) > 0:
            return f"Malicious - {url}"
        elif stats.get("suspicious", 0) > 0:
            return f"Suspicious - {url}"
    return None

# ✅ Classification for URLs
def classify_urls(urls):
    if not urls:
        return "Safe", "No URLs found in the email body or subject."

    malicious_urls = []
    suspicious_urls = []

    for url in urls:
        result = analyze_url(url)
        if result:
            if "Malicious" in result:
                malicious_urls.append(url)
            elif "Suspicious" in result:
                suspicious_urls.append(url)

    if malicious_urls:
        reason = "Malicious URLs found:\n" + "\n".join(f" - {url}" for url in malicious_urls)
        return "Malicious", reason.strip()

    if suspicious_urls:
        reason = "Suspicious URLs found:\n" + "\n".join(f" - {url}" for url in suspicious_urls)
        return "Suspicious", reason.strip()

    return "Safe", "All URLs are safe."

# ==========================================
# 🔹 MAIN FUNCTION
# ==========================================
def analyze_email(raw_email):
    if not raw_email:
        return {"Fetch Status": "❌ No email content found."}
  

    # 🔸 Sender Domain Analysis
    sender_domain = ESD.extract_sender_domain(raw_email)
    domain_status, domain_message = verify_sender_domain(sender_domain)
    domain_classification, domain_reason = classify_sender_domain(domain_status, domain_message, sender_domain)

    # 🔸 URL Analysis
    urls = extract_urls(raw_email)
    url_classification, url_reason = classify_urls(urls)

    # ✅ Final Results
    results = {
        "Sender Domain": {
            "Classification": domain_classification,
            "Reason": domain_reason
        },
        "URLs": {
            "Classification": url_classification,
            "Reason": url_reason
        }
    }

    return results

   