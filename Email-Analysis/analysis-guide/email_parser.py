import email
import os
import hashlib
import re
import requests
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser
from virustotal_python import Virustotal

# VirusTotal API Key
VT_API_KEY = '9af05adeec7c4dbd8faa07ed086a3aa55c878be2610ec05d5c6072580344e5c1'  # Replace this
vt = Virustotal(API_KEY=VT_API_KEY)

def parse_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    metadata = {
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Subject": msg.get("Subject"),
        "Date": msg.get("Date"),
        "Return-Path": msg.get("Return-Path"),
        "Message-ID": msg.get("Message-ID"),
        "Reply-To": msg.get("Reply-To"),
        "X-Mailer": msg.get("X-Mailer"),
        "Authentication-Results": msg.get("Authentication-Results"),
        "Received": msg.get_all("Received", [])
    }

    body = extract_body(msg)
    attachments = extract_attachments(msg)
    urls = extract_urls(body)

    return metadata, body, attachments, urls

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/html':
                return part.get_content()
            elif ctype == 'text/plain' and not body:
                body = part.get_content()
    else:
        body = msg.get_content()
    return body

def extract_attachments(msg):
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        content = part.get_payload(decode=True)
        hash_sha256 = hashlib.sha256(content).hexdigest()
        attachments.append({"filename": filename, "hash": hash_sha256})
        # Save for manual analysis
        with open(filename, "wb") as f:
            f.write(content)
    return attachments

def extract_urls(body):
    urls = []
    soup = BeautifulSoup(body, "html.parser")
    for link in soup.find_all("a", href=True):
        urls.append(link['href'])
    return list(set(urls))

def vt_url_analysis(url):
    try:
        resp = vt.request("urls", data={"url": url}, method="POST")
        analysis_id = resp['data']['id']
        result = vt.request(f"analyses/{analysis_id}")
        return result['data']['attributes']['stats']
    except Exception as e:
        return {"error": str(e)}

def vt_file_analysis(file_path):
    try:
        with open(file_path, "rb") as f:
            resp = vt.request("files", files={"file": (file_path, f)})
        analysis_id = resp['data']['id']
        result = vt.request(f"analyses/{analysis_id}")
        return result['data']['attributes']['stats']
    except Exception as e:
        return {"error": str(e)}

def generate_report(metadata, body, attachments, urls, vt_results):
    report = f"\n{'='*60}\nMALICIOUS EMAIL ANALYSIS REPORT\n{'='*60}\n"
    report += "\n[Header Metadata]\n"
    for k, v in metadata.items():
        if isinstance(v, list):
            report += f"{k}:\n"
            for item in v:
                report += f"  - {item}\n"
        else:
            report += f"{k}: {v}\n"

    report += "\n[Body Preview]\n"
    report += (body[:500] + '...') if len(body) > 500 else body

    report += "\n\n[Attachments]\n"
    for att in attachments:
        report += f"- {att['filename']} (SHA256: {att['hash']})\n"

    report += "\n[URLs Found]\n"
    for url in urls:
        report += f"- {url}\n"

    report += "\n[VirusTotal Results]\n"
    for url, res in vt_results.items():
        if "error" in res:
            report += f"- {url}: ERROR - {res['error']}\n"
        else:
            report += f"- {url}: Malicious: {res.get('malicious', 0)}, Suspicious: {res.get('suspicious', 0)}\n"

    with open("email_analysis_report.txt", "w") as f:
        f.write(report)

    print("[+] Report generated: email_analysis_report.txt")

def main():
    file_path = input("Enter path to .eml file: ").strip()
    metadata, body, attachments, urls = parse_email(file_path)

    vt_results = {}
    for url in urls:
        vt_results[url] = vt_url_analysis(url)

    for att in attachments:
        vt_results[att['filename']] = vt_file_analysis(att['filename'])

    generate_report(metadata, body, attachments, urls, vt_results)

if __name__ == "__main__":
    main()

