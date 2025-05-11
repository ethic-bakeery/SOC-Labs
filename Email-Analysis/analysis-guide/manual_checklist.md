# ✅ Email Analysis Checklist (Notion Template)

---

## 🔍 1. Initial Triage
- [ ] Confirm source of report (user, alert, or tool)
- [ ] Review email subject & body for red flags (urgency, threats, fake branding)
- [ ] Check attachments or URLs for suspicious indicators
- [ ] Assign a risk level (Low/Medium/High)

🔗 **Tools**:
- [VirusTotal](https://www.virustotal.com)
- [PhishTool](https://www.phishtool.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

---

## 📧 2. Email Header Analysis
- [ ] Compare From: name and actual email address
- [ ] Check Return-Path: for sender’s real address
- [ ] Check Reply-To: for redirection
- [ ] Review Message-ID: for mismatch or strange format
- [ ] Analyze all Received: headers (server hops)
- [ ] Inspect Authentication-Results: (SPF, DKIM, DMARC)
- [ ] Check X-Originating-IP: and X-Mailer:
- [ ] Check To: / CC: field for targeting signs

🔗 **Tools**:
- [MxToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
- [Mailheader Analyzer](https://mailheader.org/)

---

## 📎 3. Attachment Analysis
- [ ] Isolate attachment in sandbox
- [ ] Check for file extension mismatch
- [ ] Extract file metadata (author, creation date)
- [ ] Look for macros or embedded objects
- [ ] Run file in dynamic sandbox
- [ ] Hash file and search on intel platforms

🔗 **Tools**:
- [VirusTotal](https://www.virustotal.com)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [Any.Run](https://any.run/)
- [OLEtools](https://github.com/decalage2/oletools)
- [ExifTool](https://exiftool.org/)
- [PDFid](https://blog.didierstevens.com/programs/pdf-tools/)

---

## 🔗 4. URL and Link Analysis
- [ ] Hover to check visible link vs actual URL
- [ ] Extract and analyze all embedded URLs
- [ ] Look for shortened or obfuscated URLs (bit.ly, Base64, JS)
- [ ] Decode hidden or obfuscated links
- [ ] Open in sandbox only if safe

🔗 **Tools**:
- [URLScan.io](https://urlscan.io/)
- [CheckPhish](https://checkphish.ai/)
- [VirusTotal](https://www.virustotal.com)
- [CyberChef](https://gchq.github.io/CyberChef/)

---

## 🧾 5. Email Body Analysis
- [ ] Check for urgency, threats, or reward tactics
- [ ] Look for fake branding or impersonation
- [ ] Review HTML content, scripts, hidden text
- [ ] Check for tracking pixels or malicious visuals
- [ ] Search for embedded JavaScript or base64 blobs

🔗 **Tools**:
- [Hopper Link Inspector](https://hopper.pw/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [HTML Code Viewer](https://html-online.com/editor/)

---

## 🖥️ 6. Infrastructure Analysis
- [ ] Perform Whois lookup on sender’s domain
- [ ] Analyze DNS records (SPF, DKIM, MX)
- [ ] Check IPs on blacklist databases
- [ ] Get geolocation and ASN info
- [ ] Use passive DNS to trace domain history

🔗 **Tools**:
- [ViewDNS.info](https://viewdns.info/)
- [IPinfo](https://ipinfo.io/)
- [Shodan](https://www.shodan.io/)
- [RiskIQ PassiveTotal](https://community.riskiq.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

---

## 🔐 7. Threat Intelligence Enrichment
- [ ] Search IOCs in TI platforms
- [ ] Look for TTPs or known phishing kits
- [ ] Cross-reference domains with known campaigns
- [ ] Use YARA rules or sandbox verdicts

🔗 **Tools**:
- [AlienVault OTX](https://otx.alienvault.com/)
- [Cisco Talos](https://talosintelligence.com/)
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
- [MISP](https://www.misp-project.org/)
- [Intezer Analyze](https://analyze.intezer.com/)

---

## 📂 8. IOC Extraction
- [ ] Extract all email-related IOCs:
  - URLs
  - IPs
  - Domains
  - File hashes
  - Email addresses
- [ ] Tag and store in IOC tracker

🔗 **Tools**:
- [CAPE Sandbox](https://cape.contextis.com/)
- [IOC Bucket](https://www.iocbucket.com/)
- [YETI Threat Intel Tracker](https://github.com/yeti-platform/yeti)

---

## 🔁 9. Cross-Environment Check
- [ ] Search email gateway for similar campaigns
- [ ] Check EDR/AV logs for matches
- [ ] Investigate firewall/proxy logs for IPs or domains
- [ ] Use SIEM to look for historical context

🔗 **Tools**:
- [Splunk](https://www.splunk.com/)
- [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/)
- [Elastic SIEM](https://www.elastic.co/siem)

---

## 🛡️ 10. Containment & Remediation
- [ ] Quarantine/delete malicious emails
- [ ] Block domains, IPs, file hashes
- [ ] Update detection rules (AV, YARA, filters)
- [ ] Alert users, provide awareness training
- [ ] Monitor endpoints and lateral movement

🔗 **Tools**:
- [Abuse.ch Feeds](https://abuse.ch/)
- [YARA Rules](https://github.com/Yara-Rules/rules)
- [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search)

