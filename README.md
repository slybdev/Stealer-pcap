# 🕵️‍♂️ Malicious PCAP Analysis – Invoice Phishing & Data Exfiltration

## 📌 Scenario

An accountant at the organization received an email regarding an invoice with a suspicious download link. Shortly after opening the email, anomalous network activity was observed. As a SOC Analyst, I was assigned to investigate the network trace and uncover any signs of compromise or data exfiltration.

---

## 🎯 Objective

- Identify the infected machine
- Trace the malware infection path
- Extract key Indicators of Compromise (IOCs)
- Detect exfiltration behavior and tactics
- Determine malware family and behavior patterns

---

## 🧰 Tools Used

- **Wireshark** – Deep packet analysis
- **PowerShell** – Hash generation
- **Base64 Decoder** – Credential decoding
- **IP Location Tools** – Geolocation of IPs
- **Google** – Vendor/manufacturer lookup

---

## 📊 Key Findings

| # | Question | Answer |
|--|----------|--------|
| 1 | Total packets in capture | `4003` |
| 2 | First packet time | `2019-04-10 21:37:07` |
| 3 | Duration of capture | `01:03:41` |
| 4 | Most active MAC | `00:08:02:1c:47:ae` |
| 5 | NIC Manufacturer | `Hewlett-Packard` |
| 6 | Manufacturer HQ | `Palo Alto` |
| 7 | Internal hosts (/24) | `3` |
| 8 | Most active hostname | `Beijing-5cd1-PC` |
| 9 | Org’s DNS IP | `10.4.10.4` |
| 10 | Queried domain | `proforma-invoices.com` |
| 11 | Domain IP | `217.182.138.150` |
| 12 | Domain country | `France` |
| 13 | Victim OS | `Windows NT 6.1` |
| 14 | Malicious file | `tkraw_Protected99.exe` |
| 15 | MD5 hash | `71826BA081E303866CE2A2534491A2F7` |
| 16 | Web server software | `LiteSpeed` |
| 17 | Victim’s public IP | `173.66.146.112` |
| 18 | Exfiltration destination country | `United States` |
| 19 | Email server software | `Exim 4.91` |
| 20 | Exfil email recipient | `sales.del@macwinlogistics.in` |
| 21 | Password used by malware | `Sales@23` |
| 22 | Malware variant | `Reborn V9` |
| 23 | Bank credentials stolen | `username:*@******$` |
| 24 | Exfiltration interval | `Every 10 minutes` |

---

## 🧠 Step-by-Step Analysis

### 1. Initial Packet Inspection
- Opened PCAP in Wireshark
- Used `Statistics > Capture File Properties` to view total packets and duration
![Screenshot 2025-05-18 222642](https://github.com/user-attachments/assets/4948e6a1-3ea3-446b-aba4-bea0c8c8f2bd)
![Screenshot 2025-05-18 223025](https://github.com/user-attachments/assets/c66c3736-a15f-478a-96ee-397df2eea06a)

### 2. Identifying the Most Active Host
- `Statistics > Conversations > IPv4` → Sorted by bytes
- `Statistics > Endpoints` → Highest packet count = most active MAC
![Screenshot 2025-05-18 223117](https://github.com/user-attachments/assets/6349fe37-b11a-41e4-beae-567c06c4c118)

### 3. MAC Vendor Lookup
- Copied first 3 octets of MAC
- Searched online → Hewlett-Packard (HP), HQ in Palo Alto
![AA OUI](https://github.com/user-attachments/assets/334036d8-d402-42a3-9f06-26138744ef1e)

### 4. Internal Host Count
- Cheached for internal IPs using `/24` subnet under endpoints(e.g. 10.4.10.0/24)
- Found 3 devices involved
![Endpoints](https://github.com/user-attachments/assets/eff3b5b0-0552-4eb3-a61e-6e7ae987eae0)

### 5. Hostname, DNS, and HTTP Details
- Found hostname SMTP traffic
- DNS query at packet 204 revealed `proforma-invoices.com`
- DNS response pointed to `217.182.138.150` (France)
![Host Name](https://github.com/user-attachments/assets/87444f38-1b15-442e-8fb2-e9b5591cbaf2)
![Screenshot 2025-05-19 123632](https://github.com/user-attachments/assets/fa06707c-21aa-4671-b6b5-6049cdf85ebd)
![DNS response](https://github.com/user-attachments/assets/887383d5-4e13-4722-ba49-8f0b7f44ba0f)
### 6. Malware Download

- Filtered `http` traffic
- Followed TCP stream revealed download of `tkraw_Protected99.exe`
- Web server software: `LiteSpeed`
![Screenshot 2025-05-19 060357](https://github.com/user-attachments/assets/22da8691-6a07-4d98-a7ec-4f7e8dc99fd2)

### 7. Hashing
- Used PowerShell:
  ```powershell
  Get-FileHash -Algorithm MD5 .\tkraw_Protected99.exe
![Screenshot 2025-05-18 225355](https://github.com/user-attachments/assets/781b1168-115c-4dc0-b9de-aa230c6b0a8c)

### 7. Exfiltrated Data
![Screenshot 2025-05-18 224549](https://github.com/user-attachments/assets/f0db6bf4-97e2-44a5-a701-1a919aae2699)

