# 🛡️ SSH Brute-Force Detector & Security Analytics

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Security](https://img.shields.io/badge/Cybersecurity-BlueTeam-00ff66?style=flat)](#)

A real-time cybersecurity log analyzer tool designed to detect SSH brute-force attacks. It parses Linux auth logs and Windows Security Events, highlights attacking IPs, renders real-time visual charts, and provides instant mitigation commands.

---

## ✨ Key Features

- **🚨 Automated Brute-Force Detection:** Detects rapid failed login attempts from malicious IPs.
- **📊 Visual Analytics Bar Charts:** Visual breakdown of failed attempt counts per IP address.
- **💥 Account Compromise Alerts:** Triggers critical warnings if a successful login occurs following multiple failed attempts from the same IP.
- **🛡️ Instant Firewall Mitigation:** Generates terminal commands like `sudo ufw deny from <IP>` for fast response.
- **💻 Cross-Platform Support:** Parses Linux SSH `/var/log/auth.log` and Windows Event Logs (Event ID 4625 / 4624).
- **🔒 Client-Side Execution:** 100% browser-based analysis — no log data is uploaded to external servers.

---

## 🛠️ Tech Stack

- **Frontend UI:** HTML5, CSS3 (Dark Mode / Responsive Grid)
- **Analytics Engine:** Vanilla JavaScript (Regex log parsing & DOM manipulation)
- **Log Compatibility:** OpenSSH (`sshd`) & Windows Security Logs

---

## ⚡ How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Bhoomijaiswal28/ssh-brute-force-detectors-.git](https://github.com/Bhoomijaiswal28/ssh-brute-force-detectors-.git)
   ```

2. **Navigate to project directory:**
   ```bash
   cd ssh-brute-force-detectors-
   ```

3. **Open Application:**
   Open `index.html` in any web browser or launch via VS Code Live Server (`http://127.0.0.1:5500/index.html`).

---

## 📖 Usage Instructions

1. Click **LOAD SAMPLE LOG** to load demo brute-force attack logs.
2. Alternatively, paste raw log lines or upload a log file via **UPLOAD FILE**.
3. Click **ANALYZE →**.
4. View real-time stats, bar chart breakdowns, and recommended firewall block commands.

---

## 👤 Author

**Bhoomi Jaiswal**  
GitHub: [@Bhoomijaiswal28](https://github.com/Bhoomijaiswal28)

live demo: https://bhoomijaiswal28.github.io/ssh-brute-force-detectors-/

---
*Built for security analytics and educational demonstration purposes.*
