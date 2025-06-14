# UltraShield URL Inspector

This is a phishing link detection tool I made using Python. It uses a simple GUI (Tkinter) to let users enter any URL and check if it's safe or suspicious.

---

## Features

- Expands shortened links (like is.gd, bit.ly, etc.)
- Checks if the link redirects to another URL
- Verifies SSL certificate (checks if HTTPS is valid)
- Scans page content for suspicious stuff like fake login forms, password fields, JavaScript redirects
- Compares the link with trusted websites like google.com, facebook.com, etc.
- Shows final result clearly: ✅ Clean URL or ❌ Suspicious URL
- Also includes a built-in education box explaining what phishing is


## How to Run

python3 phishing_detector.py



1. Make sure you have **Python 3** installed.
2. Install the required libraries:


```bash
pip install validators requests

```

Developer

Made by Dilan Umesh
For cybersecurity awareness and learning.
Sri Lanka 🇱🇰



⚠️ Disclaimer

This tool is for educational and cybersecurity awareness purposes only. Always validate findings manually. Do not use this tool for malicious purposes.
