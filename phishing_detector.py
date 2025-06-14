import tkinter as tk
from tkinter import messagebox, scrolledtext
import validators
import requests
import difflib
import re
import threading
import socket
import ssl

# Known legit domains for similarity check
KNOWN_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "amazon.com",
    "apple.com", "microsoft.com", "twitter.com", "linkedin.com",
    "peoplesbank.lk", "paypal.com", "netflix.com", "wellsfargo.com"
]

# Regex-based phishing signals
SUSPICIOUS_PATTERNS = {
    "Fake login form": r"<form[^>]*action=[\"']?[^>]*login[^>]*>",
    "Password field detected": r"<input[^>]+type=[\"']?password[\"']?",
    "Credit card field detected": r"(credit[\s_-]?card|cc-num|cc_number)",
    "JavaScript redirect": r"window\\.location|window\\.open|document\\.location",
    "Suspicious script call": r"<script[^>]+src=[\"']?(http[^\"']+)",
    "Sensitive action keywords": r"(verify|reset|confirm|update)[\s\S]{1,20}(account|password|email)"
}

def expand_short_url(url):
    try:
        session = requests.Session()
        resp = session.head(url, allow_redirects=True, timeout=6)
        return resp.url if resp.url != url else None
    except:
        return None

def validate_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert is not None
    except:
        return False

def get_redirect_chain(url):
    try:
        session = requests.Session()
        resp = session.get(url, allow_redirects=True, timeout=6)
        chain = [r.url for r in resp.history] + [resp.url]
        return chain
    except:
        return []

def url_analysis(url):
    results = []
    if not validators.url(url):
        results.append("❌ Invalid URL syntax.")
        return results, None, None

    if len(url) > 75:
        results.append("⚠️ Suspiciously long URL (>75 characters).")

    if not url.startswith("https://"):
        results.append("⚠️ Missing HTTPS - connection not secure.")

    if re.match(r"http[s]?://(\d{1,3}\.){3}\d{1,3}", url):
        results.append("❌ IP address used instead of domain name.")

    domain = url.split("//")[-1].split("/")[0].lower()
    for known in KNOWN_DOMAINS:
        similarity = difflib.SequenceMatcher(None, domain, known).ratio()
        if similarity > 0.7 and domain != known:
            results.append(f"❌ Domain closely resembles known domain: {known}")

    ssl_valid = validate_ssl_certificate(domain)
    if not ssl_valid:
        results.append("⚠️ SSL certificate could not be verified.")

    if not results:
        results.append("✅ URL passed all basic checks.")

    return results, domain, url

def check_page_content(url):
    try:
        response = requests.get(url, timeout=6)
        content = response.text.lower()
        found_signals = []
        for description, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, content):
                found_signals.append(f"⚠️ {description}")
        return found_signals if found_signals else ["✅ Content appears clean."]
    except Exception as e:
        return [f"⚠️ Could not fetch page content: {e}"]

# GUI setup (unchanged visually)
root = tk.Tk()
root.title("🛡️ UltraShield URL Inspector")
root.geometry("900x750")
root.configure(bg="#1a1a2e")

tk.Label(root, text="Developed for Cybersecurity Awareness | Made by Dilan Umesh",
         font=("Segoe UI", 11, "bold"), fg="#a1caff", bg="#1a1a2e").pack(pady=10)

tk.Label(root, text="🛡️ Phishing URL Detector", font=("Segoe UI", 24, "bold"),
         fg="#e1eaff", bg="#1a1a2e").pack(pady=(0, 15))

tk.Label(root, text="Enter URL to scan:", font=("Segoe UI", 14), fg="white", bg="#1a1a2e").pack()
url_entry = tk.Entry(root, font=("Segoe UI", 14), width=70, bd=3, relief="groove")
url_entry.pack(pady=10)

# <<< Changed height from 10 to 18 here >>>
output_box = scrolledtext.ScrolledText(root, width=100, height=18, font=("Courier New", 11),
                                       bg="#222733", fg="#76f2d4", bd=3, relief="sunken")
output_box.pack(pady=(5, 15))

def run_scan_thread():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input needed", "Please enter a URL to scan.")
        return

    scan_button.config(state="disabled")
    output_box.config(state='normal')
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"🔍 Scanning URL: {url}\n\n")
    output_box.config(state='disabled')

    def scan():
        expanded = expand_short_url(url)
        if expanded:
            output_box.config(state='normal')
            output_box.insert(tk.END, f"🔁 Shortened URL expanded to: {expanded}\n")
            output_box.config(state='disabled')
            url_to_check = expanded
        else:
            url_to_check = url

        url_results, domain, final_url = url_analysis(url_to_check)
        chain = get_redirect_chain(url_to_check)
        suspicious_redirect = any("http://" in u or any(k not in u for k in KNOWN_DOMAINS) for u in chain)

        output_box.config(state='normal')
        for line in url_results:
            output_box.insert(tk.END, line + "\n")
        if chain and len(chain) > 1:
            output_box.insert(tk.END, f"🔗 Redirection chain:\n  " + "\n  ".join(chain) + "\n")
        if suspicious_redirect:
            output_box.insert(tk.END, "⚠️ Final destination may be suspicious based on redirect.\n")

        output_box.insert(tk.END, "\n🌐 Checking page content...\n")
        output_box.config(state='disabled')

        signals = check_page_content(url_to_check)
        output_box.config(state='normal')
        for line in signals:
            output_box.insert(tk.END, line + "\n")
        output_box.insert(tk.END, "\n")

        final_result = "❌ Suspicious URL" if any("⚠️" in line or "❌" in line for line in url_results + signals) else "✅ Clean URL"
        output_box.insert(tk.END, f"\n🔚 Final Result: {final_result}\n")
        output_box.config(state='disabled')
        scan_button.config(state="normal")

    threading.Thread(target=scan, daemon=True).start()

scan_button = tk.Button(root, text="🚀 Check", font=("Segoe UI", 14, "bold"), bg="#f25c54",
                        fg="white", padx=25, pady=7, command=run_scan_thread)
scan_button.pack(pady=10)

edu_text = """What is Phishing?
Phishing is a cyber attack where attackers trick you by pretending to be trustworthy.
They use fake emails, messages, or websites to steal your sensitive info like passwords or credit cards.

How Does Phishing Work?
- Attackers create fake websites or emails that look real and trustworthy.
- They lure victims into entering personal or financial information.
- The stolen data is used to commit fraud or identity theft.

How Can You Detect Phishing?
- Check URLs carefully for strange spellings or IP addresses.
- Always look for HTTPS and a valid security certificate.
- Be cautious of urgent or suspicious requests to update or verify accounts.
- Use URL scanning tools and anti-phishing software.

How Can You Prevent Phishing?
- Never click on links or download attachments from unknown sources.
- Verify website URLs before submitting any sensitive info.
- Enable two-factor authentication wherever possible.
- Keep your browser and security software updated.

Examples of phishing domains:
- g00gle.com instead of google.com
- faceb00k.com instead of facebook.com
- amaz0n-secure.com instead of amazon.com
"""

edu_box = scrolledtext.ScrolledText(root, font=("Segoe UI", 14), bg="#283046",
                                    fg="#cde6ff", bd=3, relief="ridge", wrap='word', height=20)
edu_box.pack(fill='both', expand=True, padx=15, pady=15)
edu_box.insert(tk.END, edu_text)

for heading in [
    "What is Phishing?", "How Does Phishing Work?",
    "How Can You Detect Phishing?", "How Can You Prevent Phishing?",
    "Examples of phishing domains:"]:
    start = '1.0'
    while True:
        pos = edu_box.search(heading, start, stopindex=tk.END)
        if not pos:
            break
        end = f"{pos}+{len(heading)}c"
        edu_box.tag_add("heading", pos, end)
        start = end

edu_box.tag_configure("heading", font=("Segoe UI", 16, "bold"),
                      background="#3e4a72", foreground="#a8d0ff")
edu_box.config(state='disabled')

tk.Label(root, text="Stay alert and protect yourself from phishing attacks!",
         font=("Segoe UI", 18, "bold"), fg="#ff5555", bg="#1a1a2e", pady=15).pack()

root.mainloop()

