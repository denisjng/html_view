# HTML View: Secure HTML File Analyzer & Viewer

---

![HTML Security Dashboard](https://img.shields.io/badge/Security-Analyzer-blue?style=flat-square)

## 🛡️ Overview
HTML View is a modern, web-based dashboard for scanning, analyzing, and visualizing HTML and related files for security threats. Built for security researchers, developers, and QA teams, it helps you:
- **Assess the safety of HTML files**
- **Detect vulnerabilities and risky constructs**
- **Understand the severity of web content threats**

---

## 🚀 Features
- **Advanced Threat Detection**: Scans for XSS, obfuscated scripts, dangerous tags, malicious attributes, and more
- **Realistic Security Scoring**: Assigns a severity-weighted score to each file, reflecting the true risk of discovered issues
- **File Organization**: Automatically sorts files into Safe, Harmful, Complex, and Other categories
- **Modern UI**: Fast triage with tabbed navigation, file search, and clear error/line pairing
- **Safe Preview**: Sanitized HTML is rendered in a secure sandboxed iframe—no scripts or styles will execute

---

## 🗂️ How to Use
1. **Start the Flask App**
   ```bash
   python app.py
   ```
   Then open [http://localhost:5000/](http://localhost:5000/) in your browser.
2. **Main Dashboard**
   - Files are grouped in tabs: Safe, Harmful, Complex, Other
   - Use the search bar to filter files by name or issue
   - Click "Show Details" to see each detected issue paired with its problematic line
   - Click "View" to preview the file in a safe, read-only mode
3. **File Structure**
   - `v1/file/safe/` – Files with no detected issues
   - `v1/file/harmful/` – Each file demonstrates a specific security threat
   - `v1/file/complex/` – Realistic web pages with multiple/subtle issues
   - `v1/file/other/` – Non-HTML files for parser robustness

---

## 🎯 How the Security Score Works

The **Security Score** reflects the real-world risk of each HTML file, starting from 100 (safe) and deducting points for each detected issue based on its severity:

| Threat Type                         | Example/Trigger                | Deduction | Rationale                          |
|-------------------------------------|-------------------------------|-----------|-------------------------------------|
| `<script>` tag / obfuscated script  | `<script>`, encoded script    |    -40    | Highest risk: XSS                   |
| Inline event handler                | `onclick`, `onload`, etc.     |    -20    | Easy XSS, phishing                  |
| JavaScript URLs                     | `href="javascript:..."`      |    -25    | XSS, drive-by attacks               |
| `<iframe>` tag                      | `<iframe>`                    |    -18    | Phishing, clickjacking              |
| `<object>`, `<embed>`, `<applet>`   | Plugin tags                   |    -15    | Plugin-based attacks                |
| `<form>` with external action       | `action="http://..."`        |    -18    | Data exfiltration, phishing         |
| `<meta http-equiv="refresh">`      | Meta refresh                  |    -10    | Forced redirects                    |
| HTML Imports                        | `<link rel="import">`        |    -6     | Deprecated, risky                   |
| Data URLs                           | `src="data:..."`             |    -8     | Obfuscated payloads                 |
| `<style>` tag                       | `<style>`                     |    -8     | CSS-based attacks                   |
| Dangerous inline style              | `style="expression(...)"`    |    -22    | CSS expressions, JS in CSS          |
| `<base>` tag                        | `<base>`                      |    -7     | Alters URL resolution               |
| SVG/MathML scripting                | `<svg><script>...</svg>`      |    -10    | Scripting in SVG                    |
| `<template>` tag                    | `<template>`                  |    -5     | DOM manipulation tricks             |
| Suspicious comments                 | `<!--#exec-->`                |    -4     | Obfuscation, legacy exploits        |

- **Score never goes below 0.**
- The dashboard shows the score and main issues for each file, so you can prioritize review and remediation.

---

## 🧑‍💻 Technology Stack
- **Python 3**
- **Flask** (web framework)
- **BeautifulSoup** (HTML parsing)
- **Bleach** (HTML sanitization)
- **Bootstrap 5** (UI)

---

## 🤝 Contributing
Pull requests are welcome for new detection rules, UI improvements, or bug fixes!

---

## 📄 License
MIT License

---

*For questions or support, please contact the maintainer listed in the repository.*
