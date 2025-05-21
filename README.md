# HTML View: Secure HTML File Analyzer & Viewer

---

![HTML Security Dashboard](https://img.shields.io/badge/Security-Analyzer-blue?style=flat-square)

## 🛡️ Overview
HTML View is a comprehensive web-based application for analyzing and securely viewing HTML files and other text-based content. It provides advanced security analysis, file viewing capabilities, and comprehensive statistics for various file types including HTML, XML, JSON, and CSV.

---

## 🚀 Features
- **Advanced Security Analysis**:
  - Comprehensive HTML security scanning with weighted scoring
  - Detection of XSS vulnerabilities, malicious scripts, and dangerous elements
  - Realistic security scoring system (0-100)
  - Detailed issue reporting with line-by-line analysis

- **File Viewing & Analysis**:
  - Secure HTML preview with sandboxing
  - Support for multiple file formats (HTML, XML, JSON, CSV, TXT)
  - Syntax highlighting and formatted display
  - File content analysis and statistics

- **Dashboard & Statistics**:
  - Comprehensive file analysis dashboard
  - Detailed security metrics and trends
  - File categorization and organization
  - Search and filtering capabilities

- **Security Features**:
  - Advanced HTML sanitization using multiple methods
  - File type detection and content validation
  - Blacklist-based file filtering
  - Path-based security restrictions

- **Modern UI**:
  - Responsive Bootstrap 5 interface
  - Tab-based navigation
  - Real-time file searching
  - Clear error visualization
  - Secure sandboxed previews

---

## 🗂️ How to Use

1. **Installation**
   ```bash
   pip install -r requirements.txt
   ```

2. **Running the Application**
   ```bash
   python app.py
   ```
   The application will be available at http://localhost:5000

3. **Main Interface**
   - **Dashboard View**: Comprehensive overview of all files and their security status
   - **File Analysis**: Detailed security analysis and content viewing
   - **Statistics**: In-depth metrics and trends about file content

4. **File Organization**
   - **Safe Files**: Files with no detected security issues
   - **Harmful Files**: Files containing potential security threats
   - **Complex Files**: Files with multiple or subtle security concerns
   - **Other Files**: Non-HTML files (XML, JSON, CSV, TXT)

5. **Security Features**
   - Files are automatically sanitized before viewing
   - Security analysis is performed on all HTML content
   - Malicious content is highlighted and explained
   - Safe preview mode prevents script execution

---

## 🎯 Security Analysis

The application performs comprehensive security analysis on HTML files using a weighted scoring system (0-100):

### Security Score Components

1. **Scripting & Execution**
   - `<script>` tags and obfuscated scripts (-40)
   - Inline event handlers (onclick, onload) (-20)
   - JavaScript URLs (javascript:) (-25)
   - SVG/MathML scripting (-10)

2. **Navigation & Redirection**
   - `<iframe>` tags (-18)
   - `<base>` tag (-7)
   - Meta refresh (-10)

3. **Data & Content**
   - External form actions (-18)
   - Data URLs (-8)
   - HTML imports (-6)

4. **Styling & Layout**
   - `<style>` tags (-8)
   - Dangerous inline styles (-22)
   - `<template>` tag (-5)

5. **Other Risks**
   - Suspicious comments (-4)
   - Object/embed/applet tags (-15)

### Security Measures
- Files are automatically sanitized using multiple methods:
  - Bleach-based sanitization
  - BeautifulSoup parsing
  - Custom sanitization rules
- Blacklisted file types and paths are blocked
- All HTML previews are rendered in secure iframes
- Malicious content is highlighted and explained

---

## 🧑‍💻 Technology Stack

- **Backend**
  - Python 3.8+
  - Flask 2.0.0+
  - BeautifulSoup4 4.12.0+
  - Bleach 6.1.0+

- **Frontend**
  - Bootstrap 5
  - HTML5
  - CSS3
  - JavaScript

- **Security Libraries**
  - BeautifulSoup4 for parsing
  - Bleach for sanitization
  - Custom security rules

---

## 🤝 Contributing
Pull requests are welcome for new detection rules, UI improvements, or bug fixes!

---

## 📄 License
MIT License

---

*For questions or support, please contact the maintainer listed in the repository.*
