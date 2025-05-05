# HTML View: Secure HTML File Analyzer & Viewer

## Overview
HTML View is a web-based security dashboard that scans, analyzes, and visualizes HTML and related files for potential security threats. It is designed for security researchers, developers, and QA teams who need to quickly assess the safety of HTML files, detect vulnerabilities, and understand the risks present in web content.

## What Does It Do?
- **Advanced Threat Detection:** Scans HTML files for a wide range of security issues, including XSS vectors, obfuscated scripts, dangerous tags, malicious attributes, and more.
- **Comprehensive Scoring:** Assigns a security score and provides a detailed report for each file, highlighting detected issues and the exact lines where problems occur.
- **File Organization:** Automatically organizes files into categories: Safe, Harmful (demonstrating specific threats), Complex (realistic mixed-content cases), and Other (XML, JSON, CSV, TXT).
- **Modern UI for Fast Triage:** The main dashboard uses tabs and search for instant navigation and review of all files and their security status.
- **No Download by Default:** The app is focused on analysis and visualization; download options for sanitized files are removed from the main UI for safety.

## How to Use
1. **Start the Flask App**
   - Run `python app.py` in your terminal.
   - Open your browser to `http://localhost:5000/`.
2. **Main Dashboard**
   - Files are grouped into Safe, Harmful, Complex, and Other tabs.
   - Use the search bar to filter files by name or issue instantly.
   - Click "Show Details" on any file to see each detected issue directly paired with the problematic line.
   - Click "View" to preview the file in a safe, read-only mode.
3. **File Structure**
   - `v1/file/safe/` – Files with no detected issues.
   - `v1/file/harmful/` – Each file demonstrates a specific security threat.
   - `v1/file/complex/` – Mixed-content and realistic web pages with multiple or subtle issues.
   - `v1/file/other/` – Non-HTML files for testing parser robustness.

## Navigation Tips
- Use the tabs to switch between categories.
- Use the search box to quickly find any file or keyword.
- Details in the report are always shown as: **Error description → Problematic line** (for maximum clarity).
- All analysis is performed server-side for safety.

## Technology Stack
- **Python 3**
- **Flask** (web framework)
- **BeautifulSoup** (HTML parsing)
- **Bleach** (HTML sanitization)
- **Bootstrap 5** (UI)

## Contributing
Feel free to fork and submit pull requests for new detection rules, UI improvements, or bug fixes.

## License
MIT License

---

*For any questions or support, please contact the maintainer listed in the repository.*
