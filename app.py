# Standard library
import fnmatch
import logging
import os
from urllib.parse import unquote

# Third-party libraries
from flask import Flask, Response, make_response, request, render_template, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup, Comment
import bleach
from typing import List, Dict, Any
import json
import csv
import xml.etree.ElementTree as ET
import io
import re

app = Flask(__name__)

# Configuration (minimal for demo)
BLACKLISTED_FILES = ['*.exe', '*.bat', '*.sh']
BLACKLISTED_PATHS = ['/etc/*', '/bin/*']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Security helpers ---
def is_file_blacklisted(filename):
    """
    Checks if a file is blacklisted based on its extension.
    """
    return any(fnmatch.fnmatch(filename, pattern) for pattern in (BLACKLISTED_FILES or []))

def is_path_blacklisted(filepath):
    """
    Checks if a path is blacklisted.
    """
    return any(fnmatch.fnmatch(filepath, pattern) for pattern in (BLACKLISTED_PATHS or []))

def advanced_security_score_html(html_content):
    """
    Advanced security scoring for HTML, reflecting real-world threat severity.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    score = 100
    issues = []
    details = []
    # 1. <script> tags (highest risk: XSS)
    script_regex = re.compile(r'<\s*script[^>]*>', re.IGNORECASE)
    if soup.find_all('script') or script_regex.search(html_content) or re.search(r's\\u0063ript|&#x73;cript', html_content, re.IGNORECASE):
        issues.append('script_tag')
        details.append("<script> tag or obfuscated script detected")
        score -= 40  # Major deduction
    # 2. Inline event handlers (e.g. onclick) - high risk
    if any(tag for tag in soup.find_all(True) for attr in tag.attrs if attr.lower().startswith('on')):
        issues.append('inline_event_handler')
        details.append("Inline event handler (e.g. onclick) detected")
        score -= 20
    # 3. JavaScript URLs (e.g. href="javascript:") - high risk
    if re.search(r'href\s*=\s*["\]?javascript:', html_content, re.IGNORECASE):
        issues.append('js_href')
        details.append('javascript: URL detected')
        score -= 25
    # 4. <iframe> tags (used for phishing, clickjacking)
    if soup.find_all('iframe'):
        issues.append('iframe_tag')
        details.append("<iframe> tag detected")
        score -= 18
    # 5. <object>, <embed>, <applet> (plugin-based attacks)
    if soup.find_all('object'):
        issues.append('object_tag')
        details.append("<object> tag detected")
        score -= 15
    if soup.find_all('embed'):
        issues.append('embed_tag')
        details.append("<embed> tag detected")
        score -= 15
    if soup.find_all('applet'):
        issues.append('applet_tag')
        details.append("<applet> tag detected")
        score -= 15
    # 6. <form> with external action (phishing/data exfiltration)
    for form in soup.find_all('form'):
        action = form.get('action', '')
        if action.startswith('http://') or action.startswith('https://') or action.startswith('//'):
            issues.append('form_external')
            details.append("<form> with external action detected")
            score -= 18
    # 7. <meta http-equiv="refresh"> (redirects)
    for meta in soup.find_all('meta'):
        if meta.get('http-equiv', '').lower() == 'refresh':
            issues.append('meta_refresh')
            details.append("<meta http-equiv='refresh'> detected")
            score -= 10
    # 8. <link rel="import"> (HTML imports, deprecated but risky)
    if re.search(r'rel\s*=\s*["\]?import', html_content, re.IGNORECASE):
        issues.append('html_import')
        details.append('HTML import link detected')
        score -= 6
    # 9. Data URLs (possible obfuscated payloads)
    if re.search(r'(src|href)\s*=\s*["\]?data:', html_content, re.IGNORECASE):
        issues.append('data_url')
        details.append('Data URL detected')
        score -= 8
    # 10. <style> tags (may contain CSS expressions)
    if soup.find_all('style'):
        issues.append('style_tag')
        details.append("<style> tag detected")
        score -= 8
    # 11. Inline style with dangerous content (CSS expressions, JS in URL)
    for tag in soup.find_all(True):
        style = tag.get('style', '')
        if 'expression(' in style.lower() or 'javascript:' in style.lower():
            issues.append('inline_style')
            details.append('Dangerous inline style (expression/javascript) detected')
            score -= 22
    # 12. <base> tag (can change URL resolution)
    if soup.find_all('base'):
        issues.append('base_tag')
        details.append("<base> tag detected")
        score -= 7
    # 13. SVG/MathML <script> or <foreignObject> (rare, but can be abused)
    for svg in soup.find_all('svg'):
        if svg.find_all(['script', 'foreignObject']):
            issues.append('svg_script_or_foreignObject')
            details.append("SVG/MathML with script/foreignObject detected")
            score -= 10
    # 14. <template> tag (can be used for DOM tricks)
    if soup.find_all('template'):
        issues.append('template_tag')
        details.append("<template> tag detected")
        score -= 5
    # 15. Suspicious comments (e.g., <!--#exec -->, base64, conditional comments)
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for c in comments:
        if re.search(r'exec|base64|\[if|#inclu', c, re.IGNORECASE):
            issues.append('suspicious_comment')
            details.append('Suspicious comment detected')
            score -= 4
    # Clamp score to minimum 0
    score = max(score, 0)
    return score, issues, details

def remove_harmful_parts(html_content, issues):
    """
    Removes harmful parts from the HTML content based on detected issues.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    # Remove <script> tags and their content
    if 'script_tag' in issues:
        [tag.decompose() for tag in soup.find_all('script')]
    # Remove <style> tags and their content
    if 'style_tag' in issues:
        [tag.decompose() for tag in soup.find_all('style')]
        # Also remove all <style> tag text nodes left behind (edge case)
        for text in soup.find_all(string=True):
            parent = text.parent
            if parent and parent.name == '[document]' and '{' in text and '}' in text:
                text.extract()
    # Remove inline event handlers
    if 'inline_event_handler' in issues:
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                if attr.lower().startswith('on'):
                    del tag.attrs[attr]
    # Remove <iframe> tags
    if 'iframe_tag' in issues:
        [tag.decompose() for tag in soup.find_all('iframe')]
    # Remove javascript: URLs
    if 'javascript_url' in issues:
        for tag in soup.find_all(['a', 'img', 'iframe', 'form', 'link', 'script']):
            for attr in ['href', 'src', 'action']:
                if attr in tag.attrs and isinstance(tag[attr], str) and tag[attr].lower().strip().startswith('javascript:'):
                    del tag.attrs[attr]
    # Remove <object>, <embed>, <applet>
    if 'object_tag' in issues:
        [tag.decompose() for tag in soup.find_all('object')]
    if 'embed_tag' in issues:
        [tag.decompose() for tag in soup.find_all('embed')]
    if 'applet_tag' in issues:
        [tag.decompose() for tag in soup.find_all('applet')]
    # Remove forms with external actions
    if 'form_external' in issues:
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action.startswith('http') and not action.startswith('/'):
                form.decompose()
    # Remove meta refresh
    if 'meta_refresh' in issues:
        for meta in soup.find_all('meta'):
            if meta.get('http-equiv', '').lower() == 'refresh':
                meta.decompose()
    # Remove HTML imports
    if 'html_import' in issues:
        for link in soup.find_all('link'):
            if link.get('rel') and 'import' in link.get('rel'):
                link.decompose()
    # Remove data URLs
    if 'data_url' in issues:
        for tag in soup.find_all(['img', 'audio', 'video', 'source', 'iframe']):
            for attr in ['src', 'href']:
                if attr in tag.attrs and isinstance(tag[attr], str) and tag[attr].strip().startswith('data:'):
                    del tag.attrs[attr]
    # Remove inline style attributes
    if 'inline_style' in issues:
        for tag in soup.find_all(True):
            if 'style' in tag.attrs:
                del tag.attrs['style']
    # Remove <base> tags
    if 'base_tag' in issues:
        [tag.decompose() for tag in soup.find_all('base')]
    # Remove SVG <script> or <foreignObject>
    if 'svg_script_or_foreignObject' in issues:
        for svg in soup.find_all('svg'):
            [t.decompose() for t in svg.find_all(['script', 'foreignObject'])]
    # Remove <template> tags
    if 'template_tag' in issues:
        [tag.decompose() for tag in soup.find_all('template')]
    # Remove suspicious comments
    if 'suspicious_comment' in issues:
        for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
            c.extract()
    return str(soup)

def extract_lines_with_issues(html_content, issues):
    """
    Extracts lines from the HTML that correspond to detected issues.
    Returns a list of lines, one per issue, in the same order as the issues list.
    """
    lines = html_content.splitlines()
    result = []
    # Map issue types to detection logic
    for idx, line in enumerate(lines, 1):
        l = line.lower()
        # Each if checks for a specific issue and adds the line if matched
        if 'script' in issues and '<script' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'iframe' in issues and '<iframe' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'inline_event_handler' in issues and ('onclick' in l or 'onload' in l or 'onerror' in l):
            result.append(f"Line {idx}: {line.strip()}")
        if 'javascript_url' in issues and 'javascript:' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'object_tag' in issues and '<object' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'embed_tag' in issues and '<embed' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'applet_tag' in issues and '<applet' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'form_external' in issues and '<form' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'meta_refresh' in issues and '<meta' in l and 'refresh' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'html_import' in issues and '<link' in l and 'import' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'data_url' in issues and 'data:' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'style_tag' in issues and '<style' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'inline_style' in issues and 'style=' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'base_tag' in issues and '<base' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'svg_script_or_foreignObject' in issues and '<svg' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'template_tag' in issues and '<template' in l:
            result.append(f"Line {idx}: {line.strip()}")
        if 'suspicious_comment' in issues and 'exec' in l:
            result.append(f"Line {idx}: {line.strip()}")
    return result

# --- Utility for advanced bleach sanitization ---
def sanitize_html_bleach(html_content: str, mode: str = 'strict') -> str:
    """
    Sanitizes HTML content using bleach.
    """
    # Strict: only allow very safe tags/attrs; Relaxed: allow more for usability
    strict_tags = [
        'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul', 'p', 'br', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'img', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'pre']
    strict_attrs = {
        '*': ['class', 'id', 'title', 'alt', 'style'],
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'title'],
    }
    relaxed_tags = strict_tags + ['hr', 'footer', 'header', 'section', 'nav', 'main', 'article']
    relaxed_attrs = dict(strict_attrs)
    relaxed_attrs['*'] += ['data-*']
    if mode == 'strict':
        return bleach.clean(html_content, tags=strict_tags, attributes=strict_attrs, strip=True)
    else:
        return bleach.clean(html_content, tags=relaxed_tags, attributes=relaxed_attrs, strip=True)

# --- General error rendering utility ---
def render_custom_error(title: str, reason: str, status: int = 403, suggestion: str = None, support_url: str = None):
    """
    Renders a custom error page.
    """
    return render_template('view_error.html', reason=reason, title=title, suggestion=suggestion, support_url=support_url), status

# --- File type detection utility ---
def detect_file_type(filename: str) -> str:
    """
    Detects the file type based on its extension.
    """
    ext = filename.lower().rsplit('.', 1)[-1]
    if ext in ['html', 'htm']: return 'html'
    if ext == 'xml': return 'xml'
    if ext == 'json': return 'json'
    if ext == 'csv': return 'csv'
    if ext == 'txt': return 'txt'
    return 'unknown'

# --- Add support for XML, JSON, TXT, CSV ---
import json
import csv
import xml.etree.ElementTree as ET

def analyze_file_content(filename: str, raw: str, filetype: str) -> Dict[str, Any]:
    """
    Analyzes the file content and returns a dictionary with the results.
    """
    if filetype == 'html':
        score, issues, details = advanced_security_score_html(raw)
        lines = extract_lines_with_issues(raw, issues)
        return dict(score=score, issues=issues, details=details, lines=lines)
    if filetype == 'xml':
        try:
            tree = ET.ElementTree(ET.fromstring(raw))
            # Check for DTD, XXE, script tags
            issues, details, lines = [], [], []
            if '<!DOCTYPE' in raw.upper():
                issues.append('dtd_doctype')
                details.append('Contains DOCTYPE (possible XXE vector)')
                for i, line in enumerate(raw.splitlines(), 1):
                    if '<!DOCTYPE' in line.upper():
                        lines.append(f"Line {i}: {line.strip()}")
            if '<script' in raw.lower():
                issues.append('script_tag')
                details.append('Contains <script> tag')
                for i, line in enumerate(raw.splitlines(), 1):
                    if '<script' in line.lower():
                        lines.append(f"Line {i}: {line.strip()}")
            score = 100 - 30*len(issues)
            return dict(score=max(score,0), issues=issues, details=details, lines=lines)
        except Exception as e:
            return dict(score=0, issues=['parse_error'], details=[str(e)], lines=[])
    if filetype == 'json':
        try:
            parsed = json.loads(raw)
            # Check for embedded HTML/script
            issues, details, lines = [], [], []
            if any(isinstance(v, str) and '<script' in v.lower() for v in json.dumps(parsed).splitlines()):
                issues.append('script_tag')
                details.append('Contains <script> tag in value')
            score = 100 - 30*len(issues)
            return dict(score=max(score,0), issues=issues, details=details, lines=[])
        except Exception as e:
            return dict(score=0, issues=['parse_error'], details=[str(e)], lines=[])
    if filetype == 'csv':
        try:
            lines = raw.splitlines()
            issues, details = [], []
            if any('javascript:' in l.lower() for l in lines):
                issues.append('javascript_url')
                details.append('Contains javascript: URL in CSV')
            score = 100 - 30*len(issues)
            return dict(score=max(score,0), issues=issues, details=details, lines=[f"Line {i+1}: {l}" for i,l in enumerate(lines) if 'javascript:' in l.lower()])
        except Exception as e:
            return dict(score=0, issues=['parse_error'], details=[str(e)], lines=[])
    if filetype == 'txt':
        # Plain text: no issues unless script detected
        lines = raw.splitlines()
        issues, details = [], []
        if any('<script' in l.lower() for l in lines):
            issues.append('script_tag')
            details.append('Contains <script> tag in text')
        score = 100 - 30*len(issues)
        return dict(score=max(score,0), issues=issues, details=details, lines=[f"Line {i+1}: {l}" for i,l in enumerate(lines) if '<script' in l.lower()])
    return dict(score=0, issues=['unknown_type'], details=['Unknown file type'], lines=[])

# --- Download sanitized version endpoint ---
@app.route('/download_sanitized/<path:filename>/<mode>')
def download_sanitized(filename, mode):
    """
    Downloads a sanitized version of the file.
    """
    filepath = unquote(filename)
    filetype = detect_file_type(filepath)
    if not os.path.exists(filepath):
        return render_custom_error("Not Found", "File does not exist.", 404)
    with open(filepath, encoding='utf-8', errors='replace') as f:
        raw = f.read()
    if filetype == 'html':
        sanitized = sanitize_html_bleach(raw, mode=mode)
        return send_file(io.BytesIO(sanitized.encode('utf-8')), mimetype='text/html', as_attachment=True, download_name=f"{os.path.basename(filepath)}.sanitized.html")
    # For xml, json, csv, txt: just return as txt
    return send_file(io.BytesIO(raw.encode('utf-8')), mimetype='text/plain', as_attachment=True, download_name=f"{os.path.basename(filepath)}.sanitized.txt")

# --- Update /view/<filename> to support all file types ---
@app.route('/view/<path:filename>')
def view_html(filename):
    """
    Views the file.
    """
    filepath = unquote(filename)
    filetype = detect_file_type(filepath)
    summary = test_html_files_and_summary()
    file_report = next((r for r in summary if r['file'] == filepath), None)
    if not file_report:
        return render_custom_error("Not Found", "File not found in report list.", 404)
    if file_report['status'] in ('BLOCKED', 'ERROR', 'SKIPPED'):
        return render_custom_error("Access Denied", file_report['reason'], 403, suggestion="Contact admin if you believe this is a mistake.", support_url="mailto:support@example.com")
    if file_report['status'] == 'UNSAFE':
        if filetype == 'html':
            cleaned = sanitize_html_bleach(file_report['raw'], mode='strict')
            return render_template('view_sanitized.html', html=cleaned, reason=file_report['reason'], issues=file_report['issues'], details=file_report['details'], filename=filename)
        # For other types, show as plain text
        return render_template('view_error.html', reason="Viewing of unsafe non-HTML files is not supported.", title="Unsafe File"), 403
    # SAFE
    # HTML: render, others: pretty print
    if filetype == 'html':
        return Response(file_report['raw'], mimetype='text/html')
    elif filetype == 'xml':
        try:
            tree = ET.ElementTree(ET.fromstring(file_report['raw']))
            xml_str = ET.tostring(tree.getroot(), encoding='unicode')
        except Exception as e:
            xml_str = file_report['raw']
        return render_template('view_plain.html', content=xml_str, filetype='XML', filename=filename)
    elif filetype == 'json':
        try:
            parsed = json.loads(file_report['raw'])
            json_str = json.dumps(parsed, indent=2)
        except Exception as e:
            json_str = file_report['raw']
        return render_template('view_plain.html', content=json_str, filetype='JSON', filename=filename)
    elif filetype == 'csv':
        return render_template('view_plain.html', content=file_report['raw'], filetype='CSV', filename=filename)
    elif filetype == 'txt':
        return render_template('view_plain.html', content=file_report['raw'], filetype='TXT', filename=filename)
    else:
        return render_custom_error("Unknown File Type", "Cannot preview this file type.", 415)

# --- Optimize and refactor test_html_files_and_summary ---
def test_html_files_and_summary():
    """
    Scans all organized HTML and related files, runs security analysis, and returns a summary list for dashboard rendering.
    """
    test_files = [
        # Safe
        'v1/file/safe/safe_basic.html',
        # Harmful (one per case)
        'v1/file/harmful/harmful_script.html',
        'v1/file/harmful/harmful_iframe.html',
        'v1/file/harmful/harmful_js_href.html',
        'v1/file/harmful/harmful_inline_event.html',
        'v1/file/harmful/harmful_object.html',
        'v1/file/harmful/harmful_embed.html',
        'v1/file/harmful/harmful_applet.html',
        'v1/file/harmful/harmful_form_external.html',
        'v1/file/harmful/harmful_meta_refresh.html',
        'v1/file/harmful/harmful_html_import.html',
        'v1/file/harmful/harmful_data_url.html',
        'v1/file/harmful/harmful_style.html',
        'v1/file/harmful/harmful_inline_style.html',
        'v1/file/harmful/harmful_base.html',
        'v1/file/harmful/harmful_svg_script.html',
        'v1/file/harmful/harmful_template.html',
        'v1/file/harmful/harmful_comment.html',
        'v1/file/harmful/harmful_multiple.html',
        # Complex
        'v1/file/complex/complex_blog.html',
        'v1/file/complex/complex_news.html',
        'v1/file/complex/complex_dashboard.html',
        'v1/file/complex/complex_ecommerce.html',
        'v1/file/complex/complex_portfolio.html',
        'v1/file/complex/complex_corporate.html',
        'v1/file/complex/complex_forum.html',
        'v1/file/complex/complex_gallery.html',
        'v1/file/complex/complex_mixed.html',
        'v1/file/complex/complex_safe.html',
        # Other
        'v1/file/other/sample.xml',
        'v1/file/other/sample.json',
        'v1/file/other/sample.csv',
        'v1/file/other/sample.txt',
    ]
    summary = []
    for file in test_files:
        filename = unquote(file)
        if not os.path.exists(filename):
            result = {'file': file, 'status': 'ERROR', 'reason': 'File not found', 'score': 0, 'issues': ['not_found'], 'details': ['File does not exist'], 'lines': [], 'raw': ''}
            summary.append(result)
            continue
        with open(filename, encoding='utf-8', errors='replace') as f:
            raw = f.read()
        filetype = detect_file_type(filename)
        analysis = analyze_file_content(filename, raw, filetype)
        issues = analysis['issues']
        if issues:
            status = 'UNSAFE' if filetype == 'html' else 'UNSAFE'
            reason = 'Unsafe file' if filetype == 'html' else 'Unsafe non-HTML file'
        else:
            status = 'SAFE'
            reason = 'No issues detected'
        result = {
            'file': file,
            'status': status,
            'reason': reason,
            'score': analysis['score'],
            'issues': analysis['issues'],
            'details': analysis['details'],
            'lines': analysis['lines'],
            'raw': raw,
        }
        summary.append(result)
    return summary

@app.route('/')
def home():
    """
    Home page.
    """
    summary = test_html_files_and_summary()
    return render_template('index.html', summary=summary)

@app.route('/v1/file/<path:pathfile>', methods=['GET'])
def serve_html_file(pathfile):
    """
    Serves an HTML file.
    """
    filename = unquote(pathfile)
    if is_file_blacklisted(filename) or is_path_blacklisted(filename):
        logger.warning(f"Access denied to blacklisted file or path: {filename}")
        return make_response('Access denied', 403)
    if not os.path.exists(filename):
        logger.warning(f"File not found: {filename}")
        return make_response('File not found', 404)
    if not secure_filename(os.path.basename(filename)):
        logger.warning(f"Insecure filename: {filename}")
        return make_response('Insecure filename', 400)
    if not filename.lower().endswith('.html'):
        logger.warning(f"Not an HTML file: {filename}")
        return make_response('Only HTML files are allowed', 415)
    with open(filename, encoding='utf-8', errors='replace') as f:
        html_content = f.read()
    score, issues, details = advanced_security_score_html(html_content)
    logger.info(f"Security score for {filename}: {score} (issues: {issues}, details: {details})")
    headers = {'Content-Type': 'text/html; charset=utf-8', 'X-Security-Score': str(score)}
    if issues:
        headers['X-Security-Issues'] = '; '.join(issues)
        headers['X-Security-Details'] = '; '.join(details)
    return Response(html_content, headers=headers)

if __name__ == '__main__':
    app.run(debug=True)
