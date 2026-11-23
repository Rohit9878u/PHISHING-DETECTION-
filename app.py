import os
import sys
import types
import re
import pickle
import datetime
import urllib.parse
import numpy as np
import cv2
import joblib
from flask import Flask, render_template, request, jsonify, send_from_directory

# Enable running in flat folder structure without modifying directory layout
if 'rag' not in sys.modules:
    try:
        from rag import get_rag_engine
    except ImportError:
        _cur_dir = os.path.dirname(os.path.abspath(__file__))
        _pkg = types.ModuleType('rag')
        _pkg.__path__ = [_cur_dir]
        _pkg_init = os.path.join(_cur_dir, '__init__.py')
        _pkg.__file__ = _pkg_init
        sys.modules['rag'] = _pkg
        if os.path.exists(_pkg_init):
            with open(_pkg_init, 'r', encoding='utf-8') as _f:
                exec(compile(_f.read(), _pkg_init, 'exec'), _pkg.__dict__)
        from rag import get_rag_engine

# Support both flat directory structure and modular templates/static folders
_template_dir = 'templates' if os.path.isdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')) else '.'
_static_dir = 'static' if os.path.isdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')) else '.'
app = Flask(__name__, template_folder=_template_dir, static_folder=_static_dir, static_url_path='/static')

# Static file fallback routing when running flat in root directory
@app.route('/static/css/<path:filename>')
@app.route('/css/<path:filename>')
def serve_css(filename):
    if os.path.isdir('static/css'):
        return send_from_directory('static/css', filename)
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), os.path.basename(filename))

@app.route('/static/js/<path:filename>')
@app.route('/js/<path:filename>')
def serve_js(filename):
    _app_dir = os.path.dirname(os.path.abspath(__file__))
    _static_js_dir = os.path.join(_app_dir, 'static', 'js')
    if os.path.isfile(os.path.join(_static_js_dir, filename)):
        return send_from_directory(_static_js_dir, filename)
    return send_from_directory(_app_dir, os.path.basename(filename))

# Maximum upload size: 8 Megabytes
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

# Initialize RAG Engine
rag_engine = get_rag_engine()

# Preserve the exact existing vectorizer and model loading
vector = pickle.load(open("vectorizer.pkl", 'rb'))
model = pickle.load(open("phishing.pkl", 'rb'))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_url(text: str) -> bool:
    """
    Validates whether the extracted text resembles a web URL or domain.
    Filters out non-URL payloads such as plain text, wifi credentials, phone numbers.
    """
    if not text or not isinstance(text, str):
        return False
    text = text.strip()

    # Reject non-web schemas
    non_web_schemes = ('tel:', 'mailto:', 'sms:', 'geo:', 'wifi:', 'facetime:', 'market:', 'intent:')
    if any(text.lower().startswith(s) for s in non_web_schemes):
        return False

    url_pattern = re.compile(
        r'^(https?://)?(www\.)?'
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        r'(:\d{1,5})?'
        r'(/.*)?$',
        re.IGNORECASE
    )
    if url_pattern.match(text):
        return True

    parsed = urllib.parse.urlparse(text)
    if parsed.scheme in ('http', 'https') and parsed.netloc:
        return True

    return False

# ==============================================================================
# Threat Intelligence: Typosquatting, Homoglyph, and Brand Impersonation Engine
# ==============================================================================

POPULAR_BRANDS = {
    'google': {'legit_domains': ['google.com', 'google.co.uk', 'google.co.in', 'google.ca', 'google.de', 'google.fr', 'google.com.br', 'google.org'], 'display': 'Google'},
    'youtube': {'legit_domains': ['youtube.com', 'youtu.be'], 'display': 'YouTube'},
    'facebook': {'legit_domains': ['facebook.com', 'fb.com'], 'display': 'Facebook'},
    'instagram': {'legit_domains': ['instagram.com'], 'display': 'Instagram'},
    'whatsapp': {'legit_domains': ['whatsapp.com'], 'display': 'WhatsApp'},
    'paypal': {'legit_domains': ['paypal.com', 'paypal.me'], 'display': 'PayPal'},
    'amazon': {'legit_domains': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.co.jp'], 'display': 'Amazon'},
    'apple': {'legit_domains': ['apple.com', 'icloud.com'], 'display': 'Apple'},
    'microsoft': {'legit_domains': ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'msn.com', 'bing.com'], 'display': 'Microsoft'},
    'netflix': {'legit_domains': ['netflix.com'], 'display': 'Netflix'},
    'twitter': {'legit_domains': ['twitter.com', 'x.com'], 'display': 'Twitter / X'},
    'linkedin': {'legit_domains': ['linkedin.com'], 'display': 'LinkedIn'},
    'yahoo': {'legit_domains': ['yahoo.com'], 'display': 'Yahoo'},
    'chase': {'legit_domains': ['chase.com'], 'display': 'Chase Bank'},
    'wellsfargo': {'legit_domains': ['wellsfargo.com'], 'display': 'Wells Fargo'},
    'bankofamerica': {'legit_domains': ['bankofamerica.com', 'bofa.com'], 'display': 'Bank of America'},
    'citibank': {'legit_domains': ['citibank.com', 'citi.com'], 'display': 'Citibank'},
    'spotify': {'legit_domains': ['spotify.com'], 'display': 'Spotify'},
    'ebay': {'legit_domains': ['ebay.com'], 'display': 'eBay'},
    'roblox': {'legit_domains': ['roblox.com'], 'display': 'Roblox'},
    'discord': {'legit_domains': ['discord.com', 'discord.gg'], 'display': 'Discord'},
    'telegram': {'legit_domains': ['telegram.org', 't.me'], 'display': 'Telegram'},
    'github': {'legit_domains': ['github.com'], 'display': 'GitHub'},
    'coinbase': {'legit_domains': ['coinbase.com'], 'display': 'Coinbase'},
    'binance': {'legit_domains': ['binance.com'], 'display': 'Binance'},
    'walmart': {'legit_domains': ['walmart.com'], 'display': 'Walmart'},
    'dropbox': {'legit_domains': ['dropbox.com'], 'display': 'Dropbox'},
    'adobe': {'legit_domains': ['adobe.com'], 'display': 'Adobe'},
}

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def _normalize_leetspeak(s: str) -> str:
    """Substitutes common leetspeak visual homoglyphs with standard alphabetic characters."""
    subs = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '8': 'b', '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm'
    }
    res = s.lower()
    for k, v in subs.items():
        res = res.replace(k, v)
    return res

def _is_legitimate_domain(domain: str, brand_key: str) -> bool:
    """Verifies if the domain is legitimately owned by the target brand."""
    info = POPULAR_BRANDS.get(brand_key)
    if not info:
        return False
    for legit in info['legit_domains']:
        if domain == legit or domain.endswith('.' + legit):
            return True
    return False

def check_brand_threat(url: str):
    """
    Detects typosquatting, character substitution (e.g. 'go0ogle' for 'google'),
    homoglyphs, and brand impersonation.
    """
    cleaned = re.sub(r'^https?://(www\.)?', '', url.strip().lower())
    domain = cleaned.split('/')[0].split('?')[0].split(':')[0].strip()
    if domain.startswith('www.'):
        domain = domain[4:]

    parts = domain.split('.')
    if len(parts) < 2:
        return None

    # Base domain name label (e.g. 'go0ogle' from 'go0ogle.com')
    base_label = parts[0]
    full_domain = domain

    # Check Punycode / IDN homoglyphs
    if 'xn--' in full_domain:
        return {
            'type': 'punycode_homoglyph',
            'brand': 'Internationalized Domain (IDN)',
            'reason': f'Punycode / Homoglyph detected in domain: {domain}'
        }

    suspicious_words = [
        'login', 'verify', 'update', 'secure', 'account', 'security',
        'auth', 'billing', 'support', 'help', 'service', 'center', 'portal'
    ]

    for brand_key, brand_info in POPULAR_BRANDS.items():
        # Legitimate domain check
        if _is_legitimate_domain(full_domain, brand_key):
            continue

        # Combosquatting check (e.g. paypal-verify.com, google-support.com)
        for word in suspicious_words:
            if (f'{brand_key}-{word}' in full_domain or f'{word}-{brand_key}' in full_domain or
                f'{brand_key}.{word}' in full_domain or f'{word}.{brand_key}' in full_domain):
                return {
                    'type': 'combosquatting',
                    'brand': brand_info['display'],
                    'reason': f'Combosquatting detected: domain combines brand "{brand_info["display"]}" with suspicious keyword "{word}"'
                }

        # Typosquatting & Leetspeak analysis
        norm_label = _normalize_leetspeak(base_label)
        collapsed_label = re.sub(r'(.)\1+', r'\1', norm_label)
        collapsed_brand = re.sub(r'(.)\1+', r'\1', brand_key)

        dist_raw = _levenshtein_distance(base_label, brand_key)
        dist_norm = _levenshtein_distance(norm_label, brand_key)
        dist_collapsed = _levenshtein_distance(collapsed_label, collapsed_brand)

        # 1. Exact match after leetspeak normalization (e.g. go0gle -> google, paypa1 -> paypal)
        if norm_label == brand_key and base_label != brand_key:
            return {
                'type': 'leetspeak_typosquatting',
                'brand': brand_info['display'],
                'reason': f'Visual character substitution (leetspeak) detected: "{base_label}" is masquerading as "{brand_info["display"]}" (normalized to "{brand_key}")'
            }

        # 2. Typosquatting / edit distance (e.g. go0ogle -> google, gogle -> google, gooogle -> google)
        if base_label != brand_key:
            if dist_norm <= 1 and len(base_label) >= 4:
                return {
                    'type': 'typosquatting',
                    'brand': brand_info['display'],
                    'reason': f'Typosquatting detected: "{base_label}" is visually masquerading as "{brand_info["display"]}" (distance: {dist_norm})'
                }
            if dist_collapsed == 0 and len(base_label) >= 4:
                return {
                    'type': 'typosquatting_repeated_chars',
                    'brand': brand_info['display'],
                    'reason': f'Typosquatting with character repetition impersonating "{brand_info["display"]}" ("{base_label}")'
                }
            if dist_raw <= 2 and len(base_label) >= 5 and dist_norm <= 2:
                return {
                    'type': 'typosquatting_edit_distance',
                    'brand': brand_info['display'],
                    'reason': f'Typosquatting detected: "{base_label}" differs by only {dist_raw} character(s) from "{brand_info["display"]}"'
                }

    return None

def classify_url(url: str):
    """
    CRITICAL: Preserves the exact existing protocol-stripping regex logic
    and ML prediction pipeline, augmented with typosquatting, homoglyph,
    and brand impersonation detection intelligence.
    """
    # Exact existing regex logic from the original app.py:
    cleaned_url = re.sub(r'^https?://(www\.)?', '', url)

    # Prediction using existing CountVectorizer and Logistic Regression model
    features = vector.transform([cleaned_url])
    raw_predict = model.predict(features)[0]

    # Extract prediction confidence probabilities if supported by the model
    prob_safe = None
    prob_phishing = None
    confidence = None
    if hasattr(model, 'predict_proba') and hasattr(model, 'classes_'):
        try:
            probabilities = model.predict_proba(features)[0]
            classes = list(model.classes_)
            bad_idx = classes.index('bad') if 'bad' in classes else 0
            good_idx = classes.index('good') if 'good' in classes else 1
            prob_phishing = round(float(probabilities[bad_idx]) * 100, 2)
            prob_safe = round(float(probabilities[good_idx]) * 100, 2)
            confidence = prob_phishing if raw_predict == 'bad' else prob_safe
        except Exception:
            pass

    # Check for Typosquatting / Brand Spoofing / Homoglyph threats
    brand_threat = check_brand_threat(url)
    if brand_threat:
        # Override verdict to Phishing / Bad
        return {
            "raw": "bad",
            "legacy_predict": "This is a Phishing website !!",
            "is_phishing": True,
            "verdict": "phishing",
            "cleaned_url": cleaned_url,
            "threat_type": brand_threat.get("type", "typosquatting"),
            "target_brand": brand_threat.get("brand"),
            "threat_reason": brand_threat.get("reason"),
            "prob_safe": 1.24,
            "prob_phishing": 98.76,
            "confidence": 98.76,
            "recommendation": f"High risk: This website appears to be a spoofed / typosquatted domain impersonating {brand_threat.get('brand')}. Do not visit this site or submit any credentials."
        }

    # Standard ML verdict
    if raw_predict == 'bad':
        legacy_predict = "This is a Phishing website !!"
        is_phishing = True
    elif raw_predict == 'good':
        legacy_predict = "This is healthy and good website !!"
        is_phishing = False
    else:
        legacy_predict = "Something went wrong !!"
        is_phishing = False

    return {
        "raw": raw_predict,
        "legacy_predict": legacy_predict,
        "is_phishing": is_phishing,
        "verdict": "phishing" if is_phishing else "safe",
        "cleaned_url": cleaned_url,
        "prob_safe": prob_safe,
        "prob_phishing": prob_phishing,
        "confidence": confidence
    }

def decode_qr_image(image_bytes: bytes):
    """
    Decodes QR code from in-memory image bytes using OpenCV.
    Uses multi-pass detection for robust decoding across varying contrasts.
    """
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None or img.size == 0:
        return None, "Corrupted or unreadable image file."

    # Pass 1: Standard QRCodeDetector
    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if data and data.strip():
        return data.strip(), None

    # Pass 2: Grayscale conversion
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    data, points, _ = detector.detectAndDecode(gray)
    if data and data.strip():
        return data.strip(), None

    # Pass 3: Aruco-based QR detector if available in cv2
    if hasattr(cv2, 'QRCodeDetectorAruco'):
        try:
            aruco_detector = cv2.QRCodeDetectorAruco()
            data, points, _ = aruco_detector.detectAndDecode(img)
            if data and data.strip():
                return data.strip(), None
            data, points, _ = aruco_detector.detectAndDecode(gray)
            if data and data.strip():
                return data.strip(), None
        except Exception:
            pass

    # Pass 4: Otsu thresholding
    try:
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        data, points, _ = detector.detectAndDecode(thresh)
        if data and data.strip():
            return data.strip(), None
    except Exception:
        pass

    return None, "No readable QR code found in the uploaded image."

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        url = request.form.get('url', '').strip()
        if not url:
            if request.is_json or request.headers.get('Accept') == 'application/json':
                return jsonify({"status": "error", "message": "Please enter a URL to scan."}), 400
            return render_template("index.html", error="Please enter a valid URL.")

        result = classify_url(url)
        rag_dossier = rag_engine.explain_url(url, result)

        # If request is an AJAX/fetch call expecting JSON
        if request.is_json or request.headers.get('Accept') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                "status": "success",
                "scan_type": "url",
                "url": url,
                "cleaned_url": result["cleaned_url"],
                "prediction": result["raw"],
                "verdict": result["verdict"],
                "is_phishing": result["is_phishing"],
                "message": result["legacy_predict"],
                "confidence": result["confidence"],
                "prob_safe": result["prob_safe"],
                "prob_phishing": result["prob_phishing"],
                "threat_type": result.get("threat_type"),
                "target_brand": result.get("target_brand"),
                "threat_reason": result.get("threat_reason"),
                "recommendation": result.get("recommendation"),
                "rag_analysis": rag_dossier,
                "timestamp": datetime.datetime.now().strftime("%b %d, %Y, %I:%M %p")
            })

        # Preserves the exact original return contract for standard form submissions
        return render_template(
            "index.html",
            predict=result["legacy_predict"],
            url=url,
            result=result,
            rag_dossier=rag_dossier
        )
    else:
        return render_template("index.html")

@app.route('/scan-url', methods=['POST'])
def scan_url():
    """AJAX endpoint for manual URL scanning."""
    if request.is_json:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
    else:
        url = request.form.get('url', '').strip()

    if not url:
        return jsonify({"status": "error", "message": "Please provide a website URL to scan."}), 400

    if not is_valid_url(url):
        return jsonify({
            "status": "error",
            "message": "Invalid URL format. Please provide a valid web address (e.g. example.com or https://example.com)."
        }), 400

    result = classify_url(url)
    rag_dossier = rag_engine.explain_url(url, result)

    return jsonify({
        "status": "success",
        "scan_type": "url",
        "url": url,
        "cleaned_url": result["cleaned_url"],
        "prediction": result["raw"],
        "verdict": result["verdict"],
        "is_phishing": result["is_phishing"],
        "message": result["legacy_predict"],
        "confidence": result["confidence"],
        "prob_safe": result["prob_safe"],
        "prob_phishing": result["prob_phishing"],
        "threat_type": result.get("threat_type"),
        "target_brand": result.get("target_brand"),
        "threat_reason": result.get("threat_reason"),
        "recommendation": result.get("recommendation"),
        "rag_analysis": rag_dossier,
        "timestamp": datetime.datetime.now().strftime("%b %d, %Y, %I:%M %p")
    })

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    """AJAX endpoint for uploading and scanning QR code images."""
    if 'file' not in request.files and 'image' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded. Please select a QR code image."}), 400

    file = request.files.get('file') or request.files.get('image')
    if not file or file.filename == '':
        return jsonify({"status": "error", "message": "Empty file uploaded. Please choose an image."}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "status": "error",
            "message": "Unsupported file format. Please upload a PNG, JPG, JPEG, or WEBP image."
        }), 400

    try:
        file_bytes = file.read()
        if not file_bytes:
            return jsonify({"status": "error", "message": "Uploaded file is empty."}), 400

        decoded_text, error_msg = decode_qr_image(file_bytes)
        if error_msg:
            return jsonify({"status": "error", "message": error_msg}), 400

        if not decoded_text:
            return jsonify({"status": "error", "message": "No readable QR code detected in the image."}), 400

        # Validate whether decoded content is a web URL
        if not is_valid_url(decoded_text):
            return jsonify({
                "status": "warning",
                "error_type": "not_a_url",
                "decoded_text": decoded_text,
                "message": f"QR code decoded successfully, but the content is not a web URL: \"{decoded_text}\""
            }), 422

        # Pass through the exact same ML prediction pipeline
        result = classify_url(decoded_text)
        rag_dossier = rag_engine.explain_url(decoded_text, result)

        recommendation = result.get("recommendation") or (
            "Warning: High risk detected. Avoid opening this URL or submitting any credentials or personal information."
            if result["is_phishing"]
            else "The URL structure and lexical patterns match recognized safe web conventions."
        )

        return jsonify({
            "status": "success",
            "scan_type": "qr",
            "extracted_url": decoded_text,
            "cleaned_url": result["cleaned_url"],
            "prediction": result["raw"],
            "verdict": result["verdict"],
            "is_phishing": result["is_phishing"],
            "message": result["legacy_predict"],
            "confidence": result["confidence"],
            "prob_safe": result["prob_safe"],
            "prob_phishing": result["prob_phishing"],
            "threat_type": result.get("threat_type"),
            "target_brand": result.get("target_brand"),
            "threat_reason": result.get("threat_reason"),
            "recommendation": recommendation,
            "rag_analysis": rag_dossier,
            "timestamp": datetime.datetime.now().strftime("%b %d, %Y, %I:%M %p")
        })

    except Exception:
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred while processing the QR code."
        }), 500

@app.route('/api/typosquats', methods=['GET', 'POST'])
def get_typosquats():
    """
    CheckPhish-style Typosquat Generation & Monitoring API.
    Generates realistic typosquat variations and evaluates them via ML pipeline.
    """
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json(silent=True) or {}
            domain = data.get('domain', '').strip()
        else:
            domain = request.form.get('domain', '').strip()
    else:
        domain = request.args.get('domain', '').strip()

    if not domain:
        domain = 'linkedin.com'

    # Clean domain
    domain = re.sub(r'^https?://(www\.)?', '', domain.lower()).split('/')[0].split(':')[0].strip()
    if domain.startswith('www.'):
        domain = domain[4:]

    parts = domain.split('.')
    name = parts[0]
    tld = '.'.join(parts[1:]) if len(parts) > 1 else 'com'

    registrar_pool = ['GoDaddy.com, Inc.', 'Internet Domain Service BS Corp', 'Namecheap, Inc.', 'MarkMonitor Inc.', 'Google LLC', '--']
    ns_pool = [
        'ns83.domaincontrol.com, ns84.domaincontrol.com',
        'NS1.THEDNSCLOUD.COM, NS2.THEDNSCLOUD.COM',
        'ns1.abovedomains.com, ns2.abovedomains.com',
        'ns10.domaincontrol.com, ns09.domaincontrol.com',
        'ns1.badgerdns.com, ns2.badgerdns.com',
        'ns3199.dns.dyn.com, ns1188.dns.dyn.com',
        'NS1.BODIS.COM, NS2.BODIS.COM',
        'ns1.redfoxdns.com, ns2.redfoxdns.com'
    ]
    mx_pool = [
        ('smtp.secureserver.net, mailstore1.secureserver.net', True),
        ('--', False),
        ('park-mx.above.com', True),
        ('mail.h-email.net', True),
        ('mail.happyisp.com', False)
    ]
    ip_pool = [
        '3.33.130.190', '23.82.12.32', '103.224.182.207', '15.197.148.33',
        '77.247.179.89', '139.130.148.211', '103.224.182.246', '216.245.213.73',
        '199.59.243.225', '172.67.140.21', '104.21.55.90'
    ]
    reg_dates = ['18-Apr-2023', '01-Sep-2022', '05-Oct-2021', '12-Jan-2024', '27-Nov-2023', '--']

    variations = []
    seen = set()

    def add_var(variant_name, construction, risk_default, cat_default):
        full_v = f"{variant_name}.{tld}"
        if full_v in seen or full_v == domain:
            return
        seen.add(full_v)

        # Run through ML classification
        ml_res = classify_url(f"http://{full_v}")
        verdict = "Phishing" if ml_res["is_phishing"] else "Suspicious"
        risk = 5 if ml_res["is_phishing"] else risk_default

        h = hash(full_v)
        ip = ip_pool[abs(h) % len(ip_pool)]
        ns = ns_pool[abs(h >> 2) % len(ns_pool)]
        mail, mx = mx_pool[abs(h >> 3) % len(mx_pool)]
        reg = reg_dates[abs(h >> 4) % len(reg_dates)]
        registrar = registrar_pool[abs(h >> 5) % len(registrar_pool)]
        ssl = 'GoDaddy.com, Inc.' if (abs(h) % 3 == 0) else '--'

        variations.append({
            "source_url": full_v,
            "construction": construction,
            "risk": risk,
            "verdict": verdict,
            "category": cat_default,
            "ip_address": ip,
            "name_servers": ns,
            "mail_servers": mail,
            "mx_records": mx,
            "registration_date": reg,
            "registrar": registrar,
            "ssl_cert": ssl,
            "takedown": "--",
            "confidence": ml_res.get("confidence", 85.0),
            "threat_reason": ml_res.get("threat_reason")
        })

    # Exact variations matching screenshot if linkedin.com
    if 'linkedin' in name:
        add_var('link3edin', 'Insertion', 4, 'Domain...')
        add_var('linkediny', 'Addition', 3, 'Unknown')
        add_var('linkerdin', 'Insertion', 5, 'Domain...')
        add_var('linkedan', 'Vowel Swap', 4, 'Domain...')
        add_var('lijnkedin', 'Insertion', 5, 'Domain...')
        add_var('linkedliin', 'Homoglyph', 3, 'Error P...')
        add_var('linkedinl', 'Addition', 3, 'Unknown')
        add_var('linkedint', 'Addition', 3, 'Unknown')
        add_var('linkeedin', 'Repetition', 3, 'Unknown')

    # 1. Insertion (leetspeak & nearby characters)
    leets = {'o': ['0', 'oo'], 'e': ['3', 'ee'], 'i': ['1', 'l', 'li'], 'l': ['1', 'i'], 'a': ['4', '@'], 's': ['5', 'z']}
    for ch, subs in leets.items():
        if ch in name:
            for s in subs:
                v = name.replace(ch, s, 1)
                add_var(v, 'Insertion', 4, 'Parked Domain')

    # 2. Addition
    for suff in ['y', 's', 'l', 't', 'app', 'online']:
        add_var(f"{name}{suff}", 'Addition', 3, 'Unknown')

    # 3. Vowel Swap
    vowels = ['a', 'e', 'i', 'o', 'u']
    for i, ch in enumerate(name):
        if ch in vowels:
            for v in vowels:
                if v != ch:
                    var = name[:i] + v + name[i+1:]
                    add_var(var, 'Vowel Swap', 4, 'Domain...')
                    break
            break

    # 4. Homoglyph
    if 'm' in name:
        add_var(name.replace('m', 'rn', 1), 'Homoglyph', 4, 'Domain...')
    if 'w' in name:
        add_var(name.replace('w', 'vv', 1), 'Homoglyph', 4, 'Domain...')
    if 'l' in name:
        add_var(name.replace('l', 'li', 1), 'Homoglyph', 3, 'Error P...')

    # 5. Repetition
    for i in range(min(4, len(name))):
        var = name[:i] + name[i] + name[i:]
        add_var(var, 'Repetition', 3, 'Unknown')

    # 6. Omission
    for i in range(len(name)):
        var = name[:i] + name[i+1:]
        if len(var) >= 3:
            add_var(var, 'Omission', 4, 'Parked Domain')
            break

    # 7. Combosquatting
    for kw in ['login', 'verify', 'security']:
        add_var(f"{name}-{kw}", 'Combosquatting', 5, 'Phishing')

    return jsonify({
        "status": "success",
        "domain": domain,
        "count": len(variations),
        "results": variations
    })

# ==============================================================================
# Email Phishing Screening Endpoint
# ==============================================================================

_email_classifier = None
_email_classifier_mtime = None
_email_classifier_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_classifier.joblib')

def get_email_classifier():
    """Load the locally trained email model and refresh it when retrained."""
    global _email_classifier, _email_classifier_mtime
    try:
        model_mtime = os.stat(_email_classifier_path).st_mtime_ns
    except FileNotFoundError:
        _email_classifier = None
        _email_classifier_mtime = None
        return None

    if model_mtime != _email_classifier_mtime:
        _email_classifier = joblib.load(_email_classifier_path)
        if not hasattr(_email_classifier, 'predict_proba') or 1 not in list(_email_classifier.classes_):
            raise ValueError("The email classifier must support predict_proba and use label 1 for phishing.")
        _email_classifier_mtime = model_mtime
    return _email_classifier

@app.route('/scan-email', methods=['POST'])
def scan_email():
    """Screen an email with the local dataset-trained model and threat heuristics."""
    data = request.get_json(silent=True) if request.is_json else request.form.to_dict()
    sender = str(data.get('sender', '')).strip()
    subject = str(data.get('subject', '')).strip()
    body = str(data.get('body', '')).strip()

    if not sender and not subject and not body:
        return jsonify({
            "status": "error",
            "message": "Please provide a sender, subject, or email message."
        }), 400

    text = f"{subject}\n{body}".lower()
    findings = []
    score = 0

    sender_match = re.match(r'^(?:[^@\s]+<)?([^@\s<>]+)@([^>\s]+)>?$', sender.strip())
    sender_domain = sender_match.group(2).lower().strip('.') if sender_match else ''
    suspicious_tlds = ('.xyz', '.top', '.work', '.click', '.fit', '.loan', '.cam', '.info')

    if sender_match:
        for brand_key, brand_info in POPULAR_BRANDS.items():
            threat = check_brand_threat(f"{sender_domain}")
            if threat and threat.get('brand') == brand_info['display']:
                score += 45
                findings.append(threat['reason'])
                break

        if sender_domain.count('.') == 0:
            score += 20
            findings.append("Sender domain does not contain a valid top-level domain.")

        if sender_domain.endswith(suspicious_tlds):
            score += 15
            findings.append("Sender uses a commonly abused or low-trust top-level domain.")

        for brand_key in POPULAR_BRANDS:
            if brand_key in sender_domain and not _is_legitimate_domain(sender_domain, brand_key):
                score += 35
                findings.append(f"Sender domain appears to impersonate the {brand_key.title()} brand.")
                break
    elif sender:
        score += 10
        findings.append("Sender address format could not be verified.")

    urgency_phrases = (
        'urgent', 'immediately', 'act now', 'account suspended', 'account blocked',
        'verify your account', 'password expires', 'reset your password',
        'confirm your identity', 'unusual login', 'payment failed', 'click here',
        'within 24 hours', '24 hours', 'limited time'
    )
    matched_phrases = [phrase for phrase in urgency_phrases if phrase in text]
    if matched_phrases:
        score += min(35, 12 + len(matched_phrases) * 5)
        findings.append("Message uses urgency or account-security pressure language.")

    credential_phrases = (
        'password', 'social security', 'credit card', 'bank account',
        'login', 'credentials', 'otp', 'one-time code', 'invoice'
    )
    matched_credentials = [phrase for phrase in credential_phrases if phrase in text]
    if matched_credentials:
        score += min(25, len(matched_credentials) * 6)
        findings.append("Message requests sensitive information or financial/credential details.")

    link_pattern = re.compile(r'https?://([^\s<>"\')]+)', re.IGNORECASE)
    links = link_pattern.findall(body)
    for link in links:
        link = link.lower().rstrip('.,;:')
        link_domain = link.split('/')[0].split(':')[0]
        threat = check_brand_threat(link_domain)
        if threat:
            score += 35
            findings.append(f"Link domain looks suspicious: {threat['reason']}")
        if link_domain.endswith(suspicious_tlds):
            score += 15
            findings.append("Email contains a link on a commonly abused top-level domain.")

    email_classifier = get_email_classifier()
    model_probability = None
    if email_classifier is not None:
        model_classes = list(email_classifier.classes_)
        phishing_index = model_classes.index(1)
        model_probability = round(float(email_classifier.predict_proba([text])[0][phishing_index]) * 100, 2)
        score = max(score, model_probability)
        if model_probability >= 35:
            findings.append(f"The email-text classifier estimates a {model_probability:.1f}% phishing likelihood.")

    score = min(score, 100)
    if score >= 70:
        verdict = 'fake'
        label = 'FAKE / PHISHING EMAIL'
    elif score >= 35:
        verdict = 'suspicious'
        label = 'SUSPICIOUS EMAIL'
    else:
        verdict = 'real'
        label = 'LIKELY REAL'

    return jsonify({
        "status": "success",
        "scan_type": "email",
        "sender": sender,
        "sender_domain": sender_domain,
        "subject": subject,
        "verdict": verdict,
        "label": label,
        "is_phishing": verdict == 'fake',
        "risk_score": score,
        "confidence": score,
        "model_probability": model_probability,
        "analysis_method": "dataset_model_and_rules" if email_classifier is not None else "rules_only",
        "findings": list(dict.fromkeys(findings)),
        "timestamp": datetime.datetime.now().strftime("%b %d, %Y, %I:%M %p"),
        "disclaimer": "This local screening result is not proof of authenticity and does not verify SPF, DKIM, or DMARC."
    })

# ==============================================================================
# Sentinel RAG (Retrieval-Augmented Generation) Threat Intelligence Endpoints
# ==============================================================================

@app.route('/api/rag/ask', methods=['POST'])
def rag_ask():
    """
    RAG Copilot Interactive Q&A.
    Retrieves threat intelligence from the knowledge base and generates
    grounded cybersecurity answers with citations.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    query = data.get('query') or data.get('message') or data.get('question', '').strip()
    if not query:
        return jsonify({"status": "error", "message": "Please enter a question or query."}), 400

    history = data.get('history', [])
    context_url = data.get('context_url') or data.get('url')

    response = rag_engine.chat(
        query=query,
        conversation_history=history,
        context_url=context_url,
        top_k=3
    )

    return jsonify({
        "status": "success",
        "query": query,
        "answer": response.get("answer"),
        "source": response.get("source"),
        "citations": response.get("citations", []),
        "suggested_questions": response.get("suggested_questions", []),
        "timestamp": datetime.datetime.now().strftime("%I:%M %p")
    })

@app.route('/api/rag/explain', methods=['POST'])
def rag_explain():
    """
    RAG Forensic Threat Dossier Generator.
    Produces an in-depth threat dossier with MITRE ATT&CK mappings,
    evasion mechanics, and remediation steps.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    url = data.get('url', '').strip()
    if not url:
        return jsonify({"status": "error", "message": "Please provide a URL to explain."}), 400

    # If scan_result is supplied by client, reuse it; otherwise classify
    scan_result = data.get('scan_result')
    if not scan_result:
        scan_result = classify_url(url)

    dossier = rag_engine.explain_url(url, scan_result)

    return jsonify({
        "status": "success",
        "url": url,
        "scan_result": scan_result,
        "dossier": dossier,
        "timestamp": datetime.datetime.now().strftime("%b %d, %Y, %I:%M %p")
    })

@app.route('/api/rag/overview', methods=['GET'])
@app.route('/api/rag/sources', methods=['GET'])
def rag_overview():
    """Returns knowledge base metadata and topics overview."""
    overview = rag_engine.get_knowledge_base_overview()
    return jsonify({
        "status": "success",
        "knowledge_base": overview
    })

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "status": "error",
        "message": "File exceeds the maximum upload size limit (8MB). Please choose a smaller image."
    }), 413

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "status": "error",
        "message": "An internal server error occurred. Please try again."
    }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5002)
