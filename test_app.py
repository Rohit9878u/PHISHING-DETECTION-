import os
import io
import re
import qrcode
from PIL import Image
import app

def run_all_tests():
    print("==================================================")
    print("RUNNING SENTINEL AI PHISHING DETECTION TEST SUITE")
    print("==================================================")
    
    client = app.app.test_client()
    passed = 0
    total = 0

    def assert_test(condition, name, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name} - {details}")

    # --- TEST 1: GET / ---
    res = client.get('/')
    assert_test(res.status_code == 200, "GET / returns 200 OK")
    html = res.data.decode('utf-8')
    assert_test("Intelligent" in html and "Phishing Detection" in html and "System" in html,
                "Home page contains Intelligent Phishing Detection System heading")
    assert_test("style.css" in html, "Home page references style.css")
    assert_test("script.js" in html, "Home page references script.js")
    assert_test("chart.umd.min.js" in html, "Home page references Chart.js CDN")
    assert_test('id="dashboardHeroTitle"' in html, "Dashboard renders the threat intelligence hero")
    assert_test('class="nav-item active" id="navDashboard"' in html
                and 'class="pane-view active" id="paneDashboard"' in html,
                "Dashboard is the default landing view")
    assert_test('data-pane-shortcut="navUrlScanner"' in html
                and 'data-pane-shortcut="navEmailScanner"' in html,
                "Dashboard hero exposes URL and email scanner shortcuts")
    core_js = client.get('/static/js/script.js')
    assert_test(core_js.status_code == 200 and b'recordAnalyticsBatch' in core_js.data,
                "Static route serves the core script from the flat project layout")
    pulse_js = client.get('/static/js/security-pulse.js')
    assert_test(pulse_js.status_code == 200 and b'SecurityPulse' in pulse_js.data,
                "Static route serves the React Security Pulse widget")

    # --- TEST 2: POST / (Legacy Form Submission) ---
    res_form_safe = client.post('/', data={'url': 'https://google.com'})
    assert_test(res_form_safe.status_code == 200, "POST / with safe URL returns 200")
    safe_html = res_form_safe.data.decode('utf-8')
    assert_test("classified this URL as a healthy website" in safe_html,
                "POST / with safe URL renders healthy prediction message")

    res_form_phish = client.post('/', data={'url': 'http://secure-login-update-paypal.account-verify.info/login'})
    assert_test(res_form_phish.status_code == 200, "POST / with phishing URL returns 200")
    phish_html = res_form_phish.data.decode('utf-8')
    assert_test("classified this URL as a potential phishing website" in phish_html,
                "POST / with phishing URL renders Phishing prediction message")

    # --- TEST 3: POST /scan-url (AJAX JSON) ---
    # 3a: Legitimate URL
    res = client.post('/scan-url', json={'url': 'https://google.com'})
    assert_test(res.status_code == 200, "AJAX /scan-url with google.com returns 200")
    data = res.get_json()
    assert_test(data.get('verdict') == 'safe' and data.get('is_phishing') is False, "google.com classified as safe")
    assert_test(data.get('cleaned_url') == 'google.com', "google.com protocol stripped correctly")
    assert_test(data.get('confidence') is not None, "google.com returns model confidence percentage")

    # 3b: Legitimate URL (github.com)
    res = client.post('/scan-url', json={'url': 'https://github.com'})
    data = res.get_json()
    assert_test(data.get('verdict') == 'safe', "github.com classified as safe")

    # 3c: Phishing URL
    res = client.post('/scan-url', json={'url': 'http://secure-login-update-paypal.account-verify.info/login'})
    assert_test(res.status_code == 200, "AJAX /scan-url with phishing URL returns 200")
    data = res.get_json()
    assert_test(data.get('verdict') == 'phishing' and data.get('is_phishing') is True, "paypal phishing classified as phishing")
    assert_test(data.get('cleaned_url') == 'secure-login-update-paypal.account-verify.info/login', "phishing URL stripped properly")
    assert_test(data.get('prob_phishing') is not None, "phishing probability is returned")

    # 3d: Phishing URL 2
    res = client.post('/scan-url', json={'url': 'http://netflix-billing-update-center-auth.com'})
    data = res.get_json()
    assert_test(data.get('verdict') == 'phishing', "netflix phishing URL classified as phishing")

    # 3e: Protocol stripping equivalence check (HTTP vs HTTPS vs bare domain)
    r1 = app.classify_url('http://example.com/test')
    r2 = app.classify_url('https://example.com/test')
    r3 = app.classify_url('example.com/test')
    assert_test(r1['cleaned_url'] == r2['cleaned_url'] == r3['cleaned_url'] == 'example.com/test',
                "Protocol stripping regex strips http://, https://, and leaves bare domain identical")

    # 3f: Invalid URL
    res = client.post('/scan-url', json={'url': 'plain text not a domain'})
    assert_test(res.status_code == 400, "AJAX /scan-url with non-URL returns 400")

    # 3g: Empty input
    res = client.post('/scan-url', json={'url': ''})
    assert_test(res.status_code == 400, "AJAX /scan-url with empty URL returns 400")

    # --- TEST 3h: POST /scan-email (local email phishing screening) ---
    res_email_empty = client.post('/scan-email', json={'body': ''})
    assert_test(res_email_empty.status_code == 400,
                "POST /scan-email with empty message returns 400")

    res_email_phish = client.post('/scan-email', json={
        'body': 'Your account is suspended. Verify your password and OTP immediately at https://paypa1-login.xyz'
    })
    email_data = res_email_phish.get_json()
    assert_test(res_email_phish.status_code == 200 and email_data.get('status') == 'success',
                "POST /scan-email accepts a pasted email message")
    assert_test(email_data.get('risk_score', 0) >= 35 and email_data.get('verdict') in {'suspicious', 'fake'},
                "Suspicious message is flagged by email screening")
    assert_test(email_data.get('analysis_method') in {'rules_only', 'dataset_model_and_rules'},
                "Email scan reports which local analysis methods were used")

    # --- TEST 4: POST /scan-qr (QR Scanner) ---
    def make_qr_bytes(content, img_format='PNG'):
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format=img_format)
        buf.seek(0)
        return buf

    # 4a: QR code containing legitimate URL
    safe_qr_buf = make_qr_bytes('https://google.com')
    res = client.post('/scan-qr', data={'file': (safe_qr_buf, 'test_safe_qr.png')}, content_type='multipart/form-data')
    assert_test(res.status_code == 200, "POST /scan-qr with safe QR returns 200")
    data = res.get_json()
    assert_test(data.get('extracted_url') == 'https://google.com', "Extracted URL matches encoded QR")
    assert_test(data.get('verdict') == 'safe', "Extracted safe URL classified as safe")
    assert_test(data.get('scan_type') == 'qr', "Scan type marked as 'qr'")

    # 4b: QR code containing phishing URL
    phish_target = 'http://secure-login-update-paypal.account-verify.info/login'
    phish_qr_buf = make_qr_bytes(phish_target)
    res = client.post('/scan-qr', data={'file': (phish_qr_buf, 'test_phish_qr.png')}, content_type='multipart/form-data')
    assert_test(res.status_code == 200, "POST /scan-qr with phishing QR returns 200")
    data = res.get_json()
    assert_test(data.get('extracted_url') == phish_target, "Extracted phishing URL matches encoded QR")
    assert_test(data.get('verdict') == 'phishing', "Extracted phishing URL classified as phishing")

    # 4c: QR code containing plain text (non-URL)
    text_qr_buf = make_qr_bytes('This is just plain text, not a website URL')
    res = client.post('/scan-qr', data={'file': (text_qr_buf, 'test_text_qr.png')}, content_type='multipart/form-data')
    assert_test(res.status_code == 422, "POST /scan-qr with plain text returns 422 Unprocessable Entity")
    data = res.get_json()
    assert_test(data.get('error_type') == 'not_a_url', "Plain text QR returns error_type 'not_a_url'")

    # 4d: Image without a QR code (blank white image)
    blank_img = Image.new('RGB', (200, 200), color='white')
    blank_buf = io.BytesIO()
    blank_img.save(blank_buf, format='PNG')
    blank_buf.seek(0)
    res = client.post('/scan-qr', data={'file': (blank_buf, 'blank.png')}, content_type='multipart/form-data')
    assert_test(res.status_code == 400, "POST /scan-qr with image without QR returns 400")

    # 4e: Corrupted image file
    corrupt_buf = io.BytesIO(b"this is corrupt binary not an image")
    res = client.post('/scan-qr', data={'file': (corrupt_buf, 'corrupt.png')}, content_type='multipart/form-data')
    assert_test(res.status_code == 400, "POST /scan-qr with corrupted image returns 400")

    # 4f: Unsupported image format
    unsupported_buf = io.BytesIO(b"dummy")
    res = client.post('/scan-qr', data={'file': (unsupported_buf, 'file.gif')}, content_type='multipart/form-data')
    assert_test(res.status_code == 400, "POST /scan-qr with unsupported format (.gif) returns 400")

    # 4g: Missing file
    res = client.post('/scan-qr', data={}, content_type='multipart/form-data')
    assert_test(res.status_code == 400, "POST /scan-qr with missing file returns 400")

    # 4h: WEBP format support
    webp_qr_buf = make_qr_bytes('https://google.com', img_format='WEBP')
    res = client.post('/scan-qr', data={'file': (webp_qr_buf, 'test.webp')}, content_type='multipart/form-data')
    assert_test(res.status_code == 200, "POST /scan-qr supports WEBP format")

    # --- TEST 5: ML Pipeline Integrity Check ---
    assert_test(type(app.vector).__name__ == 'CountVectorizer', "CountVectorizer is intact")
    assert_test(type(app.model).__name__ == 'LogisticRegression', "LogisticRegression model is intact")
    assert_test(list(app.model.classes_) == ['bad', 'good'], "Class labels are ['bad', 'good']")

    # Check identical prediction between manual URL call and QR extracted URL call
    test_sample = "http://phishing-account-alert-update.com/login"
    qr_buf = make_qr_bytes(test_sample)
    qr_res = client.post('/scan-qr', data={'file': (qr_buf, 'qr.png')}, content_type='multipart/form-data').get_json()
    url_res = client.post('/scan-url', json={'url': test_sample}).get_json()
    assert_test(qr_res['verdict'] == url_res['verdict'] and qr_res['confidence'] == url_res['confidence'],
                "QR scanning and manual URL scanning yield identical prediction & confidence")

    # --- TEST 6: Typosquatting & Brand Spoofing Detection (Image 1 & 2 Request) ---
    res_go0ogle = client.post('/scan-url', json={'url': 'https://go0ogle.com'}).get_json()
    assert_test(res_go0ogle.get('verdict') == 'phishing' and res_go0ogle.get('is_phishing') is True,
                "https://go0ogle.com correctly flagged as phishing")
    assert_test(res_go0ogle.get('target_brand') == 'Google',
                "https://go0ogle.com target brand identified as Google")

    res_www_go0ogle = client.post('/scan-url', json={'url': 'http://www.go0ogle.com/'}).get_json()
    assert_test(res_www_go0ogle.get('verdict') == 'phishing',
                "http://www.go0ogle.com/ correctly flagged as phishing")

    res_paypa1 = client.post('/scan-url', json={'url': 'https://paypa1.com'}).get_json()
    assert_test(res_paypa1.get('verdict') == 'phishing' and res_paypa1.get('target_brand') == 'PayPal',
                "https://paypa1.com correctly flagged as PayPal typosquatting")

    res_amaz0n = client.post('/scan-url', json={'url': 'https://amaz0n.com'}).get_json()
    assert_test(res_amaz0n.get('verdict') == 'phishing' and res_amaz0n.get('target_brand') == 'Amazon',
                "https://amaz0n.com correctly flagged as Amazon typosquatting")

    # Verify legitimate google.com is not falsely flagged
    res_google = client.post('/scan-url', json={'url': 'https://google.com'}).get_json()
    assert_test(res_google.get('verdict') == 'safe',
                "Legitimate google.com correctly classified as safe")

    # --- TEST 7: CheckPhish Typosquat Dashboard API ---
    res_typo = client.get('/api/typosquats?domain=linkedin.com').get_json()
    assert_test(res_typo.get('status') == 'success' and res_typo.get('domain') == 'linkedin.com',
                "/api/typosquats returns success for linkedin.com")
    assert_test(len(res_typo.get('results', [])) > 0,
                "/api/typosquats returns populated results matching screenshot")
    first_item = res_typo['results'][0]
    assert_test('source_url' in first_item and 'construction' in first_item and 'risk' in first_item and 'verdict' in first_item,
                "Typosquat records contain all table columns (source_url, construction, risk, verdict)")

    # --- TEST 8: RAG Threat Intelligence & Copilot Engine ---
    # 8a: Knowledge Base Loading & Integrity
    kb_overview = app.rag_engine.get_knowledge_base_overview()
    assert_test(kb_overview.get('total_documents', 0) >= 15,
                f"RAG Knowledge Base contains {kb_overview.get('total_documents')} documents (>= 15 required)")
    assert_test('attack_technique' in kb_overview.get('categories', {}) and 'evasion_tactic' in kb_overview.get('categories', {}),
                "Knowledge Base contains structured cybersecurity categories")

    # 8b: Semantic Vector Retrieval (EvilProxy / Reverse Proxy)
    aitm_results = app.rag_engine.search_threat_intel("EvilProxy reverse proxy session cookies", top_k=2)
    assert_test(len(aitm_results) > 0, "RAG semantic search returned results for EvilProxy")
    aitm_ids = [r['id'] for r in aitm_results]
    assert_test('reverse-proxy-phishing-kits' in aitm_ids or 'mitre-t1556' in aitm_ids,
                "Semantic search correctly retrieved EvilProxy or MITRE T1556 documents")

    # 8c: Semantic Vector Retrieval (Quishing / QR code phishing)
    quish_results = app.rag_engine.search_threat_intel("Quishing QR code scanner email gateway bypass", top_k=2)
    assert_test(len(quish_results) > 0 and 'quishing-evasion' in [r['id'] for r in quish_results],
                "Semantic search correctly retrieved quishing-evasion document")

    # 8d: POST /api/rag/ask (Interactive Copilot Q&A)
    res_rag_ask = client.post('/api/rag/ask', json={'message': 'What is typosquatting and combosquatting?'})
    assert_test(res_rag_ask.status_code == 200, "POST /api/rag/ask returns 200 OK")
    ask_data = res_rag_ask.get_json()
    assert_test(ask_data.get('status') == 'success', "POST /api/rag/ask status is success")
    assert_test(len(ask_data.get('answer', '')) > 50, "POST /api/rag/ask generated comprehensive answer")
    assert_test(len(ask_data.get('citations', [])) > 0, "POST /api/rag/ask includes threat knowledge citations")
    assert_test(len(ask_data.get('suggested_questions', [])) > 0, "POST /api/rag/ask includes follow-up suggestions")

    # 8d-1: Incident-response questions must retrieve the incident-response playbook
    res_ir_clicked = client.post('/api/rag/ask', json={'message': 'I clicked a malicious link but did not enter credentials.'})
    ir_clicked = res_ir_clicked.get_json()
    assert_test(res_ir_clicked.status_code == 200, "POST /api/rag/ask handles malicious-link incidents")
    assert_test(ir_clicked.get('status') == 'success', "Malicious-link incident response status is success")
    assert_test(any(c.get('id') == 'ir-link-clicked' for c in ir_clicked.get('citations', [])),
                "Malicious-link query retrieves the link-clicked incident playbook")

    res_ir_credentials = client.post('/api/rag/ask', json={'message': 'I entered my password on a phishing website.'})
    ir_credentials = res_ir_credentials.get_json()
    assert_test(ir_credentials.get('citations', [{}])[0].get('id') == 'ir-credentials-submitted',
                "Credential-submission query retrieves the credentials-submitted incident playbook")

    res_takedown = client.post('/api/rag/ask', json={'message': 'How do I report and take down a phishing domain?'})
    takedown = res_takedown.get_json()
    assert_test(any(c.get('id') == 'takedown-procedure' for c in takedown.get('citations', [])),
                "Takedown query retrieves the domain abuse reporting workflow")

    # 8e: POST /api/rag/ask validation (empty query)
    res_rag_empty = client.post('/api/rag/ask', json={'message': ''})
    assert_test(res_rag_empty.status_code == 400, "POST /api/rag/ask with empty query returns 400")

    # 8f: POST /api/rag/explain (URL Threat Dossier)
    res_explain = client.post('/api/rag/explain', json={'url': 'https://go0ogle.com'})
    assert_test(res_explain.status_code == 200, "POST /api/rag/explain returns 200 OK")
    exp_data = res_explain.get_json()
    assert_test(exp_data.get('status') == 'success', "POST /api/rag/explain status is success")
    dossier = exp_data.get('dossier', {})
    assert_test('executive_summary' in dossier and 'attack_mechanism' in dossier,
                "RAG Dossier contains executive_summary and attack_mechanism")
    assert_test(len(dossier.get('mitre_techniques', [])) > 0, "RAG Dossier identifies MITRE ATT&CK techniques")
    assert_test(len(dossier.get('action_steps', [])) > 0, "RAG Dossier includes actionable incident playbook steps")
    assert_test(len(dossier.get('citations', [])) > 0, "RAG Dossier includes verified source citations")

    # 8g: POST /api/rag/overview & /api/rag/sources
    res_overview = client.get('/api/rag/overview')
    res_sources = client.get('/api/rag/sources')
    assert_test(res_overview.status_code == 200 and res_sources.status_code == 200,
                "GET /api/rag/overview and /api/rag/sources return 200 OK")
    overview_data = res_overview.get_json()
    assert_test('knowledge_base' in overview_data, "RAG overview contains knowledge_base telemetry")

    # 8h: Integrated /scan-url RAG enrichment check
    scan_res = client.post('/scan-url', json={'url': 'https://go0ogle.com'}).get_json()
    assert_test('rag_analysis' in scan_res, "/scan-url response enriched with rag_analysis")
    assert_test(scan_res['rag_analysis'].get('executive_summary') is not None,
                "/scan-url rag_analysis contains executive_summary")

    # 8i: Integrated /scan-qr RAG enrichment check
    qr_buf = make_qr_bytes('https://go0ogle.com')
    qr_scan_res = client.post('/scan-qr', data={'file': (qr_buf, 'test_rag_qr.png')}, content_type='multipart/form-data').get_json()
    assert_test('rag_analysis' in qr_scan_res, "/scan-qr response enriched with rag_analysis")

    print("==================================================")
    print(f"TEST RESULTS: {passed} / {total} TESTS PASSED ({round(passed/total*100, 1)}%)")
    print("==================================================")
    return passed == total

if __name__ == '__main__':
    success = run_all_tests()
    exit(0 if success else 1)
