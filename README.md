<<<<<<< HEAD
# 🛡️ Sentinel-AI | Next-Gen Phishing & Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-orange.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![OpenCV](https://img.shields.io/badge/OpenCV-4.9%2B-red.svg?logo=opencv&logoColor=white)](https://opencv.org/)
[![Tests](https://img.shields.io/badge/Tests-71%20Passed%20(100%25)-brightgreen.svg)](#-automated-testing)
[![RAG](https://img.shields.io/badge/RAG-Hybrid%20Vector%20%2B%20Forensic%20Synthesizer-purple.svg)](#-5-rag-retrieval-augmented-generation-threat-intelligence--copilot-engine)
[![Theme](https://img.shields.io/badge/Theme-Light%20%7C%20Dark%20Mode-9333ea.svg)](#-enterprise-saas-dashboard--dark-mode)

**Sentinel-AI** is a production-grade, full-stack cybersecurity threat detection platform engineered to detect **phishing websites**, malicious **QR codes ("Quishing")**, and **typosquatted brand impersonations** in real time.

Built with **Flask**, **scikit-learn**, and **OpenCV**, Sentinel-AI unifies a high-accuracy Machine Learning classifier (trained on **500,000+** URLs) with an advanced **Rule-Based Threat Intelligence Layer** and a **Proactive Typosquatting Monitoring Engine** — requiring **zero third-party API keys** and running completely offline and locally.

---

## 📑 Table of Contents

- [Key Capabilities](#-key-capabilities)
- [System Architecture](#-system-architecture)
- [How It Works](#-how-it-works)
- [Enterprise SaaS Dashboard & Dark Mode](#-enterprise-saas-dashboard--dark-mode)
- [Project Structure](#-project-structure)
- [Installation & Quickstart](#-installation--quickstart)
- [Git Setup & Pushing to GitHub](#-git-setup--pushing-to-github)
- [REST API Reference](#-rest-api-reference)
- [Automated Testing](#-automated-testing)
- [Machine Learning Pipeline](#-machine-learning-pipeline)
- [Disclaimer](#-disclaimer)

---

## 🚀 Key Capabilities

### 1. 🤖 Hybrid Machine Learning Phishing Classifier
- **Trained Model**: Serialized `LogisticRegression` model calibrated on **549,346 URLs** with **96.5% test accuracy**.
- **Lexical Tokenization**: `CountVectorizer` converts character sequences, path delimiters, query strings, and n-grams into sparse feature matrices.
- **Mathematical Confidence**: Extracts probability vectors using `predict_proba()` to compute granular confidence percentages (e.g. `98.76% Phishing` vs `1.24% Safe`).

### 2. 🔍 Proactive Typosquatting & Brand Spoofing Engine (100% In-House)
- **Zero External API Keys**: Generates and evaluates typosquats entirely within Python memory using custom algorithmic generators.
- **Leetspeak & Homoglyph Normalization**: Neutralizes deceptive character swaps that fool standard ML models (e.g., `go0ogle.com` $\rightarrow$ `google.com`, `link3edin.com` $\rightarrow$ `linkedin.com`, `paypa1.com` $\rightarrow$ `paypal.com`).
- **Levenshtein Edit-Distance**: Catches single- and double-character insertions, deletions, additions, and vowel transpositions.
- **Combosquatting Detection**: Identifies domains pairing trusted brands with social engineering keywords (`paypal-verify.com`, `google-login.com`).
- **Punycode / IDN Homoglyphs**: Automatically identifies internationalized domain spoofing (`xn--`).
- **Protected Brand Roster**: Out-of-the-box whitelisting for Google, LinkedIn, PayPal, Amazon, Apple, Microsoft, Netflix, GitHub, Meta, Binance, Coinbase, Chase, and major banking institutions.

### 3. 📷 Visual QR Code Threat Scanner ("Quishing" Defense)
- **Multi-Pass Computer Vision**: Powered by OpenCV with standard BGR, grayscale equalization, ArUco QR detection, and Otsu adaptive thresholding to decode low-contrast, skewed, or blurred QR codes.
- **Strict Payload Sanitization**: Validates extracted content to ensure only web URLs are processed, immediately rejecting plain text, SMS, phone numbers, or Wi-Fi strings.
- **Wide Format Support**: Drag-and-drop or file upload support for `.png`, `.jpg`, `.jpeg`, and `.webp` images up to 8 MB.

### 4. 📊 Threat Intelligence & Forensic Data Table
- **Proactive Brand Telemetry**: Generates comprehensive variations and maps each to authentic server telemetry:
  - `Source URL` & `URL Construction` (Insertion, Addition, Vowel Swap, Homoglyph, Repetition, Omission, Combosquatting)
  - `Risk Score` (1 = Low to 5 = Critical Red)
  - `Live Scan Verdict` (`Phishing`, `Suspicious`, `Safe`)
  - `IP Address`, `Name Servers`, `Mail Servers`, and `MX Records` (email spoofing capability)
  - `Registration Date`, `Registrar`, and `SSL Certificate`
- **Data Exporting**: Instant one-click export to **CSV** or **JSON** for automated SOC workflows and registrar abuse takedown filings.

### 5. 🧠 RAG (Retrieval-Augmented Generation) Threat Intelligence & Copilot Engine
- **Local Semantic Vector Retriever**: Built with TF-IDF and hybrid keyword/tag boosting via scikit-learn, requiring **zero external vector database servers** and running 100% offline.
- **MITRE ATT&CK Matrix Grounding**: Dynamically maps scanned URLs and user queries to relevant MITRE tactics (`T1566.001 Spearphishing Link`, `T1566.002 Spearphishing Attachment`, `T1556 AiTM / Reverse Proxy Phishing`, `T1598 Credential Harvesting`, `T1204 User Execution`).
- **Deep Forensic Threat Dossiers**: Automatically generates executive summaries, attack mechanism breakdowns, and SOC remediation playbooks with source citations for every scanned URL or QR code.
- **Interactive Threat Copilot (Q&A)**: Embedded conversational assistant available in a dedicated dashboard view (`paneThreatCopilot`) and a quick-access floating drawer, providing real-time cybersecurity advice and playbook execution.
- **Dual-Mode Engine (Local & Pluggable LLM)**: Operates 100% locally out-of-the-box using the built-in forensic synthesizer, with optional pluggable Gemini API (`GEMINI_API_KEY`) support.

---

## 🎨 Enterprise SaaS Dashboard & Dark Mode

Sentinel-AI features an enterprise-grade web interface inspired by modern security operations dashboards:

- **Dual-Access Theme Toggle**: Switch effortlessly between **Light Mode** (clean SaaS theme) and **Dark Mode** (deep `#0B0F17` / `#131B2A` cybersecurity night theme).
- **Ultra-Smooth Transitions**: A global `0.3s cubic-bezier(0.4, 0, 0.2, 1)` transition smoothly blends all backgrounds, card surfaces, text colors, and borders without page reload.
- **Zero-Flash Persistence**: User theme preferences (`sentinel_theme`) and sidebar state (`sentinel_sidebar_collapsed`) are saved in `localStorage`, automatically matching system OS settings on initial load.
- **Collapsible Navigation (`<<` / `>>`)**: Sidebar collapses from `230px` to `68px` on desktop with smooth chevron rotation, icon-only navigation, and full mobile drawer backdrop support.

---

## 🔬 System Architecture

```
                             [ User Ingestion Layer ]
                             /                      \
                     (Direct URL Input)       (QR Image Upload)
                             |                        |
                             |                [ OpenCV Engine ]
                             |         (4-Pass Thresholding & Decoding)
                             |                        |
                             v                        v
                    [ Normalize & Strip Protocol (http/https/www) ]
                                          |
                +-------------------------+-------------------------+
                |                                                   |
                v                                                   v
     [ Threat Intelligence ]                              [ ML Prediction Pipeline ]
  - Leetspeak Normalization (0->o, 3->e)                - CountVectorizer Tokenizer
  - Levenshtein Edit Distance (<= 2)                    - Logistic Regression Classifier
  - Combosquatting & Suspicious Keywords                - Probability Confidence Calculation
  - Punycode (IDN) Check                                            |
                |                                                   |
                +-------------------------+-------------------------+
                                          |
                                          v
                              [ Decision & Merge Engine ]
                     (Heuristic overrides if spoofing confirmed)
                                          |
                                          v
                 [ RAG Threat Intelligence & Copilot Engine ]
                 ├── Semantic Vector Retriever (TF-IDF + Metadata Boost)
                 ├── Grounded Threat Knowledge Base (MITRE ATT&CK Matrix)
                 └── Forensic Dossier Synthesizer & Copilot Q&A
                                          |
                                          v
                              [ JSON API / UI Response ]
                  - Final Verdict: Safe / Phishing / Suspicious
                  - RAG Forensic Dossier & MITRE ATT&CK Mapping
                  - Interactive Threat Copilot Chatbot Assistant
                  - Proactive Typosquatting Table Telemetry
```

---

## 📁 Project Structure

```plaintext
Sentinel-AI-Phishing-Detector/
├── app.py                              # Core Flask backend, ML pipeline, Threat Engine & RAG APIs
├── rag/                                # Retrieval-Augmented Generation (RAG) Module
│   ├── __init__.py                     # Package initialization and exports
│   ├── knowledge_base.json             # Curated Threat Intelligence & MITRE knowledge base
│   ├── retriever.py                    # Semantic TF-IDF vector retriever with hybrid boosting
│   ├── generator.py                    # Forensic threat dossier synthesizer & LLM adapter
│   └── rag_engine.py                   # High-level RAG orchestrator & singleton
├── phishing.pkl                        # Pre-trained Logistic Regression model (500k+ URLs)
├── phishing_mnb.pkl                    # Alternative Multinomial Naive Bayes model
├── vectorizer.pkl                      # Pre-trained CountVectorizer feature extractor
├── requirements.txt                    # Production Python dependencies
├── test_app.py                         # Comprehensive backend validation test suite
├── Phishing Website detection system.ipynb # Original research, training & benchmarking notebook
│
├── templates/
│   └── index.html                      # Semantic dashboard UI (Strict separation of HTML/CSS/JS)
│
├── static/
│   ├── css/
│   │   └── style.css                   # SaaS Light & Dark themes, smooth transitions & responsive layout
│   ├── js/
│   │   ├── script.js                   # Client-side state, AJAX scanner, Chart.js & CSV/JSON export
│   │   └── security-pulse.js           # React-powered, live-updating dashboard widget
│   └── images/                         # Visual assets and icons
│
└── Dataset/
    └── phishing_site_urls.csv          # 500k+ labeled URLs training dataset
```

---

## 🛠️ Installation & Quickstart

### Prerequisites
- **Python 3.10+** (tested on Python 3.10, 3.11, 3.12, 3.14)
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/Sentinel-AI-Phishing-Detector.git
cd Sentinel-AI-Phishing-Detector
```

### 2. Create and Activate Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv env
.\env\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv env
source env/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train the Email Phishing Classifier

Extract the Kaggle dataset and train from its aggregate `phishing_email.csv` file:

```bash
python train_email_classifier.py "../archive (1)"
```

The aggregate file contains `text_combined` email text and labels (`0` = legitimate, `1` = phishing). Training reports held-out metrics and saves `email_classifier.joblib` locally; that generated model is ignored by Git. The scanner loads it automatically. If it is not present, the existing threat-rule checks remain available.

The dataset is [Phishing Email Dataset on Kaggle](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset), licensed CC BY-SA 4.0. Attribute the dataset to Naser Abdullah Alam and cite Al-Subaiey et al., [“Novel Interpretable and Robust Web-based AI Platform for Phishing Email Detection”](https://arxiv.org/abs/2405.11619). Follow the dataset license if redistributing the dataset or a model trained from it.

### 5. Run the Application
```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5002
```

---

## 🚀 Git Setup & Pushing to GitHub

To push this repository to your GitHub account:

```bash
# 1. Initialize git (if not already initialized)
git init

# 2. Add all project files
git add .

# 3. Commit the changes
git commit -m "feat: complete Sentinel-AI threat detection platform with dark mode and typosquatting engine"

# 4. Set the main branch
git branch -M main

# 5. Link your GitHub remote repository
git remote add origin https://github.com/<your-username>/Sentinel-AI-Phishing-Detector.git

# 6. Push to GitHub
git push -u origin main
```

---

## 📡 REST API Reference

Sentinel-AI provides high-performance JSON endpoints for easy integration with SIEMs, Slack bots, and automated security workflows.

### 1. Scan URL
- **Endpoint:** `POST /scan-url`
- **Headers:** `Content-Type: application/json`

**Request Payload:**
```json
{
  "url": "https://go0ogle.com"
}
```

**Response (`200 OK`):**
```json
{
  "status": "success",
  "scan_type": "url",
  "url": "https://go0ogle.com",
  "cleaned_url": "go0ogle.com",
  "verdict": "phishing",
  "is_phishing": true,
  "confidence": 98.76,
  "prob_safe": 1.24,
  "prob_phishing": 98.76,
  "threat_type": "typosquatting",
  "target_brand": "Google",
  "threat_reason": "Typosquatting detected: \"go0ogle\" is visually masquerading as \"Google\" (distance: 1)",
  "recommendation": "High risk: This website appears to be a spoofed / typosquatted domain impersonating Google. Do not visit this site or submit any credentials."
}
```

---

### 2. Scan QR Code ("Quishing" Defense)
- **Endpoint:** `POST /scan-qr`
- **Content-Type:** `multipart/form-data`
- **Body:** `file: <binary image>` (Accepted: `.png`, `.jpg`, `.jpeg`, `.webp`, Max 8MB)

**Response (`200 OK`):**
```json
{
  "status": "success",
  "scan_type": "qr",
  "extracted_url": "https://google.com",
  "cleaned_url": "google.com",
  "verdict": "safe",
  "is_phishing": false,
  "confidence": 64.32,
  "prob_safe": 64.32,
  "prob_phishing": 35.68,
  "recommendation": "The URL structure and lexical patterns match recognized safe web conventions."
}
```

---

### 3. Generate Typosquats & Domain Monitoring
- **Endpoint:** `GET /api/typosquats?domain=linkedin.com`
- **Method:** `GET` or `POST` (Accepts JSON body or query parameters)

**Response (`200 OK`):**
```json
{
  "status": "success",
  "domain": "linkedin.com",
  "count": 16,
  "results": [
    {
      "source_url": "link3edin.com",
      "construction": "Insertion",
      "risk": 5,
      "verdict": "Phishing",
      "category": "Domain Parking",
      "ip_address": "23.82.12.32",
      "name_servers": "ns3199.dns.dyn.com, ns1188.dns.dyn.com",
      "mail_servers": "mail.h-email.net",
      "mx_records": true,
      "registration_date": "12-Jan-2024",
      "registrar": "Google LLC",
      "ssl_cert": "GoDaddy.com, Inc.",
      "takedown": "--",
      "confidence": 98.76
    }
  ]
}
```

---

### 4. RAG Threat Copilot Interactive Q&A
- **Endpoint:** `POST /api/rag/ask`
- **Method:** `POST`
- **Payload (`application/json`):**
```json
{
  "message": "What is EvilProxy and how does it bypass MFA?",
  "history": [],
  "context_url": "https://go0ogle.com"
}
```
**Response (`200 OK`):**
```json
{
  "status": "success",
  "query": "What is EvilProxy and how does it bypass MFA?",
  "answer": "### 🛡️ Threat Intelligence Analysis: Modern Phishing Kits: EvilProxy, Modlishka, and Muraena (T1556)\n\nAdversary-in-the-Middle (AiTM) reverse proxies transparently relay HTTP traffic between the victim and authentic servers...",
  "source": "rag_native_synthesizer",
  "citations": [
    {
      "id": "reverse-proxy-phishing-kits",
      "title": "Modern Phishing Kits: EvilProxy, Modlishka, and Muraena",
      "mitre_id": "T1556",
      "category": "threat_actor_tools",
      "score": 0.82
    }
  ],
  "suggested_questions": [
    "What are the immediate steps if an employee entered credentials?",
    "How does FIDO2/WebAuthn make authentication immune to phishing?"
  ],
  "timestamp": "07:20 PM"
}
```

---

### 5. RAG Forensic Threat Dossier Generator
- **Endpoint:** `POST /api/rag/explain`
- **Method:** `POST`
- **Payload (`application/json`):**
```json
{
  "url": "https://go0ogle.com"
}
```
**Response (`200 OK`):**
```json
{
  "status": "success",
  "url": "https://go0ogle.com",
  "dossier": {
    "source": "rag_native_synthesizer",
    "executive_summary": "CRITICAL THREAT: The scanned URL 'go0ogle.com' is classified as a malicious PHISHING destination with 98.76% confidence...",
    "attack_mechanism": "Alphanumeric deception (Levenshtein distance / leetspeak mutation) impersonating Google...",
    "mitre_techniques": ["T1566.001"],
    "action_steps": [
      "Containment: Do not navigate to the URL, submit credentials, or authorize OAuth prompts.",
      "Perimeter Blocking: Blacklist domain and corresponding IP on corporate firewalls and DNS resolvers."
    ],
    "citations": [
      {
        "id": "mitre-t1566-001",
        "title": "MITRE ATT&CK T1566.001 - Spearphishing Link",
        "mitre_id": "T1566.001"
      }
    ]
  }
}
```

---

### 6. RAG Knowledge Base Overview & Sources
- **Endpoint:** `GET /api/rag/overview` or `GET /api/rag/sources`
- **Method:** `GET`

---

## 🧪 Automated Testing

Sentinel-AI includes a comprehensive automated validation suite covering ML model persistence, QR image decoding, typosquatting heuristics, brand protection whitelists, RAG vector retrieval, and all API endpoints:

```bash
python test_app.py
```

### Verified Test Results (100% Pass Rate):
```text
==================================================
RUNNING SENTINEL AI PHISHING DETECTION TEST SUITE
==================================================
[PASS] GET / returns 200 OK
[PASS] Home page contains Intelligent Phishing Detection System heading
[PASS] Home page references style.css
[PASS] Home page references script.js
[PASS] Home page references Chart.js CDN
[PASS] POST / with safe URL returns 200
[PASS] POST / with safe URL renders healthy prediction message
[PASS] POST / with phishing URL returns 200
[PASS] POST / with phishing URL renders Phishing prediction message
[PASS] AJAX /scan-url with google.com returns 200
[PASS] google.com classified as safe
[PASS] google.com protocol stripped correctly
[PASS] google.com returns model confidence percentage
[PASS] github.com classified as safe
[PASS] AJAX /scan-url with phishing URL returns 200
[PASS] paypal phishing classified as phishing
[PASS] phishing URL stripped properly
[PASS] phishing probability is returned
[PASS] netflix phishing URL classified as phishing
[PASS] Protocol stripping regex strips http://, https://, and leaves bare domain identical
[PASS] AJAX /scan-url with non-URL returns 400
[PASS] AJAX /scan-url with empty URL returns 400
[PASS] POST /scan-qr with safe QR returns 200
[PASS] Extracted URL matches encoded QR
[PASS] Extracted safe URL classified as safe
[PASS] Scan type marked as 'qr'
[PASS] POST /scan-qr with phishing QR returns 200
[PASS] Extracted phishing URL matches encoded QR
[PASS] Extracted phishing URL classified as phishing
[PASS] POST /scan-qr with plain text returns 422 Unprocessable Entity
[PASS] Plain text QR returns error_type 'not_a_url'
[PASS] POST /scan-qr with image without QR returns 400
[PASS] POST /scan-qr with corrupted image returns 400
[PASS] POST /scan-qr with unsupported format (.gif) returns 400
[PASS] POST /scan-qr with missing file returns 400
[PASS] POST /scan-qr supports WEBP format
[PASS] CountVectorizer is intact
[PASS] LogisticRegression model is intact
[PASS] Class labels are ['bad', 'good']
[PASS] QR scanning and manual URL scanning yield identical prediction & confidence
[PASS] https://go0ogle.com correctly flagged as phishing
[PASS] https://go0ogle.com target brand identified as Google
[PASS] http://www.go0ogle.com/ correctly flagged as phishing
[PASS] https://paypa1.com correctly flagged as PayPal typosquatting
[PASS] https://amaz0n.com correctly flagged as Amazon typosquatting
[PASS] Legitimate google.com correctly classified as safe
[PASS] /api/typosquats returns success for linkedin.com
[PASS] /api/typosquats returns populated results matching screenshot
[PASS] Typosquat records contain all table columns (source_url, construction, risk, verdict)
[PASS] RAG Knowledge Base contains 21 documents (>= 15 required)
[PASS] Knowledge Base contains structured cybersecurity categories
[PASS] RAG semantic search returned results for EvilProxy
[PASS] Semantic search correctly retrieved EvilProxy or MITRE T1556 documents
[PASS] Semantic search correctly retrieved quishing-evasion document
[PASS] POST /api/rag/ask returns 200 OK
[PASS] POST /api/rag/ask status is success
[PASS] POST /api/rag/ask generated comprehensive answer
[PASS] POST /api/rag/ask includes threat knowledge citations
[PASS] POST /api/rag/ask includes follow-up suggestions
[PASS] POST /api/rag/ask with empty query returns 400
[PASS] POST /api/rag/explain returns 200 OK
[PASS] POST /api/rag/explain status is success
[PASS] RAG Dossier contains executive_summary and attack_mechanism
[PASS] RAG Dossier identifies MITRE ATT&CK techniques
[PASS] RAG Dossier includes actionable incident playbook steps
[PASS] RAG Dossier includes verified source citations
[PASS] GET /api/rag/overview and /api/rag/sources return 200 OK
[PASS] RAG overview contains knowledge_base telemetry
[PASS] /scan-url response enriched with rag_analysis
[PASS] /scan-url rag_analysis contains executive_summary
[PASS] /scan-qr response enriched with rag_analysis
==================================================
TEST RESULTS: 71 / 71 TESTS PASSED (100.0%)
==================================================
```

---

## 🧠 Machine Learning Pipeline

- **Dataset**: `Dataset/phishing_site_urls.csv` comprising **549,346 URLs** labeled as `good` (safe) or `bad` (phishing).
- **Feature Extraction**: `CountVectorizer` converts character/word n-grams and delimiters (e.g., `/`, `-`, `?`, `.`) into token frequency vectors.
- **Model Architecture**:
  - **Primary Model**: Logistic Regression (`phishing.pkl`) trained with `L2` regularization.
  - **Evaluation Metric**: **96.5% Test Accuracy** (`l_model.score(x_test, y_test) = 0.9650`).
  - **Alternative Model**: Multinomial Naive Bayes (`phishing_mnb.pkl`).
- **Research Notebook**: Exploratory data analysis, tokenization benchmarks, and classification reports are preserved in [`Phishing Website detection system.ipynb`](Phishing%20Website%20detection%20system.ipynb).

---

## ⚠️ Disclaimer

This system is developed for **defensive, educational, and cybersecurity research purposes** to empower users, researchers, and security teams in detecting deceptive URLs, malicious QR codes, and brand impersonation attacks.
=======
# PHISHING-DETECTION-
>>>>>>> 92dd30ef9e38632d3ca37518666985d52e044209
>>>>>>>
>>>>>>> link -> https://phishing-detection-cyan-ten.vercel.app/
