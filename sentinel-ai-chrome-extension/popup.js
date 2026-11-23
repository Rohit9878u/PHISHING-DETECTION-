'use strict';

const API_BASE_URL = 'http://127.0.0.1:5002';

const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const refreshTabButton = document.getElementById('refreshTabButton');
const tabHint = document.getElementById('tabHint');
const scanButton = document.getElementById('scanButton');
const scanningState = document.getElementById('scanningState');
const resultPanel = document.getElementById('resultPanel');
const resultLabel = document.getElementById('resultLabel');
const resultHeading = document.getElementById('resultHeading');
const resultUrl = document.getElementById('resultUrl');
const confidenceBlock = document.getElementById('confidenceBlock');
const confidenceValue = document.getElementById('confidenceValue');
const reasonCard = document.getElementById('reasonCard');
const reasonText = document.getElementById('reasonText');

async function loadActiveTabUrl() {
    try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (activeTab && typeof activeTab.url === 'string') {
            urlInput.value = activeTab.url;
            tabHint.textContent = 'Current tab URL loaded. You can edit or paste another URL.';
            return;
        }

        tabHint.textContent = 'This browser page does not expose a website URL. Paste an http or https address.';
    } catch (error) {
        tabHint.textContent = 'Could not read the current tab. Paste an http or https address to continue.';
    }
}

function normalizeWebUrl(value) {
    const trimmed = value.trim();
    if (!trimmed) {
        throw new Error('Enter a website URL to scan.');
    }

    const candidate = /^[a-z][a-z\d+.-]*:/i.test(trimmed) ? trimmed : `https://${trimmed}`;
    let parsed;
    try {
        parsed = new URL(candidate);
    } catch (error) {
        throw new Error('Enter a valid website URL, such as https://example.com.');
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Only http and https website URLs can be scanned.');
    }

    if (!parsed.hostname) {
        throw new Error('Enter a valid website URL, such as https://example.com.');
    }

    return parsed.href;
}

function showResultError(message, url = '') {
    resultPanel.dataset.verdict = 'error';
    resultLabel.textContent = 'SCAN ERROR';
    resultHeading.textContent = 'Unable to scan this URL';
    resultUrl.textContent = url;
    confidenceBlock.hidden = true;
    reasonText.textContent = message;
    reasonCard.hidden = false;
    resultPanel.hidden = false;
}

function getVerdict(data) {
    const verdict = typeof data.verdict === 'string' ? data.verdict.toLowerCase() : '';

    if (verdict === 'phishing' || data.is_phishing === true) {
        return { key: 'phishing', label: 'PHISHING', heading: 'Threat detected' };
    }
    if (verdict === 'suspicious') {
        return { key: 'suspicious', label: 'SUSPICIOUS', heading: 'Review this website carefully' };
    }
    if (verdict === 'safe' || (verdict === '' && data.is_phishing === false)) {
        return { key: 'safe', label: 'SAFE', heading: 'No phishing detected' };
    }

    throw new Error('The Sentinel AI backend returned an unrecognized verdict.');
}

function renderResult(data, scannedUrl) {
    const verdict = getVerdict(data);
    resultPanel.dataset.verdict = verdict.key;
    resultLabel.textContent = verdict.label;
    resultHeading.textContent = verdict.heading;
    resultUrl.textContent = data.cleaned_url || scannedUrl;

    const confidence = data.confidence;
    if (typeof confidence === 'number' && Number.isFinite(confidence) && confidence >= 0 && confidence <= 100) {
        confidenceValue.textContent = `${Math.round(confidence)}%`;
        confidenceBlock.hidden = false;
    } else {
        confidenceBlock.hidden = true;
    }

    const explanation = [data.threat_reason, data.recommendation, data.message]
        .find(value => typeof value === 'string' && value.trim());
    if (explanation) {
        reasonText.textContent = explanation;
        reasonCard.hidden = false;
    } else {
        reasonCard.hidden = true;
        reasonText.textContent = '';
    }

    resultPanel.hidden = false;
}

function setScanning(isScanning) {
    scanButton.disabled = isScanning;
    scanButton.classList.toggle('is-scanning', isScanning);
    scanButton.setAttribute('aria-busy', String(isScanning));
    scanButton.querySelector('.scan-button-text').textContent = isScanning ? 'Scanning…' : 'Scan URL';
    scanningState.hidden = !isScanning;
}

async function scanUrl(event) {
    event.preventDefault();
    let scannedUrl;

    try {
        scannedUrl = normalizeWebUrl(urlInput.value);
    } catch (error) {
        showResultError(error.message);
        return;
    }

    urlInput.value = scannedUrl;
    resultPanel.hidden = true;
    setScanning(true);

    try {
        const response = await fetch(`${API_BASE_URL}/scan-url`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            credentials: 'omit',
            cache: 'no-store',
            referrerPolicy: 'no-referrer',
            body: JSON.stringify({ url: scannedUrl })
        });

        let data;
        try {
            data = await response.json();
        } catch (error) {
            throw new Error(`Sentinel AI returned an unreadable response (HTTP ${response.status}).`);
        }

        if (!data || typeof data !== 'object') {
            throw new Error('Sentinel AI returned an invalid scan response.');
        }

        if (!response.ok || data.status !== 'success') {
            throw new Error(data.message || `Sentinel AI could not scan this URL (HTTP ${response.status}).`);
        }

        renderResult(data, scannedUrl);
    } catch (error) {
        const message = error instanceof TypeError
            ? `Could not connect to the Sentinel AI backend at ${API_BASE_URL}. Make sure the Flask app is running.`
            : error.message;
        showResultError(message, scannedUrl);
    } finally {
        setScanning(false);
    }
}

scanForm.addEventListener('submit', scanUrl);
refreshTabButton.addEventListener('click', loadActiveTabUrl);
loadActiveTabUrl();
