# Sentinel AI Chrome Extension

The Manifest V3 popup reads the current tab URL after the user opens the extension and sends it only when **Scan URL** is clicked. Predictions come from the existing Flask `POST /scan-url` endpoint; the extension does not include or train a model and does not store URLs or scan history.

## Run and load

1. Start the existing Sentinel AI Flask app at `http://127.0.0.1:5002/`.
2. In Chrome, open `chrome://extensions` and enable **Developer mode**.
3. Select **Load unpacked** and choose this `Sentinel-AI-Chrome-Extension` folder.
4. Pin the Sentinel AI extension, open a website, click the extension icon, then select **Scan URL**. You can edit the captured address before scanning.
5. To verify both outcomes, scan `https://google.com` and then paste `https://go0ogle.com` into the popup. The second value is sent only to the local scanner API; the extension never opens it.

The extension requests only the `activeTab` permission and access to `http://127.0.0.1:5002/*` for the existing API. It does not open scanned links. Browser-internal pages such as `chrome://extensions` are not scannable.

## Existing API contract

The popup sends `POST /scan-url` with JSON shaped as `{"url":"https://example.com"}`. It renders the backend's `verdict`, `confidence`, `threat_reason`, `recommendation`, and `message` fields. The current backend returns `safe` or `phishing`; the popup also recognizes `suspicious` if the API provides that verdict.

If you deploy the backend on a different origin, update `API_BASE_URL` in `popup.js` and the matching single entry in `host_permissions` in `manifest.json`.
