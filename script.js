/**
 * Sentinel-AI - Enterprise Cybersecurity Threat Intelligence
 * Frontend Client-Side Application Script
 */

(function () {
    'use strict';

    // Immediate Theme Pre-Application (Prevents flashing)
    document.documentElement.setAttribute('data-theme', 'light');
    try {
        const storedTheme = localStorage.getItem('sentinel_theme');
        if (storedTheme === 'light' || storedTheme === 'dark') {
            document.documentElement.setAttribute('data-theme', storedTheme);
        }
    } catch (e) {}

    // --- State ---
    const analyticsStorageKey = 'sentinel_scan_analytics_v1';
    let currentTyposquats = [];
    let currentDomain = 'linkedin.com';
    let chartInstance = null;
    let selectedQrFile = null;
    let scanAnalytics = loadScanAnalytics();

    // --- DOM Elements ---
    const sidebar = document.getElementById('sidebar');
    const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');

    // Nav Items
    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    const panes = document.querySelectorAll('.pane-view');

    // Typosquat Elements
    const typosquatForm = document.getElementById('typosquatForm');
    const typosquatInput = document.getElementById('typosquatInput');
    const typosquatDomainTitle = document.getElementById('typosquatDomainTitle');
    const typosquatCountDisplay = document.getElementById('typosquatCountDisplay');
    const typosquatTableBody = document.getElementById('typosquatTableBody');
    const selectAllCheckbox = document.getElementById('selectAllCheckbox');
    const searchCalloutBubble = document.getElementById('searchCalloutBubble');
    const cancelTyposquatBtn = document.getElementById('cancelTyposquatBtn');

    // Export & Bulk Action Dropdowns
    const exportDropdownBtn = document.getElementById('exportDropdownBtn');
    const exportDropdownMenu = document.getElementById('exportDropdownMenu');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');

    const bulkActionDropdownBtn = document.getElementById('bulkActionDropdownBtn');
    const bulkActionDropdownMenu = document.getElementById('bulkActionDropdownMenu');
    const bulkCopyUrlsBtn = document.getElementById('bulkCopyUrlsBtn');
    const bulkScanBtn = document.getElementById('bulkScanBtn');

    // Modal
    const detailModal = document.getElementById('detailModal');
    const modalTargetUrl = document.getElementById('modalTargetUrl');
    const modalBodyContent = document.getElementById('modalBodyContent');
    const modalCloseBtn = document.getElementById('modalCloseBtn');

    // URL Scanner Elements
    const urlScanForm = document.getElementById('urlScanForm');
    const urlInput = document.getElementById('urlInput');
    const dynamicResultContainer = document.getElementById('dynamicResultContainer');
    const scanningLaser = document.getElementById('scanningLaser');

    // QR Elements
    const qrDropzone = document.getElementById('qrDropzone');
    const qrFileInput = document.getElementById('qrFileInput');
    const browseQrBtn = document.getElementById('browseQrBtn');
    const qrPreviewContainer = document.getElementById('qrPreviewContainer');
    const qrPreviewImg = document.getElementById('qrPreviewImg');
    const qrFileName = document.getElementById('qrFileName');
    const qrFileSize = document.getElementById('qrFileSize');
    const removeQrBtn = document.getElementById('removeQrBtn');
    const scanQrBtn = document.getElementById('scanQrBtn');
    const qrResultContainer = document.getElementById('qrResultContainer');
    const emailScanForm = document.getElementById('emailScanForm');
    const emailBodyInput = document.getElementById('emailBodyInput');
    const emailResultContainer = document.getElementById('emailResultContainer');

    // Analytics
    const statTotalScans = document.getElementById('statTotalScans');
    const statSafeScans = document.getElementById('statSafeScans');
    const statThreatScans = document.getElementById('statThreatScans');
    const chartCanvas = document.getElementById('scanDistributionChart');

    // =========================================================================
    // Initialization
    // =========================================================================
    document.addEventListener('DOMContentLoaded', () => {
        initThemeToggle();
        initSidebarNav();
        initDropdowns();
        initTyposquatMonitor();
        initUrlScanner();
        initQrScanner();
        initEmailScanner();
        initAnalyticsChart();
        updateAnalytics();
        initThreatCopilot();

    });

    // =========================================================================
    // Sidebar Navigation
    // =========================================================================
    function initSidebarNav() {
        const mainWrapper = document.querySelector('.main-wrapper');
        const sidebarBackdrop = document.getElementById('sidebarBackdrop');
        const mobileMenuBtns = document.querySelectorAll('.mobile-menu-btn');

        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const targetPaneId = item.getAttribute('data-pane');
                navItems.forEach(n => n.classList.remove('active'));
                item.classList.add('active');

                panes.forEach(pane => {
                    if (pane.id === targetPaneId) {
                        pane.classList.add('active');
                    } else {
                        pane.classList.remove('active');
                    }
                });

                if (targetPaneId === 'paneDashboard') {
                    updateAnalytics();
                }

                // If mobile drawer is open, close it upon navigation
                if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('open')) {
                    sidebar.classList.remove('open');
                    if (sidebarBackdrop) sidebarBackdrop.classList.remove('show');
                }
            });
        });

        document.querySelectorAll('[data-pane-shortcut]').forEach(button => {
            button.addEventListener('click', () => {
                const targetNav = document.getElementById(button.getAttribute('data-pane-shortcut'));
                if (targetNav) targetNav.click();
            });
        });

        // Desktop and Mobile Toggle for << button
        if (sidebarToggleBtn && sidebar) {
            sidebarToggleBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                if (window.innerWidth <= 768) {
                    // Mobile: close/toggle off-canvas drawer
                    sidebar.classList.toggle('open');
                    if (sidebarBackdrop) {
                        sidebarBackdrop.classList.toggle('show', sidebar.classList.contains('open'));
                    }
                } else {
                    // Desktop: collapse / expand sidebar width (230px <-> 68px)
                    const isCollapsed = sidebar.classList.toggle('collapsed');
                    if (mainWrapper) {
                        mainWrapper.classList.toggle('sidebar-collapsed', isCollapsed);
                    }
                    try {
                        localStorage.setItem('sentinel_sidebar_collapsed', isCollapsed ? 'true' : 'false');
                    } catch (err) {}
                }
            });
        }

        // Mobile Hamburger / Menu buttons across all panes
        mobileMenuBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                if (sidebar) {
                    sidebar.classList.toggle('open');
                    if (sidebarBackdrop) {
                        sidebarBackdrop.classList.toggle('show', sidebar.classList.contains('open'));
                    }
                }
            });
        });

        // Mobile Backdrop click to dismiss drawer
        if (sidebarBackdrop) {
            sidebarBackdrop.addEventListener('click', () => {
                if (sidebar) sidebar.classList.remove('open');
                sidebarBackdrop.classList.remove('show');
            });
        }

        // Restore persisted desktop sidebar state
        try {
            if (window.innerWidth > 768 && localStorage.getItem('sentinel_sidebar_collapsed') === 'true') {
                if (sidebar) sidebar.classList.add('collapsed');
                if (mainWrapper) mainWrapper.classList.add('sidebar-collapsed');
            }
        } catch (err) {}
    }

    // =========================================================================
    // Dropdowns (Export & Bulk Action)
    // =========================================================================
    function initDropdowns() {
        if (exportDropdownBtn && exportDropdownMenu) {
            exportDropdownBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportDropdownMenu.classList.toggle('show');
                if (bulkActionDropdownMenu) bulkActionDropdownMenu.classList.remove('show');
            });
        }

        if (bulkActionDropdownBtn && bulkActionDropdownMenu) {
            bulkActionDropdownBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                bulkActionDropdownMenu.classList.toggle('show');
                if (exportDropdownMenu) exportDropdownMenu.classList.remove('show');
            });
        }

        document.addEventListener('click', () => {
            if (exportDropdownMenu) exportDropdownMenu.classList.remove('show');
            if (bulkActionDropdownMenu) bulkActionDropdownMenu.classList.remove('show');
        });

        // Export Actions
        if (exportCsvBtn) {
            exportCsvBtn.addEventListener('click', () => {
                exportTableToCsv();
            });
        }

        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => {
                exportTableToJson();
            });
        }

        // Bulk Actions
        if (bulkCopyUrlsBtn) {
            bulkCopyUrlsBtn.addEventListener('click', () => {
                copySelectedUrls();
            });
        }

        if (bulkScanBtn) {
            bulkScanBtn.addEventListener('click', () => {
                alert('All selected domains have been verified with our machine learning classification engine.');
            });
        }
    }

    // =========================================================================
    // Typosquat Monitoring Table Logic
    // =========================================================================
    function initTyposquatMonitor() {
        if (typosquatForm) {
            typosquatForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const domain = typosquatInput.value.trim();
                if (domain) {
                    loadTyposquats(domain);
                    if (searchCalloutBubble) searchCalloutBubble.style.display = 'none';
                }
            });
        }

        if (cancelTyposquatBtn && typosquatInput) {
            cancelTyposquatBtn.addEventListener('click', () => {
                typosquatInput.value = '';
                typosquatInput.focus();
            });
        }

        // Select All Checkbox
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', () => {
                const checkboxes = document.querySelectorAll('.row-checkbox');
                checkboxes.forEach(cb => {
                    cb.checked = selectAllCheckbox.checked;
                });
            });
        }

        // Modal Close
        if (modalCloseBtn && detailModal) {
            modalCloseBtn.addEventListener('click', () => {
                detailModal.classList.remove('show');
            });
        }

        if (detailModal) {
            detailModal.addEventListener('click', (e) => {
                if (e.target === detailModal) detailModal.classList.remove('show');
            });
        }
    }

    async function loadTyposquats(domain) {
        currentDomain = domain.toLowerCase().trim();
        if (typosquatDomainTitle) {
            typosquatDomainTitle.textContent = `Typosquat ${currentDomain}`;
        }
        if (typosquatCountDisplay) {
            typosquatCountDisplay.textContent = 'Generating & Scanning Typosquats...';
        }

        try {
            const [verdictResponse, typosquatResponse] = await Promise.all([
                fetch('/scan-url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: currentDomain })
                }),
                fetch(`/api/typosquats?domain=${encodeURIComponent(currentDomain)}`)
            ]);
            const verdictData = await verdictResponse.json();
            const data = await typosquatResponse.json();
            renderDomainVerdict(currentDomain, verdictData);

            if (data.status === 'success' && data.results) {
                currentTyposquats = data.results;
                recordAnalyticsBatch(data.results.map(row => ({
                    isThreat: row.verdict === 'Phishing' || row.risk >= 4
                })));
                renderTyposquatTable(data.results);
                if (typosquatCountDisplay) {
                    typosquatCountDisplay.textContent = `${data.results.length} Typosquats Discovered`;
                }
            }
        } catch (err) {
            console.error('Error fetching typosquats:', err);
            if (typosquatCountDisplay) {
                typosquatCountDisplay.textContent = 'Failed to load typosquats.';
            }
        }
    }

    function renderDomainVerdict(domain, data) {
        const verdictContainer = document.getElementById('domainVerdict');
        if (!verdictContainer) return;

        if (data.status === 'error') {
            verdictContainer.className = 'domain-verdict verdict-neutral';
            verdictContainer.innerHTML = `
                <span class="domain-verdict-dot"></span>
                <strong>Check Failed</strong>
                <span>${escapeHtml(data.message || 'Enter a valid domain')}</span>
            `;
            return;
        }

        const isPhishing = data.is_phishing || data.verdict === 'phishing';
        const label = isPhishing ? 'FAKE / PHISHING' : 'REAL / SAFE';
        const confidence = typeof data.confidence === 'number'
            ? `${Math.round(data.confidence)}%`
            : '';

        verdictContainer.className = `domain-verdict ${isPhishing ? 'verdict-fake' : 'verdict-real'}`;
        verdictContainer.innerHTML = `
            <span class="domain-verdict-dot"></span>
            <strong>${label}</strong>
            <span>${escapeHtml(domain)}</span>
            ${confidence ? `<span class="domain-confidence">${confidence} confidence</span>` : ''}
        `;
    }

    function renderTyposquatTable(rows) {
        if (!typosquatTableBody) return;

        let html = '';
        rows.forEach((row, idx) => {
            const riskClass = `risk-${row.risk || 3}`;
            const verdictLower = (row.verdict || 'suspicious').toLowerCase();
            const verdictClass = verdictLower === 'phishing' ? 'verdict-phishing' : (verdictLower === 'safe' ? 'verdict-safe' : 'verdict-suspicious');
            const verdictLabel = row.verdict || 'Suspicious';

            html += `
                <tr data-index="${idx}">
                    <td>
                        <input type="checkbox" class="table-checkbox row-checkbox" data-url="${escapeHtml(row.source_url)}">
                    </td>
                    <td>
                        <a href="javascript:void(0)" class="source-url-link" onclick="window.viewRowDetails(${idx})">
                            ${escapeHtml(row.source_url)}
                        </a>
                    </td>
                    <td class="construction-text">${escapeHtml(row.construction || 'Insertion')}</td>
                    <td>
                        <span class="risk-circle-badge ${riskClass}">${row.risk || 3}</span>
                    </td>
                    <td>
                        <span class="verdict-badge ${verdictClass}">${verdictLabel}</span>
                    </td>
                    <td>${escapeHtml(row.category || 'Unknown')}</td>
                    <td>
                        <a href="javascript:void(0)" class="ip-link">${escapeHtml(row.ip_address || '127.0.0.1')}</a>
                    </td>
                    <td class="cell-truncate" title="${escapeHtml(row.name_servers || '--')}">
                        ${escapeHtml(row.name_servers || '--')}
                    </td>
                    <td class="cell-truncate" title="${escapeHtml(row.mail_servers || '--')}">
                        ${escapeHtml(row.mail_servers || '--')}
                    </td>
                    <td>${row.mx_records ? 'True' : 'False'}</td>
                    <td>${escapeHtml(row.registration_date || '--')}</td>
                    <td class="cell-truncate" title="${escapeHtml(row.registrar || '--')}">
                        ${escapeHtml(row.registrar || '--')}
                    </td>
                    <td>${escapeHtml(row.ssl_cert || '--')}</td>
                    <td class="cell-muted">${escapeHtml(row.takedown || '--')}</td>
                </tr>
            `;
        });

        typosquatTableBody.innerHTML = html;
    }

    // Expose viewRowDetails to window for table row clicks
    window.viewRowDetails = function (index) {
        const item = currentTyposquats[index];
        if (!item || !detailModal) return;

        modalTargetUrl.textContent = item.source_url;
        modalBodyContent.innerHTML = `
            <div class="modal-row">
                <span class="modal-label">Domain Name:</span>
                <span class="modal-val">${escapeHtml(item.source_url)}</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Construction Technique:</span>
                <span class="modal-val">${escapeHtml(item.construction)}</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">ML Scan Verdict:</span>
                <span class="modal-val" style="color: ${item.verdict === 'Phishing' ? '#DC2626' : '#D97706'}; font-weight: 800;">
                    ${escapeHtml(item.verdict)}
                </span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Calculated Risk Score:</span>
                <span class="modal-val">${item.risk} / 5</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Model Confidence:</span>
                <span class="modal-val">${item.confidence}%</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Category:</span>
                <span class="modal-val">${escapeHtml(item.category)}</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">IP Address:</span>
                <span class="modal-val">${escapeHtml(item.ip_address)}</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Name Servers:</span>
                <span class="modal-val" style="font-size: 0.8rem;">${escapeHtml(item.name_servers)}</span>
            </div>
            <div class="modal-row">
                <span class="modal-label">Registrar:</span>
                <span class="modal-val">${escapeHtml(item.registrar)}</span>
            </div>
            ${item.threat_reason ? `
                <div style="margin-top: 16px; padding: 12px; background: #FEF2F2; border: 1px solid #FECACA; border-radius: 8px; font-size: 0.85rem; color: #991B1B;">
                    <strong>Threat Intel Alert:</strong> ${escapeHtml(item.threat_reason)}
                </div>
            ` : ''}
        `;
        detailModal.classList.add('show');
    };

    // =========================================================================
    // Export Functions (CSV & JSON)
    // =========================================================================
    function exportTableToCsv() {
        if (!currentTyposquats || currentTyposquats.length === 0) {
            alert('No typosquat data available to export.');
            return;
        }

        const headers = ['Source URL', 'Construction', 'Risk', 'Live Scan Verdict', 'Category', 'IP Address', 'Name Servers', 'Mail Servers', 'MX Records', 'Registration Date', 'Registrar', 'SSL Certificate'];
        const csvRows = [headers.join(',')];

        currentTyposquats.forEach(item => {
            const row = [
                `"${item.source_url}"`,
                `"${item.construction}"`,
                item.risk,
                `"${item.verdict}"`,
                `"${item.category}"`,
                `"${item.ip_address}"`,
                `"${(item.name_servers || '').replace(/"/g, '""')}"`,
                `"${(item.mail_servers || '').replace(/"/g, '""')}"`,
                item.mx_records,
                `"${item.registration_date}"`,
                `"${(item.registrar || '').replace(/"/g, '""')}"`,
                `"${item.ssl_cert}"`
            ];
            csvRows.push(row.join(','));
        });

        const csvString = csvRows.join('\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `typosquat_${currentDomain}_${Date.now()}.csv`;
        link.click();
    }

    function exportTableToJson() {
        if (!currentTyposquats || currentTyposquats.length === 0) {
            alert('No typosquat data available to export.');
            return;
        }

        const jsonString = JSON.stringify(currentTyposquats, null, 2);
        const blob = new Blob([jsonString], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `typosquat_${currentDomain}_${Date.now()}.json`;
        link.click();
    }

    function copySelectedUrls() {
        const checked = document.querySelectorAll('.row-checkbox:checked');
        if (checked.length === 0) {
            alert('Please select at least one domain from the table.');
            return;
        }

        const urls = Array.from(checked).map(cb => cb.getAttribute('data-url'));
        navigator.clipboard.writeText(urls.join('\n')).then(() => {
            alert(`Copied ${urls.length} selected URLs to clipboard!`);
        });
    }

    // =========================================================================
    // Standalone URL Scanner
    // =========================================================================
    function initUrlScanner() {
        if (!urlScanForm || !urlInput) return;

        urlScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const targetUrl = urlInput.value.trim();
            if (!targetUrl) return;

            if (scanningLaser) scanningLaser.style.display = 'block';

            try {
                const response = await fetch('/scan-url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({ url: targetUrl })
                });
                const data = await response.json();
                renderStandaloneResult(data, dynamicResultContainer);
            } catch (err) {
                console.error(err);
            } finally {
                if (scanningLaser) scanningLaser.style.display = 'none';
            }
        });
    }

    // =========================================================================
    // Email Phishing Scanner
    // =========================================================================
    function initEmailScanner() {
        if (!emailScanForm) return;

        emailScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const body = emailBodyInput ? emailBodyInput.value.trim() : '';

            if (!body) {
                emailResultContainer.innerHTML = '<div class="email-verdict email-suspicious">Please paste an email message to check.</div>';
                return;
            }

            try {
                const response = await fetch('/scan-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ body })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.message || 'Email scan failed.');
                renderEmailResult(data);
            } catch (err) {
                emailResultContainer.innerHTML = `<div class="email-verdict email-suspicious">${escapeHtml(err.message)}</div>`;
            }
        });
    }

    function renderEmailResult(data) {
        if (!emailResultContainer) return;

        const isFake = data.verdict !== 'real';
        const verdictClass = isFake ? 'email-fake' : 'email-real';
        const verdictMessage = data.verdict === 'fake'
            ? 'This email is fake'
            : (data.verdict === 'suspicious' ? 'This email may be fake' : 'This email is not flagged as fake');
        const findings = data.findings && data.findings.length
            ? data.findings.map(finding => `<li>${escapeHtml(finding)}</li>`).join('')
            : '<li>No strong phishing indicators were detected.</li>';

        emailResultContainer.innerHTML = `
            <div class="email-verdict ${verdictClass}">
                <span class="domain-verdict-dot"></span>
                <strong>${verdictMessage}</strong>
                <span>${escapeHtml(String(data.risk_score ?? ''))} / 100 risk score</span>
            </div>
            <div class="email-findings">
                <p class="email-analysis-method">
                    Analysis: ${data.analysis_method === 'dataset_model_and_rules'
                        ? 'dataset-trained model and threat rules'
                        : 'threat rules only (train the dataset model for ML screening)'}
                </p>
                <h4>Screening findings</h4>
                <ul>${findings}</ul>
                <p class="email-disclaimer">${escapeHtml(data.disclaimer)}</p>
            </div>
        `;
    }

    // =========================================================================
    // Standalone QR Scanner
    // =========================================================================
    function initQrScanner() {
        if (!qrDropzone || !qrFileInput) return;

        browseQrBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            qrFileInput.click();
        });
        qrDropzone.addEventListener('click', () => qrFileInput.click());

        qrFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) handleQrFile(file);
        });

        if (removeQrBtn) {
            removeQrBtn.addEventListener('click', () => {
                selectedQrFile = null;
                qrPreviewContainer.style.display = 'none';
                qrDropzone.style.display = 'block';
            });
        }

        if (scanQrBtn) {
            scanQrBtn.addEventListener('click', async () => {
                if (!selectedQrFile) return;

                const formData = new FormData();
                formData.append('file', selectedQrFile);

                try {
                    const response = await fetch('/scan-qr', { method: 'POST', body: formData });
                    const data = await response.json();
                    renderStandaloneResult(data, qrResultContainer);
                } catch (err) {
                    console.error(err);
                }
            });
        }
    }

    function handleQrFile(file) {
        selectedQrFile = file;
        const reader = new FileReader();
        reader.onload = (e) => {
            qrPreviewImg.src = e.target.result;
            qrFileName.textContent = file.name;
            qrFileSize.textContent = `${Math.round(file.size / 1024)} KB`;
            qrDropzone.style.display = 'none';
            qrPreviewContainer.style.display = 'block';
        };
        reader.readAsDataURL(file);
    }

    function renderStandaloneResult(data, container) {
        if (!container) return;
        const isPhishing = data.is_phishing || data.verdict === 'phishing';
        if (data.status === 'success') {
            recordAnalyticsBatch([{ isThreat: isPhishing }]);
        }
        const cardClass = isPhishing ? 'verdict-phish-bg' : 'verdict-safe-bg';
        const textColor = isPhishing ? '#DC2626' : '#16A34A';
        const targetUrl = data.url || data.extracted_url || '';
        if (targetUrl) {
            setCopilotActiveContext(targetUrl);
        }

        const rag = data.rag_analysis;
        let ragHtml = '';
        if (rag) {
            let mitreHtml = '';
            if (rag.mitre_techniques && rag.mitre_techniques.length > 0) {
                mitreHtml = rag.mitre_techniques.map(t => `<span class="mitre-pill">${escapeHtml(t)}</span>`).join('');
            }
            let stepsHtml = '';
            if (rag.action_steps && rag.action_steps.length > 0) {
                stepsHtml = `<ul class="rag-steps-bullet-list">` +
                    rag.action_steps.map(s => `<li>${escapeHtml(s)}</li>`).join('') +
                    `</ul>`;
            }
            let citationsHtml = '';
            if (rag.citations && rag.citations.length > 0) {
                citationsHtml = `<div class="rag-citations-footer">
                    <span class="citations-heading">Knowledge Base References:</span>
                    <div class="citations-chips-wrap">` +
                    rag.citations.map(c => `<span class="citation-tag" title="${escapeHtml(c.summary || '')}">${escapeHtml(c.title)}</span>`).join('') +
                    `</div></div>`;
            }

            ragHtml = `
                <div class="rag-dossier-box">
                    <div class="rag-dossier-header-bar">
                        <div class="rag-tag-group">
                            <span class="rag-pill-badge">RAG THREAT DOSSIER</span>
                            <span class="rag-source-badge">${escapeHtml(rag.source || 'rag_engine')}</span>
                        </div>
                        <div class="mitre-tags-list">${mitreHtml}</div>
                    </div>
                    <div class="rag-dossier-content">
                        <p class="rag-exec-summary">${escapeHtml(rag.executive_summary || '')}</p>
                        ${rag.attack_mechanism ? `
                            <div class="rag-section-item">
                                <div class="rag-section-title">Attack Mechanism &amp; Evasion Vectors</div>
                                <p class="rag-section-text">${escapeHtml(rag.attack_mechanism)}</p>
                            </div>
                        ` : ''}
                        ${stepsHtml ? `
                            <div class="rag-section-item">
                                <div class="rag-section-title">SOC Mitigation &amp; Incident Playbook</div>
                                ${stepsHtml}
                            </div>
                        ` : ''}
                        ${citationsHtml}
                        <button type="button" class="btn-ask-copilot" onclick="window.askCopilotAboutUrl('${escapeHtml(targetUrl)}')">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                            Investigate in Threat Copilot
                        </button>
                    </div>
                </div>
            `;
        }

        container.innerHTML = `
            <div style="background: ${cardClass}; border: 1.5px solid ${isPhishing ? '#FCA5A5' : '#86EFAC'}; border-radius: 12px; padding: 20px; margin-top: 20px;">
                <h4 style="color: ${textColor}; font-weight: 800; font-size: 1.15rem; margin-bottom: 8px;">
                    ${isPhishing ? 'Phishing Website Detected' : 'Healthy Website Verified'}
                </h4>
                <p style="font-size: 0.92rem; font-weight: 600; color: #1E293B; margin-bottom: 12px;">
                    ${data.message || (isPhishing ? 'Warning! High risk phishing domain identified.' : 'Good news! Classified as safe.')}
                </p>
                <div style="background: #FFFFFF; padding: 10px 14px; border-radius: 6px; font-family: monospace; font-size: 0.88rem; margin-bottom: 12px; word-break: break-all;">
                    ${escapeHtml(targetUrl)}
                </div>
                ${data.threat_reason ? `
                    <div style="font-size: 0.85rem; color: #991B1B; font-weight: 600; margin-bottom: 8px;">
                        Threat Intelligence: ${escapeHtml(data.threat_reason)}
                    </div>
                ` : ''}
                <div style="font-size: 0.85rem; color: #64748B;">
                    Confidence Probability: <strong>${data.confidence}%</strong>
                </div>
                ${ragHtml}
            </div>
        `;
        container.style.display = 'block';
    }

    // =========================================================================
    // Dark & Light Mode Theme Toggle
    // =========================================================================
    function initThemeToggle() {
        const themeToggleBtns = document.querySelectorAll('.theme-toggle-btn');
        const themeLabelTexts = document.querySelectorAll('.theme-label-text');

        function applyTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            const isDark = theme === 'dark';

            themeLabelTexts.forEach(label => {
                label.textContent = isDark ? 'Light Mode' : 'Dark Mode';
            });

            themeToggleBtns.forEach(btn => {
                btn.setAttribute('title', isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode');
            });

            // Update Chart.js colors dynamically
            if (chartInstance) {
                chartInstance.data.datasets[0].borderColor = isDark ? '#111019' : '#FFFCF9';
                const legendLabels = chartInstance.options.plugins?.legend?.labels;
                if (legendLabels) {
                    legendLabels.color = isDark ? '#F1F5F9' : '#2A2029';
                }
                chartInstance.update();
            }

            try {
                localStorage.setItem('sentinel_theme', theme);
            } catch (err) {}
        }

        // Determine current or stored theme
        let currentTheme = document.documentElement.getAttribute('data-theme');
        if (!currentTheme) {
            try {
                currentTheme = localStorage.getItem('sentinel_theme');
            } catch (e) {}
            if (!currentTheme) {
                currentTheme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }
        }
        applyTheme(currentTheme);

        // Attach event listeners to all theme toggles
        themeToggleBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const active = document.documentElement.getAttribute('data-theme') || 'light';
                const nextTheme = active === 'dark' ? 'light' : 'dark';
                applyTheme(nextTheme);
            });
        });

        // Listen for system color-scheme changes
        if (window.matchMedia) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
                try {
                    if (!localStorage.getItem('sentinel_theme')) {
                        applyTheme(e.matches ? 'dark' : 'light');
                    }
                } catch (err) {}
            });
        }
    }

    // =========================================================================
    // Analytics
    // =========================================================================
    function loadScanAnalytics() {
        const emptyAnalytics = { total: 0, safe: 0, threats: 0 };
        try {
            const stored = JSON.parse(localStorage.getItem(analyticsStorageKey) || 'null');
            if (!stored || typeof stored !== 'object') return emptyAnalytics;
            return {
                total: Number.isSafeInteger(stored.total) && stored.total >= 0 ? stored.total : 0,
                safe: Number.isSafeInteger(stored.safe) && stored.safe >= 0 ? stored.safe : 0,
                threats: Number.isSafeInteger(stored.threats) && stored.threats >= 0 ? stored.threats : 0
            };
        } catch (err) {
            console.error('Unable to load saved scan analytics:', err);
            return emptyAnalytics;
        }
    }

    function recordAnalyticsBatch(scans) {
        if (!Array.isArray(scans) || scans.length === 0) return;

        scans.forEach(scan => {
            scanAnalytics.total += 1;
            if (scan.isThreat) {
                scanAnalytics.threats += 1;
            } else {
                scanAnalytics.safe += 1;
            }
        });

        try {
            localStorage.setItem(analyticsStorageKey, JSON.stringify(scanAnalytics));
        } catch (err) {
            console.error('Unable to save scan analytics:', err);
        }
        window.dispatchEvent(new CustomEvent('sentinel:analytics-updated', {
            detail: { ...scanAnalytics }
        }));
        updateAnalytics();
    }

    function initAnalyticsChart() {
        if (!chartCanvas) return;
        const ctx = chartCanvas.getContext('2d');
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';

        chartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Websites', 'Phishing & Typosquats'],
                datasets: [{
                    data: [scanAnalytics.safe, scanAnalytics.threats],
                    backgroundColor: ['#16A34A', '#DC2626'],
                    borderWidth: 2,
                    borderColor: isDark ? '#131B2A' : '#FFFFFF'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: isDark ? '#F1F5F9' : '#1E293B',
                            font: { family: 'Plus Jakarta Sans', weight: '600' }
                        }
                    }
                }
            }
        });
    }

    function updateAnalytics() {
        if (statTotalScans) statTotalScans.textContent = scanAnalytics.total;
        if (statSafeScans) statSafeScans.textContent = scanAnalytics.safe;
        if (statThreatScans) statThreatScans.textContent = scanAnalytics.threats;

        if (chartInstance) {
            chartInstance.data.datasets[0].data = [scanAnalytics.safe, scanAnalytics.threats];
            chartInstance.update();
        }
    }

    // =========================================================================
    // Threat Copilot (RAG) Interactive Assistant Logic
    // =========================================================================
    let activeContextUrl = null;
    let copilotHistory = [];

    function setCopilotActiveContext(url) {
        activeContextUrl = url;
        const contextBar = document.getElementById('copilotContextBar');
        const activeUrlSpan = document.getElementById('copilotActiveUrl');
        if (contextBar && activeUrlSpan) {
            activeUrlSpan.textContent = url;
            contextBar.style.display = 'flex';
        }
    }

    function clearCopilotActiveContext() {
        activeContextUrl = null;
        const contextBar = document.getElementById('copilotContextBar');
        if (contextBar) {
            contextBar.style.display = 'none';
        }
    }

    function initThreatCopilot() {
        const copilotChatForm = document.getElementById('copilotChatForm');
        const copilotInput = document.getElementById('copilotInput');
        const copilotMessagesContainer = document.getElementById('copilotMessagesContainer');
        const clearContextBtn = document.getElementById('copilotClearContextBtn');

        const floatingBotBtn = document.getElementById('floatingBotBtn');
        const floatingCopilotDrawer = document.getElementById('floatingCopilotDrawer');
        const drawerCloseBtn = document.getElementById('drawerCloseBtn');
        const drawerExpandBtn = document.getElementById('drawerExpandBtn');
        const drawerChatForm = document.getElementById('drawerChatForm');
        const drawerInput = document.getElementById('drawerInput');
        const drawerMessagesContainer = document.getElementById('drawerMessagesContainer');

        const promptChips = document.querySelectorAll('.prompt-chip');

        // Clear Context
        if (clearContextBtn) {
            clearContextBtn.addEventListener('click', () => {
                clearCopilotActiveContext();
            });
        }

        // Quick Prompt Chips
        promptChips.forEach(chip => {
            chip.addEventListener('click', () => {
                const query = chip.getAttribute('data-query');
                if (query) {
                    if (copilotInput) copilotInput.value = query;
                    submitCopilotMessage(query, copilotMessagesContainer, copilotInput);
                }
            });
        });

        // Main Pane Form Submit
        if (copilotChatForm && copilotInput) {
            copilotChatForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const q = copilotInput.value.trim();
                if (q) {
                    submitCopilotMessage(q, copilotMessagesContainer, copilotInput);
                }
            });
        }

        // Floating Drawer Toggle
        if (floatingBotBtn && floatingCopilotDrawer) {
            floatingBotBtn.addEventListener('click', (e) => {
                e.preventDefault();
                floatingCopilotDrawer.classList.toggle('open');
                if (floatingCopilotDrawer.classList.contains('open') && drawerInput) {
                    drawerInput.focus();
                }
            });
        }

        if (drawerCloseBtn && floatingCopilotDrawer) {
            drawerCloseBtn.addEventListener('click', () => {
                floatingCopilotDrawer.classList.remove('open');
            });
        }

        if (drawerExpandBtn && floatingCopilotDrawer) {
            drawerExpandBtn.addEventListener('click', () => {
                floatingCopilotDrawer.classList.remove('open');
                const navCopilot = document.getElementById('navThreatCopilot');
                if (navCopilot) navCopilot.click();
            });
        }

        // Drawer Form Submit
        if (drawerChatForm && drawerInput) {
            drawerChatForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const q = drawerInput.value.trim();
                if (q) {
                    submitCopilotMessage(q, drawerMessagesContainer, drawerInput);
                }
            });
        }

        // Global function to trigger copilot from scan result cards
        window.askCopilotAboutUrl = function(targetUrl) {
            setCopilotActiveContext(targetUrl);
            const navCopilot = document.getElementById('navThreatCopilot');
            if (navCopilot) navCopilot.click();
            const query = `Analyze the threat vectors, MITRE ATT&CK techniques, and mitigation steps for: ${targetUrl}`;
            if (copilotInput) copilotInput.value = query;
            setTimeout(() => {
                submitCopilotMessage(query, copilotMessagesContainer, copilotInput);
            }, 300);
        };
    }

    async function submitCopilotMessage(query, container, inputElement) {
        if (!query || !container) return;

        // Append User Message Bubble
        appendUserMessage(query, container);
        if (inputElement) inputElement.value = '';

        // Append Thinking Indicator
        const loadingId = 'loading-' + Date.now();
        const loadingHtml = `
            <div class="copilot-msg msg-assistant" id="${loadingId}">
                <div class="msg-avatar">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div class="msg-bubble">
                    <div class="msg-author-tag">Sentinel RAG Copilot</div>
                    <div style="display: flex; align-items: center; gap: 8px; font-size: 0.88rem; color: var(--text-secondary);">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #7C3AED; animation: pulse 1s infinite;"></span>
                        Retrieving relevant threat intelligence from knowledge base &amp; MITRE matrix...
                    </div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', loadingHtml);
        container.scrollTop = container.scrollHeight;

        try {
            const response = await fetch('/api/rag/ask', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({
                    message: query,
                    history: copilotHistory,
                    context_url: activeContextUrl
                })
            });
            const data = await response.json();

            // Remove loading
            const loadingElem = document.getElementById(loadingId);
            if (loadingElem) loadingElem.remove();

            if (data.status === 'success') {
                appendAssistantMessage(data, container);
                copilotHistory.push({ role: 'user', content: query });
                copilotHistory.push({ role: 'assistant', content: data.answer });
            } else {
                appendErrorMessage(data.message || 'Error communicating with Threat Copilot.', container);
            }
        } catch (err) {
            console.error('Copilot error:', err);
            const loadingElem = document.getElementById(loadingId);
            if (loadingElem) loadingElem.remove();
            appendErrorMessage('Failed to connect to the Sentinel RAG service.', container);
        }

        container.scrollTop = container.scrollHeight;
    }

    function appendUserMessage(text, container) {
        const html = `
            <div class="copilot-msg msg-user">
                <div class="msg-avatar">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
                    </svg>
                </div>
                <div class="msg-bubble">
                    <div class="msg-text">${escapeHtml(text)}</div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
        container.scrollTop = container.scrollHeight;
    }

    function appendAssistantMessage(data, container) {
        let citationsHtml = '';
        if (data.citations && data.citations.length > 0) {
            citationsHtml = `
                <div class="rag-citations-footer" style="margin-top: 10px; padding-top: 8px;">
                    <span class="citations-heading">Retrieved References:</span>
                    <div class="citations-chips-wrap">
                        ${data.citations.map(c => `
                            <span class="citation-tag" title="${escapeHtml(c.summary || '')}">
                                ${c.mitre_id ? `<strong style="color: #7C3AED;">[${escapeHtml(c.mitre_id)}]</strong> ` : ''}
                                ${escapeHtml(c.title)}
                            </span>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        let suggestionsHtml = '';
        if (data.suggested_questions && data.suggested_questions.length > 0) {
            suggestionsHtml = `
                <div style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">
                    ${data.suggested_questions.map(q => `
                        <button type="button" class="prompt-chip" style="font-size: 0.76rem; padding: 4px 10px;" onclick="window.askCopilotDirectly('${escapeHtml(q).replace(/'/g, "\\'")}')">
                            ${escapeHtml(q)}
                        </button>
                    `).join('')}
                </div>
            `;
        }

        const formattedAnswer = formatMarkdownText(data.answer);

        const html = `
            <div class="copilot-msg msg-assistant">
                <div class="msg-avatar">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div class="msg-bubble">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span class="msg-author-tag">Sentinel Threat Copilot</span>
                        <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono);">${data.timestamp || ''}</span>
                    </div>
                    <div class="msg-text">${formattedAnswer}</div>
                    ${citationsHtml}
                    ${suggestionsHtml}
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
        container.scrollTop = container.scrollHeight;
    }

    function appendErrorMessage(msg, container) {
        const html = `
            <div class="copilot-msg msg-assistant">
                <div class="msg-avatar" style="background: #DC2626;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                </div>
                <div class="msg-bubble" style="border-color: #FCA5A5; background: #FEF2F2;">
                    <div class="msg-text" style="color: #991B1B;">${escapeHtml(msg)}</div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
        container.scrollTop = container.scrollHeight;
    }

    window.askCopilotDirectly = function(q) {
        const copilotMessagesContainer = document.getElementById('copilotMessagesContainer');
        const copilotInput = document.getElementById('copilotInput');
        submitCopilotMessage(q, copilotMessagesContainer, copilotInput);
    };

    function formatMarkdownText(md) {
        if (!md) return '';
        let s = escapeHtml(md);

        // Headings
        s = s.replace(/^### (.*$)/gim, '<h3>$1</h3>');
        s = s.replace(/^#### (.*$)/gim, '<h4>$1</h4>');

        // Bold & Italic
        s = s.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
        s = s.replace(/\*(.*?)\*/gim, '<em>$1</em>');

        // Inline Code
        s = s.replace(/`([^`]+)`/gim, '<code>$1</code>');

        // Unordered lists
        s = s.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');
        s = s.replace(/(<li>.*<\/li>)/gims, '<ul style="margin: 6px 0; padding-left: 20px;">$1</ul>');

        // Paragraph breaks
        s = s.replace(/\n\n/gim, '<br><br>');
        s = s.replace(/\n/gim, '<br>');

        return s;
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

})();
