(function () {
    'use strict';

    if (!window.React || !window.ReactDOM) {
        console.error('Security Pulse could not start because React did not load.');
        return;
    }

    const { createElement: h, useEffect, useState } = window.React;
    const analyticsStorageKey = 'sentinel_scan_analytics_v1';
    const emptyStats = { total: 0, safe: 0, threats: 0 };

    function readStats() {
        try {
            const stored = JSON.parse(localStorage.getItem(analyticsStorageKey) || 'null');
            if (!stored || typeof stored !== 'object') return emptyStats;
            return {
                total: Number.isSafeInteger(stored.total) && stored.total >= 0 ? stored.total : 0,
                safe: Number.isSafeInteger(stored.safe) && stored.safe >= 0 ? stored.safe : 0,
                threats: Number.isSafeInteger(stored.threats) && stored.threats >= 0 ? stored.threats : 0
            };
        } catch (error) {
            console.error('Security Pulse could not read saved analytics:', error);
            return emptyStats;
        }
    }

    function SecurityPulse() {
        const [stats, setStats] = useState(readStats);

        useEffect(() => {
            const refresh = () => setStats(readStats());
            const onStorage = event => {
                if (event.key === analyticsStorageKey) refresh();
            };

            window.addEventListener('sentinel:analytics-updated', refresh);
            window.addEventListener('storage', onStorage);
            return () => {
                window.removeEventListener('sentinel:analytics-updated', refresh);
                window.removeEventListener('storage', onStorage);
            };
        }, []);

        const hasThreats = stats.threats > 0;
        const threatRate = stats.total > 0
            ? Math.round((stats.threats / stats.total) * 100)
            : 0;
        const statusText = hasThreats
            ? 'Threats detected — review your scans'
            : (stats.total > 0 ? 'No threats detected in your scans' : 'Ready for your first scan');

        return h('section', {
            className: `security-pulse-card${hasThreats ? ' has-threats' : ''}`,
            'aria-live': 'polite'
        },
        h('div', { className: 'security-pulse-copy' },
            h('div', { className: 'security-pulse-kicker' },
                h('span', { className: 'security-pulse-live-dot' }),
                'SECURITY PULSE'
            ),
            h('h3', { className: 'security-pulse-title' }, statusText),
            h('p', { className: 'security-pulse-description' },
                `${stats.total.toLocaleString()} domain scans tracked in this browser.`
            ),
            h('div', { className: 'security-pulse-meter-row' },
                h('span', null, 'Threat share'),
                h('strong', null, `${threatRate}%`)
            ),
            h('div', {
                className: 'security-pulse-meter',
                role: 'meter',
                'aria-label': 'Threat share',
                'aria-valuemin': 0,
                'aria-valuemax': 100,
                'aria-valuenow': threatRate
            }, h('span', { style: { width: `${threatRate}%` } })),
            h('button', {
                type: 'button',
                className: 'security-pulse-action',
                onClick: () => {
                    const scannerLink = document.getElementById('navUrlScanner');
                    if (scannerLink) scannerLink.click();
                }
            }, 'Scan a website')
        ),
        h('div', { className: 'security-pulse-orb', 'aria-hidden': 'true' },
            h('span', { className: 'security-pulse-orbit orbit-outer' }),
            h('span', { className: 'security-pulse-orbit orbit-inner' }),
            h('div', { className: 'security-pulse-orb-center' },
                h('svg', {
                    width: 34,
                    height: 34,
                    viewBox: '0 0 24 24',
                    fill: 'none',
                    stroke: 'currentColor',
                    strokeWidth: 1.7,
                    strokeLinecap: 'round',
                    strokeLinejoin: 'round'
                },
                h('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }),
                h('path', { d: 'm9 12 2 2 4-4' }))
            )
        ));
    }

    const rootElement = document.getElementById('securityPulseRoot');
    if (rootElement) {
        window.ReactDOM.createRoot(rootElement).render(h(SecurityPulse));
    }
})();
