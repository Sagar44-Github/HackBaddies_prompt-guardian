document.addEventListener("DOMContentLoaded", () => {
    // Load data immediately, then auto-refresh every 3 seconds
    loadData();
    setInterval(loadData, 3000);

    // Backend health check
    checkHealth();
    setInterval(checkHealth, 10000);

    // Global threat intelligence ticker (load once)
    loadThreatFeed();

    // ── HONEYPOT MODE INITIALIZATION ─────────────────────────────────────
    initHoneypotMode();

    const miniOpenDashboard = document.getElementById("mini-open-dashboard");
    if (miniOpenDashboard) {
        miniOpenDashboard.addEventListener("click", () => {
            chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
        });
    }
});

function loadData() {
    const totalEl = document.getElementById("total");
    const blockedEl = document.getElementById("blocked");
    const safeEl = document.getElementById("safe");
    const multilingualEl = document.getElementById("multilingual");
    const historyContainer = document.getElementById("history");

    chrome.storage.local.get(["pg_history"], (data) => {
        const history = data.pg_history || [];

        // ── Update stat counters ──────────────────────────────────────
        const blocked = history.filter(
            (e) => e.action === "BLOCK" || e.action === "WARN"
        ).length;
        const safe = history.filter((e) => e.action === "ALLOW").length;
        const multilingualCount = history.filter((e) => (e?.is_multilingual_attack ?? false) === true).length;

        totalEl.textContent = history.length;
        blockedEl.textContent = blocked;
        safeEl.textContent = safe;
        if (multilingualEl) multilingualEl.textContent = multilingualCount;

        // ── Mini Attack Breakdown Chart ───────────────────────────────────
        // Build attack type frequency from non-ALLOW entries
        const attackCounts = {};
        history.forEach(e => {
            if (e.action === 'ALLOW') return;
            const type = e.attack_type;
            if (!type || type === 'Unknown' || type === 'None') return;
            const label = type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            attackCounts[label] = (attackCounts[label] || 0) + 1;
        });
        const chartData = Object.entries(attackCounts)
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count);

        if (typeof window.renderAttackChart === 'function') {
            window.renderAttackChart('mini-chart-container', chartData, {
                size: 120,
                mode: 'compact',
                showCenterText: true,
                animationDuration: 700,
            });
        }

        // ── Session Timeline Preview ───────────────────────────────────────
        renderMiniTimeline(history);

        // ── Render history entries ────────────────────────────────────
        if (history.length === 0) {
            historyContainer.innerHTML = `
                <div class="empty-msg">
                    No recent prompts analyzed yet.<br>
                    Visit ChatGPT and start chatting!
                </div>`;
            return;
        }

        historyContainer.innerHTML = "";

        // Show last 20 entries
        history.slice(0, 20).forEach((entry) => {
            const div = document.createElement("div");

            let cls = "safe";
            if (entry.action === "BLOCK") cls = "danger";
            else if (entry.action === "WARN") cls = "warn";

            div.className = `entry ${cls}`;

            const timeAgo = formatTimeAgo(entry.timestamp);

            const attackLabel =
                entry.attack_type && entry.attack_type !== "Unknown"
                    ? entry.attack_type
                    : entry.action === "ALLOW"
                    ? "Safe"
                    : "Suspicious";

            div.innerHTML = `
                <div class="entry-top">
                    <span class="score">${entry.risk_score || 0}% — ${attackLabel}</span>
                    <span class="time">${timeAgo}</span>
                </div>
                <div class="prompt-snip">${escapeHtml(entry.prompt || "")}</div>
            `;

            historyContainer.appendChild(div);
        });
    });
}

// ── MINI TIMELINE PREVIEW ───────────────────────────────────────────────────
function renderMiniTimeline(history) {
    const container = document.getElementById("mini-timeline-container");
    if (!container) return;
    container.innerHTML = "";

    if (!history || history.length === 0) {
        const empty = document.createElement("div");
        empty.textContent = "No events";
        empty.style.position = "absolute";
        empty.style.left = "50%";
        empty.style.top = "50%";
        empty.style.transform = "translate(-50%, -50%)";
        empty.style.color = "#64748B";
        empty.style.fontSize = "10px";
        container.appendChild(empty);
        return;
    }

    const centerLine = document.createElement("div");
    centerLine.style.position = "absolute";
    centerLine.style.left = "0";
    centerLine.style.top = "50%";
    centerLine.style.width = "100%";
    centerLine.style.height = "1px";
    centerLine.style.background = "#334155";
    centerLine.style.transform = "translateY(-50%)";
    container.appendChild(centerLine);

    const chronological = [...history].reverse();
    const startTime = new Date(chronological[0].timestamp).getTime();
    const endTime = new Date(chronological[chronological.length - 1].timestamp).getTime();
    const duration = endTime - startTime;
    const width = container.clientWidth || 348;

    chronological.forEach((event, idx) => {
        let x;
        if (duration === 0) {
            const step = chronological.length > 1 ? (width - 8) / (chronological.length - 1) : width / 2;
            x = chronological.length > 1 ? idx * step : step;
        } else {
            const eventTime = new Date(event.timestamp).getTime();
            x = ((eventTime - startTime) / duration) * (width - 8);
        }

        const dot = document.createElement("div");
        dot.style.position = "absolute";
        dot.style.width = "6px";
        dot.style.height = "6px";
        dot.style.borderRadius = "50%";
        dot.style.top = "50%";
        dot.style.transform = "translateY(-50%)";
        dot.style.left = `${Math.max(0, Math.min(width - 8, x))}px`;
        dot.style.background =
            event.action === "BLOCK" ? "#EF4444" :
            event.action === "WARN" ? "#F59E0B" :
            "#10B981";
        container.appendChild(dot);
    });
}

function checkHealth() {
    const statusDot = document.querySelector(".status-dot");
    const footerEl = document.querySelector(".footer");

    fetch("http://127.0.0.1:5000/health")
        .then((res) => res.json())
        .then((data) => {
            if (data.status === "ok") {
                statusDot.style.background = "#10B981";
                statusDot.style.boxShadow = "0 0 12px rgba(16,185,129,0.55)";
                footerEl.innerHTML = `<span class="status-dot" style="background:#10B981;display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle;box-shadow:0 0 12px rgba(16,185,129,0.55)"></span> Backend: online`;
            }
        })
        .catch(() => {
            statusDot.style.background = "#EF4444";
            statusDot.style.boxShadow = "0 0 12px rgba(239,68,68,0.55)";
            footerEl.innerHTML = `<span class="status-dot" style="background:#EF4444;display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle;box-shadow:0 0 12px rgba(239,68,68,0.55)"></span> Backend: offline`;
        });
}

// ── Helpers ───────────────────────────────────────────────────────────

function formatTimeAgo(isoString) {
    if (!isoString) return "";

    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffMs = now - then;

    const seconds = Math.floor(diffMs / 1000);
    if (seconds < 60) return "Just now";

    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + "m ago";

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + "h ago";

    const days = Math.floor(hours / 24);
    return days + "d ago";
}

function escapeHtml(str) {
    return (str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

// ── RELATIVE TIME HELPER ───────────────────────────────────────────────────────
function getRelativeTime(isoString) {
    if (!isoString) return '';
    const diffSec = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diffSec < 3600)  return Math.max(1, Math.floor(diffSec / 60)) + 'm ago';
    if (diffSec < 86400) return Math.floor(diffSec / 3600) + 'h ago';
    return Math.floor(diffSec / 86400) + 'd ago';
}

// ── THREAT FEED TICKER ────────────────────────────────────────────────────────────
function loadThreatFeed() {
    const ticker = document.getElementById('threat-ticker-scroll');
    if (!ticker) return;

    fetch('http://127.0.0.1:5000/threat-feed')
        .then(res => res.json())
        .then(data => {
            const feed = data.feed || [];
            if (feed.length === 0) throw new Error('empty feed');

            // Build ticker items HTML
            const itemsHtml = feed.map(t => `
                <div class="ticker-item">
                    <span class="ticker-severity ${t.severity}">${t.severity}</span>
                    <span class="ticker-title">${escapeHtml(t.title)}</span>
                    <span class="ticker-time">${getRelativeTime(t.discovered_at)}</span>
                </div>
            `).join('');

            // Duplicate content for seamless infinite scroll loop
            ticker.innerHTML = itemsHtml + itemsHtml;
        })
        .catch(() => {
            ticker.innerHTML = `
                <div class="ticker-item" style="color:#475569;text-align:center;padding:16px;">
                    ⚠️ Feed offline — backend not reachable
                </div>`;
        });
}

// ── EXPORT FORENSIC REPORT ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const exportBtn = document.getElementById('export-report-btn');
    if (!exportBtn) return;

    exportBtn.addEventListener('click', async () => {
        const originalText = exportBtn.textContent;
        exportBtn.disabled = true;
        exportBtn.textContent = '⏳ Generating Report...';

        try {
            // 1. Read session history from chrome.storage
            const stored = await new Promise(resolve =>
                chrome.storage.local.get(['pg_history'], resolve)
            );
            const history = stored.pg_history || [];

            // 2. POST to backend /generate-report
            const res = await fetch('http://127.0.0.1:5000/generate-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ history }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const reportData = await res.json();

            // 3. Store report in chrome.storage for report.html to read
            await new Promise(resolve =>
                chrome.storage.local.set({ pg_report_data: reportData }, resolve)
            );

            // 4. Open report.html in a new tab
            chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });

        } catch (err) {
            alert('Report generation failed. Make sure the backend is running on localhost:5000.\n\nError: ' + err.message);
        } finally {
            setTimeout(() => {
                exportBtn.disabled = false;
                exportBtn.textContent = originalText;
            }, 2000);
        }
    });
});

// ── HONEYPOT MODE STATE MANAGEMENT ────────────────────────────────────────────
function initHoneypotMode() {
    const toggle = document.getElementById('honeypot-toggle');
    const statusEl = document.getElementById('honeypot-status');
    const countEl = document.getElementById('honeypot-count');
    const sectionEl = document.getElementById('honeypot-section');
    
    if (!toggle || !statusEl || !countEl || !sectionEl) return;

    // Read honeypot mode state from storage
    chrome.storage.local.get(['honeypot_mode', 'pg_history'], (data) => {
        const isHoneypot = data.honeypot_mode || false;
        const history = data.pg_history || [];

        // Set toggle state
        toggle.checked = isHoneypot;

        // Update status text
        updateHoneypotStatus(isHoneypot, statusEl, sectionEl);

        // Count honeypot events from history
        const honeypotCount = history.filter(e => e.user_action === 'honeypot-tracked' || e.honeypot === true).length;
        countEl.textContent = `Honeypot events this session: ${honeypotCount}`;
    });

    // Toggle event listener
    toggle.addEventListener('change', () => {
        const newState = toggle.checked;
        
        // Save to storage
        chrome.storage.local.set({ honeypot_mode: newState });

        // Update UI immediately
        updateHoneypotStatus(newState, statusEl, sectionEl);

        // If turning ON, show brief confirmation
        if (newState) {
            const originalText = statusEl.textContent;
            statusEl.textContent = '✅ Honeypot Mode activated';
            statusEl.classList.add('active');
            sectionEl.classList.add('active');
            
            setTimeout(() => {
                updateHoneypotStatus(true, statusEl, sectionEl);
            }, 1000);
        } else {
            sectionEl.classList.remove('active');
        }
    });
}

function updateHoneypotStatus(isActive, statusEl, sectionEl) {
    if (isActive) {
        statusEl.textContent = '⚠️ Research Mode — Threats logged but allowed through';
        statusEl.classList.add('active');
        sectionEl.classList.add('active');
    } else {
        statusEl.textContent = '🔒 Normal Protection — Threats are blocked';
        statusEl.classList.remove('active');
        sectionEl.classList.remove('active');
    }
}
