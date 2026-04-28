document.addEventListener("DOMContentLoaded", () => {
    // Load data immediately, then auto-refresh every 3 seconds
    loadData();
    setInterval(loadData, 3000);

    // Backend health check
    checkHealth();
    setInterval(checkHealth, 10000);

    // Global threat intelligence ticker (load once)
    loadThreatFeed();
});

function loadData() {
    const totalEl = document.getElementById("total");
    const blockedEl = document.getElementById("blocked");
    const safeEl = document.getElementById("safe");
    const historyContainer = document.getElementById("history");

    chrome.storage.local.get(["pg_history"], (data) => {
        const history = data.pg_history || [];

        // ── Update stat counters ──────────────────────────────────────
        const blocked = history.filter(
            (e) => e.action === "BLOCK" || e.action === "WARN"
        ).length;
        const safe = history.filter((e) => e.action === "ALLOW").length;

        totalEl.textContent = history.length;
        blockedEl.textContent = blocked;
        safeEl.textContent = safe;

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
