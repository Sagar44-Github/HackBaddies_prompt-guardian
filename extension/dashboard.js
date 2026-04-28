/**
 * dashboard.js — Prompt Guardian Threat Intelligence Center
 * Reads pg_history from chrome.storage.local and renders full analytics.
 */

// ── COLOR PALETTE FOR ATTACK TYPES ──────────────────────────────────────────
const ATTACK_COLORS = {
  jailbreak: "#EF4444",
  instruction_override: "#F59E0B",
  prompt_extraction: "#3B82F6",
  data_extraction: "#8B5CF6",
  role_override: "#EC4899",
  encoded_injection: "#06B6D4",
  indirect_injection: "#F97316",
  social_engineering: "#84CC16",
  privilege_escalation: "#A78BFA",
  harmful_content: "#FB7185",
  other: "#64748B",
};

// Normalize attack type key
function normalizeKey(type) {
  if (!type || type === "Unknown" || type === "None") return null;
  return type.toLowerCase().replace(/\s+/g, "_");
}

// Get color for attack type
function colorFor(type) {
  const k = normalizeKey(type);
  return k && ATTACK_COLORS[k] ? ATTACK_COLORS[k] : ATTACK_COLORS["other"];
}

// Safe HTML escape
function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Truncate string
function truncate(str, len) {
  if (!str) return "—";
  return str.length > len ? str.slice(0, len) + "…" : str;
}

// Format ISO timestamp to local time string
function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// Format ISO timestamp to full locale string
function fmtFull(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ── ANIMATED COUNTER ────────────────────────────────────────────────────────
function animateCounter(el, target, isDecimal = false, duration = 900) {
  const start = performance.now();
  const startVal = 0;

  function step(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = startVal + (target - startVal) * eased;

    el.textContent = isDecimal
      ? current.toFixed(1)
      : Math.round(current).toString();

    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = isDecimal ? target.toFixed(1) : target.toString();
  }

  requestAnimationFrame(step);
}

// ── THREAT LOG TABLE ────────────────────────────────────────────────────────
function renderTable(history) {
  const tbody = document.getElementById("log-table-body");
  const recent = history.slice(0, 20);

  if (recent.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#475569;padding:24px;">No entries to display</td></tr>`;
    return;
  }

  tbody.innerHTML = recent
    .map((entry) => {
      const action = entry.action || "ALLOW";
      const rowClass =
        action === "BLOCK"
          ? "row-block"
          : action === "WARN"
            ? "row-warn"
            : "row-allow";
      const badgeClass =
        action === "BLOCK"
          ? "badge-block"
          : action === "WARN"
            ? "badge-warn"
            : "badge-allow";

      const riskColor =
        action === "BLOCK"
          ? "#EF4444"
          : action === "WARN"
            ? "#F59E0B"
            : "#10B981";
      const attackLabel =
        entry.attack_type && entry.attack_type !== "Unknown"
          ? entry.attack_type.replace(/_/g, " ")
          : action === "ALLOW"
            ? "Clean"
            : "Unknown";

      return `
      <tr class="${rowClass}">
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64748B;white-space:nowrap;">${fmtTime(entry.timestamp)}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(entry.prompt)}">${escapeHtml(truncate(entry.prompt, 55))}</td>
        <td class="risk-cell" style="color:${riskColor}">${(entry.risk_score || 0).toFixed(1)}%</td>
        <td style="font-size:12px;text-transform:capitalize;color:#94A3B8;">${escapeHtml(attackLabel)}</td>
        <td><span class="action-badge ${badgeClass}">${action}</span></td>
      </tr>`;
    })
    .join("");
}

// ── ATTACK CHART (SVG via chart.js) ─────────────────────────────────────────
function renderChart(history) {
  // Build frequency map of attack_type (exclude ALLOW and Unknown/None)
  const counts = {};
  history.forEach((entry) => {
    if (entry.action === "ALLOW") return;
    const type = entry.attack_type;
    if (!type || type === "Unknown" || type === "None") return;
    const label = type
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    counts[label] = (counts[label] || 0) + 1;
  });

  // Convert to array format expected by renderAttackChart
  const chartData = Object.entries(counts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  // Render using the custom SVG engine from chart.js
  if (typeof window.renderAttackChart === "function") {
    window.renderAttackChart("attack-chart-container", chartData, {
      size: 240,
      mode: "full",
      showCenterText: true,
      animationDuration: 900,
    });
  } else {
    console.warn(
      "[dashboard.js] chart.js not loaded — window.renderAttackChart missing",
    );
  }
}

// ── FOOTER ──────────────────────────────────────────────────────────────────
function renderFooter(history) {
  const footerEl = document.getElementById("footer-session");
  if (!footerEl) return;

  if (history.length === 0) {
    footerEl.textContent = "Session started: —";
    return;
  }

  const sorted = [...history].sort(
    (a, b) => new Date(a.timestamp) - new Date(b.timestamp),
  );
  footerEl.textContent = `Session started: ${fmtFull(sorted[0].timestamp)}`;
}

// ── LANGUAGE BREAKDOWN ──────────────────────────────────────────────────────
function renderLanguageBreakdown(history) {
  const container = document.getElementById("language-breakdown");
  if (!container) return;

  // Filter to multilingual attacks only
  const multiAttacks = history.filter(
    (e) => (e?.is_multilingual_attack ?? false) === true,
  );

  if (multiAttacks.length === 0) {
    container.innerHTML =
      '<div style="color:#475569;padding:24px;text-align:center;font-size:12px;">No multilingual attacks detected this session.</div>';
    return;
  }

  // Count each language
  const langCounts = {};
  const langEmojis = {};
  multiAttacks.forEach((e) => {
    const lang = e?.detected_language || "Unknown";
    const emoji = e?.language_emoji || "🌐";
    langCounts[lang] = (langCounts[lang] || 0) + 1;
    langEmojis[lang] = emoji;
  });

  // Sort by count descending
  const sorted = Object.entries(langCounts)
    .map(([lang, count]) => ({ lang, count, emoji: langEmojis[lang] }))
    .sort((a, b) => b.count - a.count);

  const maxCount = sorted[0].count;

  // Build HTML with staggered animation
  container.innerHTML = "";
  sorted.forEach((item, i) => {
    const el = document.createElement("div");
    el.className = "lang-item";
    el.style.opacity = "0";
    el.style.transform = "translateX(-12px)";
    el.style.transition = `opacity 0.4s ease ${i * 0.08}s, transform 0.4s ease ${i * 0.08}s`;
    el.innerHTML = `
      <span class="lang-flag">${item.emoji}</span>
      <span class="lang-name">${escapeHtml(item.lang)}</span>
      <span class="lang-count">${item.count}</span>
      <div class="lang-bar"><div class="lang-bar-fill" style="width:0%"></div></div>
    `;
    container.appendChild(el);

    // Trigger animation
    requestAnimationFrame(() => {
      el.style.opacity = "1";
      el.style.transform = "translateX(0)";
      const fill = el.querySelector(".lang-bar-fill");
      if (fill)
        setTimeout(
          () => {
            fill.style.width = `${(item.count / maxCount) * 100}%`;
          },
          100 + i * 60,
        );
    });
  });
}

// ── THREAT PROFILE ANALYSIS (RADAR CHARTS) ────────────────────────────────────
function renderThreatProfiles(history) {
  const container = document.getElementById("radar-chart-grid");
  const countLabel = document.getElementById("radar-count");
  if (!container) return;

  // Filter to threats only (not ALLOW)
  const threats = history.filter((e) => e.action !== "ALLOW");

  // Sort by risk_score descending
  threats.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  // Take top 3
  const topThreats = threats.slice(0, 3);

  // Update count label
  if (countLabel) {
    countLabel.textContent = `Showing top ${topThreats.length} threats`;
  }

  // Empty state
  if (topThreats.length === 0) {
    container.innerHTML =
      '<div style="grid-column:1/-1;text-align:center;padding:32px;color:#475569;">No threats to analyze. All prompts in this session were safe.</div>';
    return;
  }

  // Clear container
  container.innerHTML = "";

  // Guard: check if radar chart function exists
  if (typeof window.renderRadarChart !== "function") {
    console.warn(
      "[dashboard.js] radar.js not loaded — window.renderRadarChart missing",
    );
    container.innerHTML =
      '<div style="grid-column:1/-1;text-align:center;padding:32px;color:#475569;">Radar chart engine not available.</div>';
    return;
  }

  // Render each threat with staggered animation
  topThreats.forEach((entry, i) => {
    const riskScore = entry.risk_score || 0;

    // Determine badge color based on severity
    let badgeClass = "blue";
    if (riskScore >= 90) badgeClass = "";
    else if (riskScore >= 70) badgeClass = "amber";
    else badgeClass = "blue";

    // Create radar item wrapper
    const item = document.createElement("div");
    item.className = "radar-item";
    item.innerHTML = `
      <div class="radar-item-header">
        <span class="radar-risk-badge ${badgeClass}">${Math.round(riskScore)}%</span>
        <span class="radar-attack-type">${escapeHtml((entry.attack_type || "Unknown").replace(/_/g, " "))}</span>
      </div>
      <div id="radar-chart-${i}"></div>
      <div class="radar-item-footer">
        <span class="radar-timestamp">${fmtTime(entry.timestamp)}</span>
        <span class="radar-prompt-snip">${escapeHtml(truncate(entry.prompt, 25))}</span>
      </div>
    `;
    container.appendChild(item);

    // Staggered rendering with setTimeout
    setTimeout(() => {
      // Backward compatibility: default pattern_score and groq_score to 0 if missing
      const patternScore =
        entry.pattern_score !== undefined
          ? Math.round(entry.pattern_score * 100)
          : 0;
      const groqScore =
        entry.groq_score !== undefined ? Math.round(entry.groq_score * 100) : 0;

      // Determine color based on severity
      const chartColor = riskScore >= 70 ? "#EF4444" : "#F59E0B";

      window.renderRadarChart(
        `radar-chart-${i}`,
        [
          { label: "Pattern", value: patternScore, color: "#F59E0B" },
          { label: "AI", value: groqScore, color: "#3B82F6" },
          { label: "Risk", value: Math.round(riskScore), color: "#EF4444" },
        ],
        {
          size: 180,
          mode: "expanded",
          fillColor: chartColor,
          fillOpacity: 0.2,
          strokeColor: chartColor,
          animationDuration: 800,
          showValues: true,
        },
      );
    }, i * 100);
  });
}

// ── MAIN ────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // ── HONEYPOT MODE INITIALIZATION ─────────────────────────────────────
  chrome.storage.local.get(["honeypot_mode"], (data) => {
    const isHoneypot = data.honeypot_mode || false;
    updateHoneypotUI(isHoneypot);
  });

  // ── HONEYPOT TOGGLE HANDLER ─────────────────────────────────────────
  const hpToggle = document.getElementById("dashboard-honeypot-toggle");
  if (hpToggle) {
    hpToggle.addEventListener("click", () => {
      chrome.storage.local.get(["honeypot_mode"], (data) => {
        const current = data.honeypot_mode || false;
        const newState = !current;
        chrome.storage.local.set({ honeypot_mode: newState });
        updateHoneypotUI(newState);
      });
    });
  }

  // ── HONEYPOT STORAGE SYNC (real-time updates from popup) ─────────────
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.honeypot_mode) {
      updateHoneypotUI(changes.honeypot_mode.newValue);
    }
  });

  chrome.storage.local.get(["pg_history"], (data) => {
    const history = data.pg_history || [];

    // Show empty state if no data
    if (history.length === 0) {
      document.getElementById("main-grid").style.display = "none";
      document.getElementById("empty-state").style.display = "block";
      return;
    }

    // ── Calculate Stats ──────────────────────────────────────────────────
    const total = history.length;
    const threats = history.filter((e) => e.action !== "ALLOW").length;
    const safe = total - threats;
    const avgRisk =
      history.reduce((sum, e) => sum + (e.risk_score || 0), 0) / total;
    const multilingual = history.filter(
      (e) => (e?.is_multilingual_attack ?? false) === true,
    ).length;

    // ── Animate Counters ─────────────────────────────────────────────────
    animateCounter(document.getElementById("stat-total"), total, false, 900);
    animateCounter(
      document.getElementById("stat-threats"),
      threats,
      false,
      900,
    );
    animateCounter(document.getElementById("stat-safe"), safe, false, 900);
    animateCounter(document.getElementById("stat-avg"), avgRisk, true, 900);
    const multilingualEl =
      document.getElementById("multilingual-count") ||
      document.getElementById("stat-multilingual");
    if (multilingualEl) {
      animateCounter(multilingualEl, multilingual, false, 900);
    }

    // ── Render Sections ──────────────────────────────────────────────────
    renderTable(history);
    renderChart(history);
    // Calculate session info for the header display
    const sessionStart =
      history.length > 0
        ? new Date(history[history.length - 1].timestamp)
        : new Date();
    const sessionEnd =
      history.length > 0 ? new Date(history[0].timestamp) : new Date();
    const sessionDurationMs = sessionEnd - sessionStart;
    const sessionDurationMins = Math.round(sessionDurationMs / 60000);

    // Update the session info label
    const sessionInfoEl = document.getElementById("timeline-session-info");
    if (sessionInfoEl) {
      sessionInfoEl.textContent = `Session: ${sessionDurationMins}m | ${history.length} events`;
    }

    // Sort history chronologically for timeline (oldest first)
    const chronologicalHistory = [...history].reverse();

    // Render the advanced timeline
    if (window.renderSeverityTimeline) {
      window.renderSeverityTimeline(
        "severity-timeline-container",
        chronologicalHistory,
        {
          animationDelay: 60,
          enableZoom: true,
          enablePlayback: true,
        },
      );
    } else {
      console.warn(
        "timeline.js not loaded — make sure script tag is before dashboard.js",
      );
    }

    const fullTimelineBtn = document.getElementById("full-timeline-btn");
    if (fullTimelineBtn && !fullTimelineBtn.dataset.bound) {
      fullTimelineBtn.dataset.bound = "true";
      fullTimelineBtn.addEventListener("click", () => {
        chrome.tabs.create({
          url: chrome.runtime.getURL("timeline-full.html"),
        });
      });
    }

    renderLanguageBreakdown(history);
    renderThreatProfiles(history);
    renderHoneypotEvents(history);
    renderFooter(history);
  });

  // Threat intelligence feed loads independently (doesn't need pg_history)
  loadGlobalThreatIntel();
});

// ── RELATIVE TIME (dashboard context) ────────────────────────────────────────
function getRelativeTime(isoString) {
  if (!isoString) return "—";
  const diffSec = Math.floor(
    (Date.now() - new Date(isoString).getTime()) / 1000,
  );
  if (diffSec < 3600) return Math.max(1, Math.floor(diffSec / 60)) + "m ago";
  if (diffSec < 86400) return Math.floor(diffSec / 3600) + "h ago";
  return Math.floor(diffSec / 86400) + "d ago";
}

// ── GLOBAL THREAT INTELLIGENCE FEED ─────────────────────────────────────────
async function loadGlobalThreatIntel() {
  const grid = document.getElementById("threat-intel-grid");
  const lastUpdEl = document.getElementById("feed-last-updated");
  if (!grid) return;

  try {
    const res = await fetch("http://127.0.0.1:5000/threat-feed");
    const data = await res.json();
    const feed = data.feed || [];

    if (lastUpdEl && data.last_updated) {
      lastUpdEl.textContent =
        "Last updated: " + getRelativeTime(data.last_updated);
    }

    if (feed.length === 0) throw new Error("empty feed");

    grid.innerHTML = feed
      .map((t) => {
        const statusCls = (t.mitigation_status || "").replace(/\s+/g, "-");
        const modelTags = (t.affected_models || [])
          .map((m) => `<span class="intel-model-tag">${escapeHtml(m)}</span>`)
          .join("");

        return `
        <div class="intel-card">
          <div class="intel-card-header">
            <span class="intel-severity ${t.severity}">${t.severity}</span>
            <span class="intel-cvss">CVSS\u00a0${(t.cvss_score || 0).toFixed(1)}</span>
          </div>
          <div class="intel-title">${escapeHtml(t.title)}</div>
          <div class="intel-description">${escapeHtml(t.description)}</div>
          <div class="intel-models">${modelTags}</div>
          <div class="intel-meta">
            <div class="intel-meta-item"><strong>ID:</strong> ${escapeHtml(t.id)}</div>
            <div class="intel-meta-item"><strong>Source:</strong> ${escapeHtml(t.source)}</div>
            <div class="intel-meta-item"><strong>Discovered:</strong> ${getRelativeTime(t.discovered_at)}</div>
            <div class="intel-meta-item"><strong>Status:</strong>
              <span class="intel-status ${statusCls}">${escapeHtml(t.mitigation_status)}</span>
            </div>
          </div>
        </div>`;
      })
      .join("");
  } catch (err) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;padding:32px;color:#475569;">
      ⚠️ Threat feed unavailable. Backend not reachable.
    </div>`;
    if (lastUpdEl) lastUpdEl.textContent = "Unavailable";
  }
}

// ── DASHBOARD EXPORT FORENSIC REPORT ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const exportBtn = document.getElementById("dashboard-export-btn");
  if (!exportBtn) return;

  exportBtn.addEventListener("click", async () => {
    const originalText = exportBtn.textContent;
    exportBtn.disabled = true;
    exportBtn.textContent = "⏳ Generating Report...";

    try {
      // 1. Read session history from chrome.storage
      const stored = await new Promise((resolve) =>
        chrome.storage.local.get(["pg_history"], resolve),
      );
      const history = stored.pg_history || [];

      // 2. POST to /generate-report
      const res = await fetch("http://127.0.0.1:5000/generate-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ history }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reportData = await res.json();

      // 3. Store for report.html
      await new Promise((resolve) =>
        chrome.storage.local.set({ pg_report_data: reportData }, resolve),
      );

      // 4. Open report in new tab
      chrome.tabs.create({ url: chrome.runtime.getURL("report.html") });
    } catch (err) {
      alert(
        "Report generation failed. Make sure the backend is running.\n\nError: " +
          err.message,
      );
    } finally {
      setTimeout(() => {
        exportBtn.disabled = false;
        exportBtn.textContent = originalText;
      }, 2000);
    }
  });
});

// ── HONEYPOT MODE DASHBOARD FUNCTIONS ─────────────────────────────────────────
function updateHoneypotUI(isActive) {
  const banner = document.getElementById("honeypot-banner");
  const toggle = document.getElementById("dashboard-honeypot-toggle");

  if (banner) {
    banner.style.display = isActive ? "block" : "none";
  }

  if (toggle) {
    if (isActive) {
      toggle.textContent = "🍯 Disable Honeypot Mode";
      toggle.classList.add("active");
    } else {
      toggle.textContent = "🍯 Enable Honeypot Mode";
      toggle.classList.remove("active");
    }
  }
}

function renderHoneypotEvents(history) {
  const tbody = document.getElementById("honeypot-table-body");
  const hpTotal = document.getElementById("hp-total");
  const hpHighest = document.getElementById("hp-highest");
  const hpTypes = document.getElementById("hp-types");

  if (!tbody) return;

  // Filter honeypot events
  const honeypotEvents = history.filter(
    (e) => e.user_action === "honeypot-tracked" || e.honeypot === true,
  );

  // Update stats
  if (hpTotal) hpTotal.textContent = honeypotEvents.length;
  if (hpHighest) {
    const maxRisk =
      honeypotEvents.length > 0
        ? Math.max(...honeypotEvents.map((e) => e.risk_score || 0)).toFixed(1) +
          "%"
        : "0%";
    hpHighest.textContent = maxRisk;
  }
  if (hpTypes) {
    const uniqueTypes = new Set(
      honeypotEvents.map((e) => e.attack_type).filter(Boolean),
    );
    hpTypes.textContent = uniqueTypes.size;
  }

  // Render table
  if (honeypotEvents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#475569;padding:24px;">No honeypot events yet. Enable Honeypot Mode and allow a threat through to see it here.</td></tr>`;
    return;
  }

  tbody.innerHTML = honeypotEvents
    .slice(0, 20)
    .map((entry) => {
      const attackLabel =
        entry.attack_type && entry.attack_type !== "Unknown"
          ? entry.attack_type.replace(/_/g, " ")
          : "Unknown";
      const langDisplay = entry.is_multilingual_attack
        ? `${entry.language_emoji || "🌐"} ${entry.detected_language || "Unknown"}`
        : "—";

      return `
      <tr class="honeypot-row">
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64748B;white-space:nowrap;">${fmtTime(entry.timestamp)}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(entry.prompt)}">${escapeHtml(truncate(entry.prompt, 50))}</td>
        <td style="color:#F59E0B;font-weight:bold;">${(entry.risk_score || 0).toFixed(1)}%</td>
        <td style="font-size:12px;text-transform:capitalize;color:#94A3B8;">${escapeHtml(attackLabel)}</td>
        <td style="font-size:12px;color:#94A3B8;">${escapeHtml(langDisplay)}</td>
        <td><span class="honeypot-badge">🐝 Logged & Allowed</span></td>
      </tr>`;
    })
    .join("");
}
