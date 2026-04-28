// Prompt Guardian - Content Script

const API_URL = "http://127.0.0.1:5000/analyze";
let isAnalyzing = false;

const PLATFORM_SELECTORS = {
  "chat.openai.com": {
    input: "#prompt-textarea",
    send: '#composer-submit-button, [data-testid="send-button"]',
  },
  "chatgpt.com": {
    input: "#prompt-textarea",
    send: '#composer-submit-button, [data-testid="send-button"]',
  },
  "gemini.google.com": { input: ".ql-editor", send: ".send-button" },
  "claude.ai": {
    input: '[contenteditable="true"]',
    send: '[aria-label="Send Message"]',
  },
};

function getSelectors() {
  const host = window.location.hostname;
  return (
    PLATFORM_SELECTORS[host] || {
      input: "textarea",
      send: "button[type=submit]",
    }
  );
}

// ---------------- INTERCEPT ----------------
async function interceptPrompt(e) {
  if (isAnalyzing) {
    e.preventDefault();
    e.stopImmediatePropagation();
    return;
  }

  const sel = getSelectors();
  const inputEl = document.querySelector(sel.input);
  if (!inputEl) return;

  const promptText =
    inputEl.value || inputEl.innerText || inputEl.textContent || "";

  if (!promptText.trim() || promptText.trim().length < 3) return;

  // CRITICAL: Must prevent immediately before any async work
  e.preventDefault();
  e.stopImmediatePropagation();

  isAnalyzing = true;
  showLoadingIndicator();

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: promptText }),
    });

    if (!response.ok) {
      throw new Error("API returned " + response.status);
    }

    const result = await response.json();
    hideLoadingIndicator();

    // ── HONEYPOT MODE CHECK ─────────────────────────────────────────
    // Check if chrome storage is available
    let isHoneypot = false;
    if (chrome && chrome.storage) {
      try {
        const hpData = await new Promise((resolve) =>
          chrome.storage.local.get(["honeypot_mode"], resolve),
        );
        isHoneypot = hpData.honeypot_mode || false;
      } catch (err) {
        console.warn("Prompt Guardian: Could not check honeypot mode:", err);
      }
    }

    if (isHoneypot && result.action === "BLOCK") {
      // Honeypot override: allow threat through but log it
      result.action = "ALLOW";
      result.honeypot = true;
      result.honeypot_note =
        "Logged in Honeypot Mode — threat allowed for analysis";

      // Log with honeypot-tracked user action
      logToHistory(promptText, result, "honeypot-tracked", () => {
        showHoneypotToast(result);
        proceedWithSend(sel);
      });

      isAnalyzing = false;
      return;
    }

    if (result.action === "ALLOW") {
      showSafeOverlay(result.risk_score || 0, promptText, result);
      logToHistory(promptText, result, "auto", () => {
        proceedWithSend(sel);
      });
    } else if (result.action === "WARN") {
      logToHistory(promptText, result);
      await showWarningOverlay(promptText, result, sel, inputEl, isHoneypot);
      // WARN: Do NOT proceed - block the send
      isAnalyzing = false;
    } else {
      // BLOCK: Show overlay but do NOT proceed
      logToHistory(promptText, result);
      await showBlockOverlay(promptText, result, sel, inputEl);
      isAnalyzing = false;
    }
  } catch (err) {
    hideLoadingIndicator();
    console.warn(
      "Prompt Guardian: API unavailable, allowing prompt through:",
      err.message,
    );
    // Fail-open: if API is down, let the prompt through
    proceedWithSend(sel);
  } finally {
    // Only reset if not already done in action handlers
    if (isAnalyzing) {
      isAnalyzing = false;
    }
  }
}

// ---------------- OVERLAYS ----------------
// ── HELPER: LOAD RADAR.JS DYNAMICALLY ─────────────────────────────────────
async function loadRadarChart() {
  if (window.renderRadarChart) return; // Already loaded

  // Check if already loading to prevent duplicate requests
  if (window._radarLoading) {
    // Wait for it to finish loading
    await new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        if (window.renderRadarChart) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 50);
      // Timeout after 2 seconds
      setTimeout(() => {
        clearInterval(checkInterval);
        resolve();
      }, 2000);
    });
    return;
  }

  window._radarLoading = true;

  try {
    // Load radar.js as an external script file (CSP-compliant)
    const scriptUrl = chrome.runtime.getURL("radar.js");

    // Create script element with proper attributes (no inline code)
    const script = document.createElement("script");
    script.src = scriptUrl;
    script.type = "text/javascript";

    // Wait for script to load
    await new Promise((resolve, reject) => {
      script.onload = () => {
        // Give the IIFE time to execute and attach to window
        setTimeout(resolve, 50);
      };
      script.onerror = () => {
        console.warn("Prompt Guardian: Failed to load radar.js");
        resolve(); // Resolve anyway to continue without radar
      };
      document.head.appendChild(script);
    });
  } catch (err) {
    console.warn("Prompt Guardian: Failed to load radar chart:", err);
  } finally {
    window._radarLoading = false;
  }
}

async function showBlockOverlay(original, result, sel, inputEl) {
  document.getElementById("pg-overlay")?.remove();

  // Play alert sound and show browser notification
  playAlertSound();
  showBrowserNotification(result);

  // Load radar.js dynamically if not already loaded
  await loadRadarChart();

  const overlay = document.createElement("div");
  overlay.id = "pg-overlay";

  const riskScore = result.risk_score || 0;
  const attackType = result.attack_type || "Unknown";
  const attackLabel = result.attack_label || attackType;
  const explanation = result.explanation || "";
  const safeVersions = result.safe_versions || [];

  // Check if we have useful sanitized versions
  const hasUsefulVersions =
    safeVersions.length > 0 &&
    safeVersions.some(
      (v) => v && !v.startsWith("[This prompt is entirely malicious"),
    );

  overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header danger">${result.is_multilingual_attack ? `🛡️ Prompt Guardian — THREAT DETECTED ${result.language_emoji || "🌐"}` : "🛡️ Prompt Guardian — THREAT DETECTED"}</div>
      <div class="pg-body">
        <div class="pg-score-row">
          <div class="pg-score danger">Risk: ${riskScore}%</div>
          <div class="pg-confidence">${result.confidence || ""} confidence</div>
        </div>
        <div class="pg-layers" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          <span style="background:#1E293B;color:#93C5FD;padding:5px 10px;border-radius:6px;font-size:11px;">Pattern ${Math.round((result.pattern_score || 0) * 100)}%</span>
          <span style="background:#1E293B;color:#A7F3D0;padding:5px 10px;border-radius:6px;font-size:11px;">Semantic ${Math.round((result.groq_score || 0) * 100)}%</span>
          <span style="background:#1E293B;color:#FCA5A5;padding:5px 10px;border-radius:6px;font-size:11px;">${result.action || "BLOCK"}</span>
          ${result.is_multilingual_attack ? `<span style="background:#7C3AED;color:white;padding:5px 12px;border-radius:6px;font-size:12px;">${result.language_emoji || "🌐"} ${result.detected_language || "Unknown"} Attack</span>` : ""}
        </div>

        <!-- Radar Chart Container -->
        <div id="pg-radar-container" style="display:flex;justify-content:center;margin:12px 0;"></div>

        <div class="pg-explanation">${escapeHtml(explanation)}</div>

        ${result.translation_hint ? `<div class="pg-label" style="background:#1E293B;padding:8px;border-radius:6px;margin-top:8px;border-left:3px solid #7C3AED;">🌐 Translation hint: "${escapeHtml(result.translation_hint)}"</div>` : ""}

        ${
          hasUsefulVersions
            ? `
        <div class="pg-sanitized-label">Choose a sanitized version to send:</div>
        <div class="pg-versions-container">
          ${safeVersions
            .map(
              (v, i) => `
            <div class="pg-version-option">
              <input type="radio" name="pg-version" id="pg-version-${i}" value="${i}" ${i === 0 ? "checked" : ""}>
              <label for="pg-version-${i}" class="pg-version-label">
                <span class="pg-version-title">Version ${i + 1}</span>
                <textarea class="pg-version-text" readonly>${escapeHtml(v)}</textarea>
              </label>
            </div>
          `,
            )
            .join("")}
        </div>
        `
            : `
        <div class="pg-blocked-msg">This prompt is entirely malicious and has been blocked.</div>
        `
        }

        <div class="pg-actions">
          ${hasUsefulVersions ? '<button class="pg-btn safe" id="pg-send-sanitized">Send Selected Version</button>' : ""}
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

  injectStyles();
  document.body.appendChild(overlay);

  // Render radar chart if available
  if (window.renderRadarChart) {
    const radarAxes = [
      {
        label: "Pattern",
        value: Math.round((result.pattern_score || 0) * 100),
        color: "#F59E0B",
      },
      {
        label: "AI Analysis",
        value: Math.round((result.groq_score || 0) * 100),
        color: "#3B82F6",
      },
      {
        label: "Risk Score",
        value: Math.round(result.risk_score || 0),
        color: "#EF4444",
      },
    ];

    // Add language confidence axis if multilingual
    if (result.is_multilingual_attack && result.language_confidence) {
      radarAxes.push({
        label: "Language",
        value: Math.round(result.language_confidence * 100),
        color: "#7C3AED",
      });
    }

    window.renderRadarChart("pg-radar-container", radarAxes, {
      size: 140,
      mode: "inline",
      fillColor: "#EF4444",
      fillOpacity: 0.25,
      strokeColor: "#EF4444",
      animationDuration: 500,
      showValues: false,
    });
  }

  const sendSanitizedBtn = document.getElementById("pg-send-sanitized");
  if (sendSanitizedBtn) {
    sendSanitizedBtn.onclick = () => {
      const selectedRadio = document.querySelector(
        'input[name="pg-version"]:checked',
      );
      if (selectedRadio) {
        const selectedIndex = parseInt(selectedRadio.value);
        const selectedVersion = safeVersions[selectedIndex];
        setInputValue(inputEl, selectedVersion);
        overlay.remove();
        logToHistory(original, result, "sanitized");
        setTimeout(() => proceedWithSend(sel), 100);
      }
    };
  }

  document.getElementById("pg-cancel").onclick = () => overlay.remove();
}

async function showWarningOverlay(
  original,
  result,
  sel,
  inputEl,
  isHoneypot = false,
) {
  document.getElementById("pg-overlay")?.remove();

  // Load radar.js dynamically if not already loaded
  await loadRadarChart();

  const overlay = document.createElement("div");
  overlay.id = "pg-overlay";

  const riskScore = result.risk_score || 0;
  const explanation =
    result.explanation || "This prompt contains suspicious patterns.";

  overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header warn">
        ${result.is_multilingual_attack ? `🛡️ Prompt Guardian — THREAT DETECTED ${result.language_emoji || "🌐"}` : "⚠️ Suspicious Prompt Detected"}
        ${isHoneypot ? '<span style="background:#F59E0B;color:#0F1729;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:bold;margin-left:8px;">[HONEYPOT ACTIVE]</span>' : ""}
      </div>
      <div class="pg-body">
        <div class="pg-score-row" style="display:flex;align-items:center;gap:8px;">
          <div class="pg-score warn">Risk: ${riskScore}%</div>
        </div>
        <div class="pg-layers" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          <span style="background:#1E293B;color:#93C5FD;padding:5px 10px;border-radius:6px;font-size:11px;">Pattern ${Math.round((result.pattern_score || 0) * 100)}%</span>
          <span style="background:#1E293B;color:#A7F3D0;padding:5px 10px;border-radius:6px;font-size:11px;">Semantic ${Math.round((result.groq_score || 0) * 100)}%</span>
          <span style="background:#1E293B;color:#FDE68A;padding:5px 10px;border-radius:6px;font-size:11px;">${result.action || "WARN"}</span>
          ${result.is_multilingual_attack ? `<span style="background:#7C3AED;color:white;padding:5px 12px;border-radius:6px;font-size:12px;">${result.language_emoji || "🌐"} ${result.detected_language || "Unknown"} Attack</span>` : ""}
        </div>

        <!-- Radar Chart Container -->
        <div id="pg-radar-container" style="display:flex;justify-content:center;margin:12px 0;"></div>

        <div class="pg-explanation">${escapeHtml(explanation)}</div>

        ${result.translation_hint ? `<div class="pg-label" style="background:#1E293B;padding:8px;border-radius:6px;margin-top:8px;border-left:3px solid #7C3AED;">🌐 Translation hint: "${escapeHtml(result.translation_hint)}"</div>` : ""}

        <div class="pg-blocked-msg">This prompt has been flagged as suspicious and has been blocked.</div>

        <div class="pg-actions">
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

  injectStyles();
  document.body.appendChild(overlay);

  // Render radar chart if available
  if (window.renderRadarChart) {
    const radarAxes = [
      {
        label: "Pattern",
        value: Math.round((result.pattern_score || 0) * 100),
        color: "#F59E0B",
      },
      {
        label: "AI Analysis",
        value: Math.round((result.groq_score || 0) * 100),
        color: "#3B82F6",
      },
      {
        label: "Risk Score",
        value: Math.round(result.risk_score || 0),
        color: "#EF4444",
      },
    ];

    // Add language confidence axis if multilingual
    if (result.is_multilingual_attack && result.language_confidence) {
      radarAxes.push({
        label: "Language",
        value: Math.round(result.language_confidence * 100),
        color: "#7C3AED",
      });
    }

    window.renderRadarChart("pg-radar-container", radarAxes, {
      size: 120,
      mode: "inline",
      fillColor: "#F59E0B",
      fillOpacity: 0.25,
      strokeColor: "#F59E0B",
      animationDuration: 500,
      showValues: false,
    });
  }

  document.getElementById("pg-cancel").onclick = () => overlay.remove();
}

async function showSafeOverlay(score, promptText, result = {}) {
  document.getElementById("pg-overlay")?.remove();

  const overlay = document.createElement("div");
  overlay.id = "pg-overlay";

  // Extract additional analysis details if available
  const patternScore = result.pattern_score || 0;
  const groqScore = result.groq_score || 0;
  const detectedLang = result.detected_language || "English";
  const langEmoji = result.language_emoji || "🇺🇸";

  overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header safe">✅ Prompt Guardian — SAFE PROMPT</div>
      <div class="pg-body">
        <div class="pg-score-row">
          <div class="pg-score safe">Risk: ${score}%</div>
          <div class="pg-confidence">LOW RISK</div>
        </div>
        <div class="pg-layers" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
          <span style="background:#1E293B;color:#93C5FD;padding:5px 10px;border-radius:6px;font-size:11px;">Pattern ${Math.round(patternScore * 100)}%</span>
          <span style="background:#1E293B;color:#A7F3D0;padding:5px 10px;border-radius:6px;font-size:11px;">Semantic ${Math.round(groqScore * 100)}%</span>
          <span style="background:#1E293B;color:#86EFAC;padding:5px 10px;border-radius:6px;font-size:11px;">ALLOW</span>
          <span style="background:#1E293B;color:#94A3B8;padding:5px 10px;border-radius:6px;font-size:11px;">${langEmoji} ${detectedLang}</span>
        </div>

        <!-- Radar Chart Container -->
        <div id="pg-radar-container" style="display:flex;justify-content:center;margin:12px 0;"></div>

        <div class="pg-explanation">This prompt has been analyzed and deemed safe to send. No injection patterns were detected.</div>
        <div class="pg-prompt-preview">
          <div class="pg-prompt-label">Your prompt:</div>
          <div class="pg-prompt-text">${escapeHtml(promptText.slice(0, 200))}${promptText.length > 200 ? "..." : ""}</div>
        </div>
        <div class="pg-actions">
          <button class="pg-btn safe" id="pg-proceed">Proceed</button>
        </div>
      </div>
    </div>
  `;

  injectStyles();
  document.body.appendChild(overlay);

  // Render radar chart if available
  if (window.renderRadarChart) {
    const radarAxes = [
      {
        label: "Pattern",
        value: Math.round(patternScore * 100),
        color: "#F59E0B",
      },
      {
        label: "AI Analysis",
        value: Math.round(groqScore * 100),
        color: "#3B82F6",
      },
      {
        label: "Risk Score",
        value: Math.round(score),
        color: "#10B981",
      },
    ];

    // Add language confidence axis if available
    if (result.language_confidence) {
      radarAxes.push({
        label: "Language",
        value: Math.round(result.language_confidence * 100),
        color: "#7C3AED",
      });
    }

    window.renderRadarChart("pg-radar-container", radarAxes, {
      size: 120,
      mode: "inline",
      fillColor: "#10B981",
      fillOpacity: 0.25,
      strokeColor: "#10B981",
      animationDuration: 500,
      showValues: false,
    });
  }

  // Auto-dismiss after 2 seconds
  setTimeout(() => {
    const btn = document.getElementById("pg-proceed");
    if (btn) btn.click();
  }, 2000);

  document.getElementById("pg-proceed").onclick = () => overlay.remove();
}

// ---------------- UTIL ----------------
function proceedWithSend(sel) {
  const btn = document.querySelector(sel.send);
  if (btn) {
    // Temporarily disable ALL our interceptors
    btn.removeEventListener("click", interceptPrompt, true);

    // Also disable on the form if it exists
    const inputEl = document.querySelector(sel.input);
    const form = inputEl?.closest("form");
    if (form) {
      form.removeEventListener("submit", interceptPrompt, true);
    }

    // Click the button
    btn.click();

    // Re-attach after a delay to prevent recursive interception
    setTimeout(() => {
      btn.addEventListener("click", interceptPrompt, true);
      if (form) {
        form.addEventListener("submit", interceptPrompt, true);
      }
    }, 500);
  }
}

function setInputValue(el, value) {
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
    const setter =
      Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype,
        "value",
      )?.set ||
      Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        "value",
      )?.set;
    if (setter) {
      setter.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
  } else {
    el.innerText = value;
    el.dispatchEvent(new InputEvent("input", { bubbles: true }));
  }
}

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function logToHistory(prompt, result, userAction = "auto", onDone = null) {
  try {
    // Check if chrome.runtime is available (extension context)
    if (!chrome || !chrome.storage) {
      console.warn("Prompt Guardian: Chrome storage API not available");
      if (onDone) onDone();
      return;
    }

    chrome.storage.local.get(["pg_history"], (data) => {
      const history = data.pg_history || [];

      history.unshift({
        timestamp: new Date().toISOString(),
        prompt: prompt.slice(0, 120),
        risk_score: result.risk_score || 0,
        action: result.action || "ALLOW",
        attack_type: result.attack_type || null,
        detected_language: result.detected_language || "English",
        language_emoji: result.language_emoji || "🇺🇸",
        is_multilingual_attack: !!result.is_multilingual_attack,
        translation_hint: result.translation_hint || null,
        user_action: userAction,
        pattern_score: result.pattern_score || 0,
        groq_score: result.groq_score || 0,
      });

      // Keep max 100 entries
      chrome.storage.local.set({ pg_history: history.slice(0, 100) }, () => {
        if (chrome.runtime.lastError) {
          console.warn(
            "Prompt Guardian: Storage error:",
            chrome.runtime.lastError,
          );
        }
        if (onDone) onDone();
      });
    });
  } catch (e) {
    console.warn("Prompt Guardian: storage unavailable", e);
    if (onDone) onDone();
  }
}

// ---------------- ATTACH ----------------
function attachInterceptor() {
  const sel = getSelectors();
  const btn = document.querySelector(sel.send);
  const inputEl = document.querySelector(sel.input);

  // Intercept send button click
  if (btn && !btn._pgAttached) {
    btn.addEventListener("click", interceptPrompt, true);
    btn._pgAttached = true;
    console.log("Prompt Guardian: Attached to send button");
  }

  // Intercept Enter key on input field
  if (inputEl && !inputEl._pgKeyAttached) {
    inputEl.addEventListener(
      "keydown",
      function (e) {
        if (e.key === "Enter" && !e.shiftKey) {
          interceptPrompt(e);
        }
      },
      true,
    );
    inputEl._pgKeyAttached = true;
    console.log("Prompt Guardian: Attached to input field (Enter key)");
  }

  // Intercept form submit (ChatGPT wraps input in a form)
  const form = inputEl?.closest("form");
  if (form && !form._pgFormAttached) {
    form.addEventListener("submit", interceptPrompt, true);
    form._pgFormAttached = true;
    console.log("Prompt Guardian: Attached to form submit");
  }

  if (btn || inputEl) {
    console.log("Prompt Guardian: Active on", window.location.hostname);
  }
}

// Watch for DOM changes (SPAs re-render the send button)
new MutationObserver(attachInterceptor).observe(document.body, {
  childList: true,
  subtree: true,
});

attachInterceptor();

// ── HONEYPOT PAGE BANNER ─────────────────────────────────────────────────
// Check and inject honeypot banner on page load
injectHoneypotBanner();

// Also check on DOM changes (in case page re-renders)
new MutationObserver(() => injectHoneypotBanner()).observe(document.body, {
  childList: true,
  subtree: true,
});

// ---------------- STYLES ----------------
function showLoadingIndicator() {
  if (document.getElementById("pg-loading")) return;

  const el = document.createElement("div");
  el.id = "pg-loading";
  el.innerHTML = '<span class="pg-spinner"></span> Analyzing prompt...';
  el.style.cssText =
    "position:fixed;bottom:20px;right:20px;background:#1B3A6B;color:white;" +
    "padding:12px 18px;border-radius:10px;z-index:99999;font-family:sans-serif;" +
    "font-size:13px;display:flex;align-items:center;gap:8px;" +
    "box-shadow:0 4px 16px rgba(0,0,0,0.3)";
  document.body.appendChild(el);
}

function hideLoadingIndicator() {
  document.getElementById("pg-loading")?.remove();
}

function showSafeBadge(score) {
  const el = document.createElement("div");
  el.id = "pg-safe-badge";
  el.innerHTML = `✅ Safe <span style="opacity:0.7">(${score}% risk)</span>`;
  el.style.cssText =
    "position:fixed;bottom:20px;right:20px;background:#059669;color:white;" +
    "padding:10px 16px;border-radius:10px;z-index:99999;font-family:sans-serif;" +
    "font-size:13px;box-shadow:0 4px 16px rgba(0,0,0,0.3);" +
    "transition:opacity 0.3s ease";
  document.body.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 300);
  }, 2000);
}

function injectStyles() {
  if (document.getElementById("pg-styles")) return;

  const style = document.createElement("style");
  style.id = "pg-styles";

  style.textContent = `
    #pg-overlay {
        position: fixed; inset: 0;
        background: rgba(0,0,0,0.85);
        display: flex; align-items: center; justify-content: center;
        z-index: 999999;
        font-family: -apple-system, "Segoe UI", sans-serif;
        animation: pgFadeIn 0.2s ease;
    }
    @keyframes pgFadeIn { from { opacity: 0 } to { opacity: 1 } }

    .pg-modal {
        background: #0F1729;
        color: #E2E8F0;
        width: 520px;
        max-width: 90vw;
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        animation: pgSlideUp 0.25s ease;
    }
    @keyframes pgSlideUp { from { transform: translateY(20px); opacity: 0 } to { transform: translateY(0); opacity: 1 } }

    .pg-header {
        padding: 14px 20px;
        font-size: 16px;
        font-weight: 700;
    }
    .pg-header.danger { background: #DC2626; color: white; }
    .pg-header.warn { background: #D97706; color: white; }
    .pg-header.safe { background: #059669; color: white; }

    .pg-body { padding: 20px; }

    .pg-score-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
    }
    .pg-score {
        font-size: 22px;
        font-weight: 700;
    }
    .pg-score.danger { color: #EF4444; }
    .pg-score.warn { color: #F59E0B; }
    .pg-score.safe { color: #10B981; }
    .pg-confidence {
        font-size: 12px;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .pg-explanation {
        font-size: 13px;
        color: #94A3B8;
        line-height: 1.6;
        margin-bottom: 14px;
        padding: 10px;
        background: rgba(255,255,255,0.03);
        border-radius: 8px;
    }

    .pg-sanitized-label {
        font-size: 11px;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 6px;
    }
    .pg-sanitized {
        width: 100%;
        min-height: 60px;
        padding: 10px;
        background: #1E293B;
        color: #E2E8F0;
        border: 1px solid #334155;
        border-radius: 8px;
        font-family: inherit;
        font-size: 13px;
        resize: vertical;
        margin-bottom: 14px;
    }

    .pg-versions-container {
        display: flex;
        flex-direction: column;
        gap: 10px;
        margin-bottom: 14px;
    }
    .pg-version-option {
        position: relative;
    }
    .pg-version-option input[type="radio"] {
        position: absolute;
        opacity: 0;
        cursor: pointer;
    }
    .pg-version-label {
        display: block;
        cursor: pointer;
        padding: 12px;
        background: #1E293B;
        border: 2px solid #334155;
        border-radius: 8px;
        transition: all 0.2s ease;
    }
    .pg-version-option input[type="radio"]:checked + .pg-version-label {
        border-color: #059669;
        background: rgba(5, 150, 105, 0.1);
    }
    .pg-version-label:hover {
        border-color: #475569;
    }
    .pg-version-title {
        display: block;
        font-size: 12px;
        font-weight: 600;
        color: #10B981;
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .pg-version-text {
        width: 100%;
        min-height: 50px;
        padding: 8px;
        background: #0F172A;
        color: #E2E8F0;
        border: 1px solid #334155;
        border-radius: 6px;
        font-family: inherit;
        font-size: 12px;
        resize: vertical;
    }

    .pg-prompt-preview {
        margin-bottom: 14px;
    }
    .pg-prompt-label {
        font-size: 11px;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 6px;
    }
    .pg-prompt-text {
        padding: 10px;
        background: #1E293B;
        color: #E2E8F0;
        border: 1px solid #334155;
        border-radius: 8px;
        font-size: 13px;
        line-height: 1.5;
    }

    .pg-blocked-msg {
        font-size: 13px;
        color: #F87171;
        padding: 12px;
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.2);
        background: rgba(239,68,68,0.08);
        border: 1px solid rgba(239,68,68,0.2);
        border-radius: 8px;
        margin-bottom: 14px;
        text-align: center;
        font-weight: 500;
    }

    .pg-actions {
        display: flex;
        gap: 10px;
        margin-top: 6px;
    }
    .pg-btn {
        padding: 10px 16px;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-size: 13px;
        font-weight: 600;
        transition: transform 0.1s ease, opacity 0.15s ease;
    }
    .pg-btn:hover { transform: scale(1.03); }
    .pg-btn:active { transform: scale(0.97); }
    .pg-btn.safe { background: #059669; color: white; }
    .pg-btn.warn { background: #D97706; color: white; }
    .pg-btn.cancel { background: #374151; color: #94A3B8; }

    .pg-spinner {
        display: inline-block;
        width: 14px; height: 14px;
        border: 2px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: pgSpin 0.6s linear infinite;
    }
    @keyframes pgSpin { to { transform: rotate(360deg) } }
  `;

  document.head.appendChild(style);
}

// ── HONEYPOT TOAST NOTIFICATION ───────────────────────────────────────────
function showHoneypotToast(result) {
  const toast = document.createElement("div");
  toast.id = "pg-honeypot-toast";
  const attackType = result.attack_type || "Unknown";
  const riskScore = result.risk_score || 0;

  toast.innerHTML = `🍯 Honeypot Mode: ${attackType} logged (${riskScore}%) — Threat allowed for research`;
  toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: #2D1B0E;
        border: 1px solid #F59E0B;
        color: #F59E0B;
        padding: 12px 20px;
        border-radius: 8px;
        z-index: 999999;
        font-size: 13px;
        font-family: -apple-system, "Segoe UI", sans-serif;
        box-shadow: 0 4px 15px rgba(245,158,11,0.3);
        animation: pgToastFadeIn 0.3s ease;
    `;

  document.body.appendChild(toast);

  // Auto-remove after 3 seconds with fade-out
  setTimeout(() => {
    toast.style.transition = "opacity 0.3s ease";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ── HONEYPOT PAGE BANNER ─────────────────────────────────────────────────────
function injectHoneypotBanner() {
  // Check if chrome storage is available
  if (!chrome || !chrome.storage) {
    return;
  }

  chrome.storage.local.get(["honeypot_mode"], (data) => {
    const isHoneypot = data.honeypot_mode || false;

    // Remove existing banner if honeypot is off
    if (!isHoneypot) {
      removeHoneypotBanner();
      return;
    }

    // Don't inject if already exists
    if (document.getElementById("pg-honeypot-banner")) return;

    const banner = document.createElement("div");
    banner.id = "pg-honeypot-banner";
    banner.innerHTML =
      "🍯 HONEYPOT MODE ACTIVE — Threats are being logged but not blocked. Toggle off in the Prompt Guardian popup.";
    banner.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 32px;
            background: #2D1B0E;
            border-bottom: 2px solid #F59E0B;
            z-index: 99999;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #F59E0B;
            font-size: 12px;
            font-weight: bold;
            font-family: -apple-system, "Segoe UI", sans-serif;
            line-height: 32px;
        `;

    document.body.appendChild(banner);

    // Push down page content
    document.body.style.paddingTop = "32px";
  });
}

function removeHoneypotBanner() {
  const banner = document.getElementById("pg-honeypot-banner");
  if (banner) {
    banner.remove();
    document.body.style.paddingTop = "0";
  }
}

// ── ALERT SOUND ─────────────────────────────────────────────────────────────
function playAlertSound() {
  const ctx = new (window.AudioContext || window.webkitAudioContext)();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.frequency.value = 800;
  gain.gain.value = 0.3;
  osc.start();
  osc.frequency.setValueAtTime(800, ctx.currentTime);
  osc.frequency.setValueAtTime(400, ctx.currentTime + 0.15);
  gain.gain.setValueAtTime(0.3, ctx.currentTime + 0.25);
  gain.gain.setValueAtTime(0, ctx.currentTime + 0.4);
  osc.stop(ctx.currentTime + 0.5);
}

// ── BROWSER NOTIFICATION ────────────────────────────────────────────────────
function showBrowserNotification(result) {
  if (Notification.permission === "granted") {
    new Notification("🛡️ Prompt Guardian Alert", {
      body: `Threat Blocked! Risk: ${result.risk_score}% | Type: ${result.attack_type}`,
      icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>',
    });
  } else {
    Notification.requestPermission();
  }
}
