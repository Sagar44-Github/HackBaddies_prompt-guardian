// Prompt Guardian - Content Script

const API_URL = 'http://127.0.0.1:5000/analyze';
let isAnalyzing = false;

const PLATFORM_SELECTORS = {
    'chat.openai.com': { input: '#prompt-textarea', send: '#composer-submit-button, [data-testid="send-button"]' },
    'chatgpt.com': { input: '#prompt-textarea', send: '#composer-submit-button, [data-testid="send-button"]' },
    'gemini.google.com': { input: '.ql-editor', send: '.send-button' },
    'claude.ai': { input: '[contenteditable="true"]', send: '[aria-label="Send Message"]' },
};

function getSelectors() {
    const host = window.location.hostname;
    return PLATFORM_SELECTORS[host] || { input: 'textarea', send: 'button[type=submit]' };
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
        inputEl.value || inputEl.innerText || inputEl.textContent || '';

    if (!promptText.trim() || promptText.trim().length < 3) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    isAnalyzing = true;
    showLoadingIndicator();

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt: promptText })
        });

        if (!response.ok) {
            if (response.status === 403) {
                const errorData = await response.json().catch(() => ({}));
                hideLoadingIndicator();
                showBanOverlay(errorData.ban_remaining_seconds || 0);
                return;
            }
            throw new Error('API returned ' + response.status);
        }

        const result = await response.json();
        hideLoadingIndicator();

        if (result.action === 'ALLOW') {
            showSafeBadge(result.risk_score || 0);
            logToHistory(promptText, result, 'auto', () => {
                proceedWithSend(sel);
            });
        } else if (result.action === 'WARN') {
            logToHistory(promptText, result);
            showWarningOverlay(promptText, result, sel, inputEl);
        } else {
            logToHistory(promptText, result);
            showBlockOverlay(promptText, result, sel, inputEl);
        }

    } catch (err) {
        hideLoadingIndicator();
        console.warn('Prompt Guardian: API unavailable, allowing prompt through:', err.message);
        // Fail-open: if API is down, let the prompt through
        proceedWithSend(sel);
    } finally {
        isAnalyzing = false;
    }
}

// ---------------- OVERLAYS ----------------
function showBlockOverlay(original, result, sel, inputEl) {
    document.getElementById('pg-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';

    const riskScore = result.risk_score || 0;
    const attackType = result.attack_type || 'Unknown';
    const attackLabel = result.attack_label || attackType;
    const explanation = result.explanation || '';
    const sanitized = result.sanitized_prompt || '';

    // Check if sanitized version is actually useful
    // (not a blocking message and not just [REDACTED] markers)
    const isUsefulSanitized = sanitized
        && !sanitized.startsWith('[Entire prompt')
        && sanitized.replace(/\[REDACTED\]/g, '').trim().length > 3;

    overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header danger">🚨 Threat Detected — ${attackLabel}</div>
      <div class="pg-body">
        <div class="pg-score-row">
          <div class="pg-score danger">Risk: ${riskScore}%</div>
          <div class="pg-confidence">${result.confidence || ''} confidence</div>
        </div>

        <div class="pg-explanation">${escapeHtml(explanation)}</div>

        ${isUsefulSanitized ? `
        <div class="pg-sanitized-label">Sanitized version (injection removed):</div>
        <textarea id="pg-clean" class="pg-sanitized">${escapeHtml(sanitized)}</textarea>
        ` : `
        <div class="pg-blocked-msg">This prompt is entirely malicious and has been blocked.</div>
        `}

        <div class="pg-actions">
          ${isUsefulSanitized ? '<button class="pg-btn safe" id="pg-clean-send">Send Sanitized</button>' : ''}
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

    injectStyles();
    document.body.appendChild(overlay);

    const cleanSendBtn = document.getElementById('pg-clean-send');
    if (cleanSendBtn) {
        cleanSendBtn.onclick = () => {
            const cleanText = document.getElementById('pg-clean').value;
            setInputValue(inputEl, cleanText);
            overlay.remove();
            logToHistory(original, result, 'sanitized');
            setTimeout(() => proceedWithSend(sel), 100);
        };
    }

    document.getElementById('pg-cancel').onclick = () => overlay.remove();
}

function showWarningOverlay(original, result, sel, inputEl) {
    document.getElementById('pg-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';

    const riskScore = result.risk_score || 0;
    const explanation = result.explanation || 'This prompt contains suspicious patterns.';

    overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header warn">⚠️ Suspicious Prompt Detected</div>
      <div class="pg-body">
        <div class="pg-score warn">Risk: ${riskScore}%</div>
        <div class="pg-explanation">${escapeHtml(explanation)}</div>

        <div class="pg-blocked-msg">This prompt has been flagged as suspicious and cannot be sent.</div>

        <div class="pg-actions">
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

    injectStyles();
    document.body.appendChild(overlay);

    document.getElementById('pg-cancel').onclick = () => overlay.remove();
}

function showBanOverlay(remainingSeconds) {
    document.getElementById('pg-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';

    const hours = Math.floor(remainingSeconds / 3600);
    const minutes = Math.floor((remainingSeconds % 3600) / 60);
    const timeText = hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;

    overlay.innerHTML = `
    <div class="pg-modal" style="border: 2px solid #DC2626;">
      <div class="pg-header danger">⛔ Account Suspended</div>
      <div class="pg-body">
        <div class="pg-score danger" style="font-size: 18px; margin-bottom: 15px;">You are temporarily banned.</div>
        <div class="pg-explanation" style="font-size: 14px; text-align: center;">
          Due to repeated violations of the safety policies, your access to AI prompts has been suspended.
        </div>
        <div class="pg-blocked-msg" style="font-size: 16px; padding: 15px;">
          Time remaining: <strong>${timeText}</strong>
        </div>
        <div class="pg-actions" style="justify-content: center; margin-top: 15px;">
          <button class="pg-btn cancel" id="pg-cancel-ban">Close</button>
        </div>
      </div>
    </div>
  `;

    injectStyles();
    document.body.appendChild(overlay);

    document.getElementById('pg-cancel-ban').onclick = () => overlay.remove();
}

// ---------------- UTIL ----------------
function proceedWithSend(sel) {
    const btn = document.querySelector(sel.send);
    if (btn) {
        // Briefly remove our interceptor so the click goes through
        btn.removeEventListener('click', interceptPrompt, true);
        btn.click();
        // Re-attach after a tick
        setTimeout(() => {
            btn.addEventListener('click', interceptPrompt, true);
        }, 200);
    }
}

function setInputValue(el, value) {
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
        const setter = Object.getOwnPropertyDescriptor(
            window.HTMLTextAreaElement.prototype, 'value'
        )?.set || Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value'
        )?.set;
        if (setter) {
            setter.call(el, value);
        } else {
            el.value = value;
        }
        el.dispatchEvent(new Event('input', { bubbles: true }));
    } else {
        el.innerText = value;
        el.dispatchEvent(new InputEvent('input', { bubbles: true }));
    }
}

function escapeHtml(str) {
    return (str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function logToHistory(prompt, result, userAction = 'auto', onDone = null) {
    try {
        chrome.storage.local.get(['pg_history'], (data) => {
            const history = data.pg_history || [];

            history.unshift({
                timestamp: new Date().toISOString(),
                prompt: prompt.slice(0, 120),
                risk_score: result.risk_score || 0,
                action: result.action || 'ALLOW',
                attack_type: result.attack_type || null,
                user_action: userAction,
            });

            // Keep max 100 entries
            chrome.storage.local.set({ pg_history: history.slice(0, 100) }, () => {
                if (onDone) onDone();
            });
        });
    } catch (e) {
        console.warn('Prompt Guardian: storage unavailable', e);
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
        btn.addEventListener('click', interceptPrompt, true);
        btn._pgAttached = true;
        console.log('Prompt Guardian: Attached to send button');
    }

    // Intercept Enter key on input field
    if (inputEl && !inputEl._pgKeyAttached) {
        inputEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                interceptPrompt(e);
            }
        }, true);
        inputEl._pgKeyAttached = true;
        console.log('Prompt Guardian: Attached to input field (Enter key)');
    }

    // Intercept form submit (ChatGPT wraps input in a form)
    const form = inputEl?.closest('form');
    if (form && !form._pgFormAttached) {
        form.addEventListener('submit', interceptPrompt, true);
        form._pgFormAttached = true;
        console.log('Prompt Guardian: Attached to form submit');
    }

    if (btn || inputEl) {
        console.log('Prompt Guardian: Active on', window.location.hostname);
    }
}

// Watch for DOM changes (SPAs re-render the send button)
new MutationObserver(attachInterceptor)
    .observe(document.body, { childList: true, subtree: true });

attachInterceptor();

// ---------------- STYLES ----------------
function showLoadingIndicator() {
    if (document.getElementById('pg-loading')) return;

    const el = document.createElement('div');
    el.id = 'pg-loading';
    el.innerHTML = '<span class="pg-spinner"></span> Analyzing prompt...';
    el.style.cssText =
        'position:fixed;bottom:20px;right:20px;background:#1B3A6B;color:white;' +
        'padding:12px 18px;border-radius:10px;z-index:99999;font-family:sans-serif;' +
        'font-size:13px;display:flex;align-items:center;gap:8px;' +
        'box-shadow:0 4px 16px rgba(0,0,0,0.3)';
    document.body.appendChild(el);
}

function hideLoadingIndicator() {
    document.getElementById('pg-loading')?.remove();
}

function showSafeBadge(score) {
    const el = document.createElement('div');
    el.id = 'pg-safe-badge';
    el.innerHTML = `✅ Safe <span style="opacity:0.7">(${score}% risk)</span>`;
    el.style.cssText =
        'position:fixed;bottom:20px;right:20px;background:#059669;color:white;' +
        'padding:10px 16px;border-radius:10px;z-index:99999;font-family:sans-serif;' +
        'font-size:13px;box-shadow:0 4px 16px rgba(0,0,0,0.3);' +
        'transition:opacity 0.3s ease';
    document.body.appendChild(el);
    setTimeout(() => {
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 300);
    }, 2000);
}

function injectStyles() {
    if (document.getElementById('pg-styles')) return;

    const style = document.createElement('style');
    style.id = 'pg-styles';

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

    .pg-blocked-msg {
        font-size: 13px;
        color: #F87171;
        padding: 12px;
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