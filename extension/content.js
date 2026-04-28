// Prompt Guardian - Content Script

const API_URL = 'http://localhost:5000/analyze';
let isAnalyzing = false;

const PLATFORM_SELECTORS = {
    'chat.openai.com': { input: '#prompt-textarea', send: '[data-testid="send-button"]' },
    'chatgpt.com': { input: '#prompt-textarea', send: '[data-testid="send-button"]' },
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

        const result = await response.json();
        hideLoadingIndicator();

        if (result.action === 'ALLOW') {
            showSafeBadge(result.risk_score || 0);
            logToHistory(promptText, result);
            proceedWithSend(sel);
        } else if (result.action === 'WARN') {
            showWarningOverlay(promptText, result, sel, inputEl);
        } else {
            showBlockOverlay(promptText, result, sel, inputEl);
        }

    } catch (err) {
        // FAIL-OPEN fallback (mock behavior)
        hideLoadingIndicator();
        console.warn('API failed, using mock:', err);

        if (promptText.toLowerCase().includes('ignore')) {
            showBlockOverlay(promptText, {
                action: 'BLOCK',
                risk_score: 90,
                attack_type: 'Instruction Override',
                sanitized_prompt: 'Hello'
            }, sel, inputEl);
        } else {
            proceedWithSend(sel);
        }

    } finally {
        isAnalyzing = false;
    }
}

// ---------------- OVERLAYS ----------------
function showBlockOverlay(original, result, sel, inputEl) {
    document.getElementById('pg-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';

    overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header danger">🚨 Threat Detected</div>
      <div class="pg-body">
        <div class="pg-score-row">
          <div class="pg-score danger">Risk: ${result.risk_score || 0}%</div>
          <div>${result.attack_type || 'Unknown'}</div>
        </div>

        <textarea id="pg-clean" class="pg-sanitized">${escapeHtml(result.sanitized_prompt || '')}</textarea>

        <div class="pg-actions">
          <button class="pg-btn safe" id="pg-clean-send">Send Sanitized</button>
          <button class="pg-btn warn" id="pg-orig-send">Send Anyway</button>
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

    injectStyles();
    document.body.appendChild(overlay);

    document.getElementById('pg-clean-send').onclick = () => {
        setInputValue(inputEl, document.getElementById('pg-clean').value);
        overlay.remove();
        logToHistory(original, result, 'sanitized');
        setTimeout(() => proceedWithSend(sel), 100);
    };

    document.getElementById('pg-orig-send').onclick = () => {
        overlay.remove();
        logToHistory(original, result, 'override');
        proceedWithSend(sel);
    };

    document.getElementById('pg-cancel').onclick = () => overlay.remove();
}

function showWarningOverlay(original, result, sel, inputEl) {
    document.getElementById('pg-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';

    overlay.innerHTML = `
    <div class="pg-modal">
      <div class="pg-header warn">⚠️ Suspicious Prompt</div>
      <div class="pg-body">
        <div class="pg-score warn">Risk: ${result.risk_score || 0}%</div>

        <div class="pg-actions">
          <button class="pg-btn warn" id="pg-orig-send">Send Anyway</button>
          <button class="pg-btn cancel" id="pg-cancel">Cancel</button>
        </div>
      </div>
    </div>
  `;

    injectStyles();
    document.body.appendChild(overlay);

    document.getElementById('pg-orig-send').onclick = () => {
        overlay.remove();
        logToHistory(original, result, 'override');
        proceedWithSend(sel);
    };

    document.getElementById('pg-cancel').onclick = () => overlay.remove();
}

// ---------------- UTIL ----------------
function proceedWithSend(sel) {
    document.querySelector(sel.send)?.click();
}

function setInputValue(el, value) {
    if (el.tagName === 'TEXTAREA') {
        const setter = Object.getOwnPropertyDescriptor(
            HTMLTextAreaElement.prototype, 'value'
        ).set;
        setter.call(el, value);
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
        .replace(/>/g, '&gt;');
}

function logToHistory(prompt, result, userAction = 'auto') {
    chrome.storage.local.get(['pg_history'], (data) => {
        const history = data.pg_history || [];

        history.unshift({
            timestamp: new Date().toISOString(),
            prompt: prompt.slice(0, 120),
            risk_score: result.risk_score,
            action: result.action,
            attack_type: result.attack_type,
            user_action: userAction,
        });

        chrome.storage.local.set({ pg_history: history.slice(0, 100) });
    });
}

// ---------------- ATTACH ----------------
function attachInterceptor() {
    const sel = getSelectors();
    const btn = document.querySelector(sel.send);

    if (btn && !btn._pgAttached) {
        btn.addEventListener('click', interceptPrompt, true);
        btn._pgAttached = true;
        console.log('Prompt Guardian Active');
    }
}

new MutationObserver(attachInterceptor)
    .observe(document.body, { childList: true, subtree: true });

attachInterceptor();

// ---------------- UI ----------------
function showLoadingIndicator() {
    if (document.getElementById('pg-loading')) return;

    const el = document.createElement('div');
    el.id = 'pg-loading';
    el.innerText = 'Analyzing...';
    el.style.cssText =
        'position:fixed;bottom:20px;right:20px;background:#1B3A6B;color:white;padding:10px;border-radius:8px;z-index:99999';
    document.body.appendChild(el);
}

function hideLoadingIndicator() {
    document.getElementById('pg-loading')?.remove();
}

function showSafeBadge(score) {
    const el = document.createElement('div');
    el.innerText = `Safe (${score}%)`;
    el.style.cssText =
        'position:fixed;bottom:20px;right:20px;background:#059669;color:white;padding:8px;border-radius:8px;z-index:99999';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2000);
}

function injectStyles() {
    if (document.getElementById('pg-styles')) return;

    const style = document.createElement('style');
    style.id = 'pg-styles';

    style.textContent = `
    #pg-overlay { position:fixed;inset:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:999999 }
    .pg-modal { background:#0F1729;color:white;width:500px;padding:20px;border-radius:12px }
    .pg-header.danger { background:#DC2626;padding:10px;border-radius:8px }
    .pg-header.warn { background:#D97706;padding:10px;border-radius:8px }
    .pg-actions { margin-top:15px;display:flex;gap:10px }
    .pg-btn { padding:8px 12px;border:none;border-radius:6px;cursor:pointer }
    .pg-btn.safe { background:#059669;color:white }
    .pg-btn.warn { background:#D97706;color:white }
    .pg-btn.cancel { background:#444;color:white }
    textarea { width:100%;margin-top:10px }
  `;

    document.head.appendChild(style);
}