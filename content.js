// content.js — DLP Content Script
// ============================================================
// Runs on every page at document_start.
// Intercepts paste, input, and submit events in the CAPTURE phase
// to detect sensitive data before it reaches the DOM/page scripts.
// ============================================================

(function () {
  'use strict';

  // ============================================================
  // DETECTION ENGINE
  // ============================================================

  /**
   * Regex patterns for detecting sensitive data.
   * Each pattern has: regex, label, and a severity level.
   * Order matters — more specific patterns are checked first to avoid
   * the generic API Key regex from matching everything.
   */
  const SENSITIVE_PATTERNS = [
    {
      name: 'AWS Key',
      regex: /AKIA[0-9A-Z]{16}/,
      severity: 'critical'
    },
    {
      name: 'Google API Key',
      regex: /AIza[0-9A-Za-z_-]{35}/,
      severity: 'critical'
    },
    {
      name: 'GitHub Token',
      regex: /gh[ps]_[a-zA-Z0-9]{36}/,
      severity: 'critical'
    },
    {
      name: 'Slack Token',
      regex: /xox[bpars]-[a-zA-Z0-9-]+/,
      severity: 'high'
    },
    {
      name: 'Private Key',
      regex: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
      severity: 'critical'
    },
    {
      name: 'JWT',
      regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
      severity: 'high'
    },
    {
      name: 'SSN',
      regex: /\b\d{3}-\d{2}-\d{4}\b/,
      severity: 'critical'
    },
    {
      name: 'Credit Card',
      regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/,
      severity: 'high'
    },
    {
      name: 'Email',
      regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
      severity: 'medium'
    },
    {
      name: 'API Key',
      // Generic hex key — only match when preceded by key-like context
      regex: /(?:api[_-]?key|secret|token|password|auth)\s*[:=]\s*["\']?([a-f0-9]{32,})["\']?/i,
      severity: 'high'
    },
    {
      name: 'PI: Instruction Override',
      regex: /(?:(?:ignore|bypass|disregard|forget|cancel|override)\s+(?:all\s+)?(?:your\s+)?(?:prior\s+)?(?:previous\s+)?(?:prompt\s+)?(?:instructions|directions|rules|policies|task)|(?:new\s+instructions|your\s+real\s+task\s+is|rules?\s+no\s+longer\s+apply|not\s+restricted|pretend\s+(?:the\s+)?system\s+message))/i,
      severity: 'high'
    },
    {
      name: 'PI: System Extraction',
      regex: /(?:(?:reveal|print|show(?:\s+me)?|dump|output|translate|summarize)\s+(?:your\s+)?(?:hidden\s+)?(?:internal\s+)?(?:initial\s+)?(?:developer\s+)?(?:system\s+)?(?:prompt|instructions|configuration|rules|policy\s+text|message)|(?:what\s+were\s+you\s+told|what\s+are\s+your\s+internal\s+rules))/i,
      severity: 'high'
    },
    {
      name: 'PI: Persona Jailbreak',
      regex: /(?:(?:you\s+are|assume\s+(?:the\s+)?role|act\s+as|roleplay\s+as|pretend).{0,30}\b(?:dan|unrestricted\s+ai|root|an\s+evil\s+ai|hacker|a\s+model\s+without\s+limitations)\b|(?:enter|activate)\s+(?:developer|admin)\s+mode)/i,
      severity: 'high'
    },
    {
      name: 'PI: Authority',
      regex: /(?:i\s+am\s+(?:the\s+)?(?:administrator|developer)|(?:openai|creator)\s+(?:authorized|requested)\s+this|this\s+is\s+a\s+(?:system\s+update|security\s+test)|(?:internal\s+audit\s+mode|developer\s+override|maintenance\s+instruction)\s+(?:enabled|granted|follows))/i,
      severity: 'high'
    },
    {
      name: 'PI: Fake Context',
      regex: /(?:\[(?:admin\s+message|system|developer|root|admin)\]|<system>|<instruction>|<override>|###\s+IMPORTANT\s+SYSTEM\s+MESSAGE\s+###)/i,
      severity: 'high'
    },
    {
      name: 'PI: Context Manipulation',
      regex: /(?:previous\s+message\s+was\s+a\s+mistake|user\s+(?:before\s+me\s+)?authorized\s+this|assume\s+all\s+previous\s+content|continue\s+from\s+the\s+hidden\s+context|use\s+the\s+original\s+instructions|restore\s+the\s+unrestricted\s+version|conversation\s+has\s+been\s+reset)/i,
      severity: 'high'
    },
    {
      name: 'PI: Tool Abuse',
      regex: /(?:call\s+this\s+api|ignore\s+approval|upload\s+this\s+file|execute\s+this\s+(?:command|shell)|run\s+this\s+(?:code|script)|access\s+private\s+files|sudo\s+rm\s+-rf|disable\s+security|remove\s+authentication|turn\s+off\s+validation)/i,
      severity: 'high'
    },
    {
      name: 'PI: Base64',
      regex: /(?:SWdub3Jl)/i,
      severity: 'medium'
    }
  ];

  /**
   * Detect sensitive data in the provided text.
   * Returns the first match found (most specific pattern wins).
   *
   * @param {string} text - The text to scan
   * @returns {{ isSensitive: boolean, type?: string, severity?: string, matches?: string[] }}
   */
  function detectSensitiveData(text) {
    if (!text || typeof text !== 'string' || text.length < 3) {
      return { isSensitive: false };
    }

    const allMatches = [];

    for (const pattern of SENSITIVE_PATTERNS) {
      const match = text.match(pattern.regex);
      if (match) {
        allMatches.push({
          type: pattern.name,
          severity: pattern.severity,
          match: match[0]
        });
      }
    }

    if (allMatches.length > 0) {
      // Return the highest-severity match
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      allMatches.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

      return {
        isSensitive: true,
        type: allMatches[0].type,
        severity: allMatches[0].severity,
        matches: allMatches.map(m => m.type)
      };
    }

    return { isSensitive: false };
  }

  // ============================================================
  // EVENT INTERCEPTION
  // ============================================================

  /**
   * Handle paste events — intercept in capture phase.
   * This fires BEFORE the page's own paste handlers.
   */
  document.addEventListener('paste', function handlePaste(event) {
    const clipboardData = event.clipboardData || window.clipboardData;
    if (!clipboardData) return;

    const pastedText = clipboardData.getData('text/plain');
    if (!pastedText) return;

    const result = detectSensitiveData(pastedText);

    if (result.isSensitive) {
      if (event.isTrusted && event.target.dataset.dlpBypass && (Date.now() - parseInt(event.target.dataset.dlpBypass) < 15000)) {
        // Bypass active, allow it through
        delete event.target.dataset.dlpBypass;
        return;
      }

      // HARD BLOCK — prevent the paste from reaching the DOM
      event.preventDefault();
      event.stopImmediatePropagation();

      // Show warning toast
      showWarning(event.target, result, event.isTrusted);

      // Report to background service worker
      reportBlock(result, 'paste');
    }
  }, true); // capture phase

  /**
   * Handle form submissions — scan all fields before submit.
   */
  document.addEventListener('submit', function handleSubmit(event) {
    const form = event.target;
    if (!form || form.tagName !== 'FORM') return;

    // Collect all text from form fields
    const fields = form.querySelectorAll('input, textarea');
    for (const field of fields) {
      const value = field.value || '';
      const result = detectSensitiveData(value);

      if (result.isSensitive) {
        if (event.isTrusted && field.dataset.dlpBypass && (Date.now() - parseInt(field.dataset.dlpBypass) < 15000)) {
          // Bypass active
          delete field.dataset.dlpBypass;
          continue;
        }

        // Block the form submission
        event.preventDefault();
        event.stopImmediatePropagation();

        showWarning(field, result, event.isTrusted);
        reportBlock(result, 'submit');
        return; // Stop checking other fields
      }
    }
  }, true); // capture phase

  /**
   * Handle Enter key presses — catch submissions before ChatGPT's JS handles them.
   * Attached to 'window' to ensure it runs before any React/ProseMirror listeners.
   */
  window.addEventListener('keydown', function handleKeydown(event) {
    if (event.key !== 'Enter') return;

    const target = event.target;
    if (!target) return;

    const tagName = target.tagName;
    if (tagName !== 'INPUT' && tagName !== 'TEXTAREA' && !target.isContentEditable) return;

    const value = target.isContentEditable
      ? (target.innerText || target.textContent || '')
      : (target.value || '');

    const result = detectSensitiveData(value);

    if (result.isSensitive) {
      if (event.isTrusted && target.dataset.dlpBypass && (Date.now() - parseInt(target.dataset.dlpBypass) < 15000)) {
        // Bypass active
        delete target.dataset.dlpBypass;
        return;
      }

      // HARD BLOCK — prevent the enter key from triggering a send
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      // Clear the sensitive text ONLY if not trusted (automated agent)
      if (!event.isTrusted) {
        if (target.isContentEditable) {
          target.focus();
          document.execCommand('selectAll', false, null);
          document.execCommand('delete', false, null);
          // Fallback
          if (target.textContent) target.textContent = '';
        } else {
          target.value = '';
        }
      }

      showWarning(target, result, event.isTrusted);
      reportBlock(result, 'submit');
    }
  }, true);

  /**
   * Handle input events — monitor text being typed/autofilled.
   * Uses a debounce to avoid scanning on every keystroke.
   */
  let inputDebounceTimer = null;

  document.addEventListener('input', function handleInput(event) {
    const target = event.target;
    if (!target) return;

    // Only check text inputs and textareas
    const tagName = target.tagName;
    if (tagName !== 'INPUT' && tagName !== 'TEXTAREA' && !target.isContentEditable) return;

    // Risk 6 fix: Never scan password fields — avoid reading auth credentials
    if (target.type === 'password') return;

    // Debounce: only scan after 500ms of inactivity
    clearTimeout(inputDebounceTimer);
    inputDebounceTimer = setTimeout(() => {
      const value = target.isContentEditable
        ? (target.innerText || target.textContent || '')
        : (target.value || '');

      const result = detectSensitiveData(value);

      if (result.isSensitive) {
        if (event.isTrusted && target.dataset.dlpBypass && (Date.now() - parseInt(target.dataset.dlpBypass) < 15000)) {
          return;
        }

        // Clear the sensitive text ONLY if not trusted
        if (!event.isTrusted) {
          if (target.isContentEditable) {
            target.focus();
            document.execCommand('selectAll', false, null);
            document.execCommand('delete', false, null);
            // Fallback
            if (target.textContent) target.textContent = '';
          } else {
            target.value = '';
          }
        }

        showWarning(target, result, event.isTrusted);
        reportBlock(result, 'input');
      }
    }, 500);
  }, true);

  /**
   * Handle beforeinput events — catch programmatic insertions.
   * This catches cases where scripts inject text via insertText commands.
   */
  document.addEventListener('beforeinput', function handleBeforeInput(event) {
    if (event.inputType !== 'insertFromPaste' && event.inputType !== 'insertFromDrop') return;

    const data = event.data || (event.dataTransfer && event.dataTransfer.getData('text/plain'));
    if (!data) return;

    const result = detectSensitiveData(data);

    if (result.isSensitive) {
      event.preventDefault();
      event.stopImmediatePropagation();

      showWarning(event.target, result);
      reportBlock(result, event.inputType);
    }
  }, true);

  /**
   * Handle drop events — prevent sensitive data from being dragged in.
   */
  document.addEventListener('drop', function handleDrop(event) {
    const dataTransfer = event.dataTransfer;
    if (!dataTransfer) return;

    const droppedText = dataTransfer.getData('text/plain');
    if (!droppedText) return;

    const result = detectSensitiveData(droppedText);

    if (result.isSensitive) {
      if (event.isTrusted && event.target.dataset.dlpBypass && (Date.now() - parseInt(event.target.dataset.dlpBypass) < 15000)) {
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      showWarning(event.target, result, event.isTrusted);
      reportBlock(result, 'drop');
    }
  }, true);


  // ============================================================
  // WARNING UI
  // ============================================================

  /**
   * Color map for different detection types (matches the popup dashboard)
   */
  const TYPE_COLORS = {
    'AWS Key': '#FF6B6B',
    'Credit Card': '#FFD93D',
    'Email': '#6BCB77',
    'SSN': '#FF8C42',
    'JWT': '#4D96FF',
    'GitHub Token': '#9B59B6',
    'Private Key': '#E74C3C',
    'Slack Token': '#1ABC9C',
    'Google API Key': '#F39C12',
    'API Key': '#3498DB'
  };

  /**
   * Show an inline warning toast near the blocked element.
   *
   * @param {HTMLElement} element - The element where the paste/input was blocked
   * @param {{ type: string, severity: string, matches?: string[] }} result - Detection result
   */
  /**
   * Validate that a color string is a safe hex color.
   * Prevents CSS injection via color values.
   */
  function safeColor(color) {
    return /^#[0-9A-Fa-f]{6}$/.test(color) ? color : '#FF6B6B';
  }

  /**
   * Inject the warning stylesheet once (idempotent).
   * Uses CSS custom properties for colors — no string interpolation in CSS.
   */
  let styleInjected = false;
  function injectWarningStyles() {
    if (styleInjected) return;
    styleInjected = true;

    const style = document.createElement('style');
    style.textContent = `
      .ai-dlp-warning {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
        pointer-events: none;
        animation: ai-dlp-slide-in 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
      }

      .ai-dlp-warning-card {
        background: rgba(13, 13, 26, 0.92);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-left: 4px solid var(--dlp-accent);
        border-radius: 12px;
        padding: 16px 20px;
        min-width: 300px;
        max-width: 420px;
        box-shadow:
          0 8px 32px rgba(0, 0, 0, 0.5),
          0 0 0 1px rgba(255, 255, 255, 0.05);
      }

      .ai-dlp-warning-header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 8px;
      }

      .ai-dlp-warning-icon {
        font-size: 20px;
        line-height: 1;
      }

      .ai-dlp-warning-title {
        font-size: 14px;
        font-weight: 700;
        color: #FFFFFF;
        letter-spacing: 0.02em;
      }

      .ai-dlp-warning-body {
        font-size: 13px;
        color: rgba(255, 255, 255, 0.7);
        line-height: 1.5;
      }

      .ai-dlp-warning-badge {
        display: inline-block;
        font-size: 11px;
        font-weight: 600;
        padding: 3px 8px;
        border-radius: 6px;
        margin-top: 8px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--dlp-accent);
        background: color-mix(in srgb, var(--dlp-accent) 13%, transparent);
        border: 1px solid color-mix(in srgb, var(--dlp-accent) 27%, transparent);
      }

      .ai-dlp-warning-progress {
        height: 2px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 1px;
        margin-top: 12px;
        overflow: hidden;
      }

      .ai-dlp-warning-progress-bar {
        height: 100%;
        background: var(--dlp-accent);
        border-radius: 1px;
        animation: ai-dlp-progress 3s linear forwards;
      }

      @keyframes ai-dlp-slide-in {
        from { opacity: 0; transform: translateX(40px) scale(0.95); }
        to   { opacity: 1; transform: translateX(0) scale(1); }
      }

      @keyframes ai-dlp-slide-out {
        from { opacity: 1; transform: translateX(0) scale(1); }
        to   { opacity: 0; transform: translateX(40px) scale(0.95); }
      }

      @keyframes ai-dlp-progress {
        from { width: 100%; }
        to   { width: 0%; }
      }

      .ai-dlp-bypass-btn {
        margin-top: 10px;
        background: transparent;
        border: 1px solid rgba(255, 255, 255, 0.2);
        color: rgba(255, 255, 255, 0.8);
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 11px;
        cursor: pointer;
        transition: background 0.2s;
      }
      .ai-dlp-bypass-btn:hover {
        background: rgba(255, 255, 255, 0.1);
      }
    `;
    document.documentElement.appendChild(style);
  }

  function showWarning(element, result, canBypass = false) {
    // Remove any existing warnings first
    const existing = document.querySelectorAll('.ai-dlp-warning');
    existing.forEach(el => el.remove());

    // Validate color to prevent CSS injection
    const accentColor = safeColor(TYPE_COLORS[result.type] || '#FF6B6B');

    // Inject stylesheet once (idempotent)
    injectWarningStyles();

    // Build warning DOM entirely via createElement — no innerHTML for structure
    const warning = document.createElement('div');
    warning.className = 'ai-dlp-warning';
    warning.setAttribute('role', 'alert');
    warning.setAttribute('aria-live', 'assertive');
    warning.style.setProperty('--dlp-accent', accentColor);

    const card = document.createElement('div');
    card.className = 'ai-dlp-warning-card';

    const header = document.createElement('div');
    header.className = 'ai-dlp-warning-header';

    const icon = document.createElement('span');
    icon.className = 'ai-dlp-warning-icon';
    icon.textContent = '🛡️';

    const title = document.createElement('span');
    title.className = 'ai-dlp-warning-title';
    title.textContent = 'Data Leak Blocked';

    header.appendChild(icon);
    header.appendChild(title);

    const body = document.createElement('div');
    body.className = 'ai-dlp-warning-body';
    body.textContent = 'Sensitive data was detected and prevented from being sent.';

    const badge = document.createElement('span');
    badge.className = 'ai-dlp-warning-badge';
    const badgeLabel = result.type + (result.matches && result.matches.length > 1
      ? ' +' + (result.matches.length - 1) + ' more'
      : '');
    badge.textContent = badgeLabel; // textContent auto-escapes — no XSS possible

    const progress = document.createElement('div');
    progress.className = 'ai-dlp-warning-progress';
    const progressBar = document.createElement('div');
    progressBar.className = 'ai-dlp-warning-progress-bar';
    progress.appendChild(progressBar);

    card.appendChild(header);
    card.appendChild(body);
    card.appendChild(badge);

    if (canBypass) {
      const bypassBtn = document.createElement('button');
      bypassBtn.className = 'ai-dlp-bypass-btn';
      bypassBtn.textContent = 'Allow Anyway';
      bypassBtn.onclick = () => {
        element.dataset.dlpBypass = Date.now();
        warning.style.animation = 'ai-dlp-slide-out 0.3s ease-in forwards';
        setTimeout(() => { if (warning.parentNode) warning.remove(); }, 300);
      };
      card.appendChild(bypassBtn);
    }

    card.appendChild(progress);
    warning.appendChild(card);

    document.documentElement.appendChild(warning);

    // Auto-dismiss after 4 seconds with slide-out animation
    setTimeout(() => {
      warning.style.animation = 'ai-dlp-slide-out 0.3s ease-in forwards';
      setTimeout(() => {
        if (warning.parentNode) {
          warning.remove();
        }
      }, 300);
    }, 4000);
  }

  // ============================================================
  // REPORTING
  // ============================================================

  /**
   * Report a blocked event to the background service worker.
   *
   * @param {{ type: string, severity: string }} result - Detection result
   * @param {string} inputType - How the data was entered (paste, input, submit, drop)
   */
  function reportBlock(result, inputType) {
    try {
      chrome.runtime.sendMessage({
        type: 'blockedPaste',
        data: {
          type: result.type,
          domain: window.location.hostname,
          timestamp: Date.now(),
          inputType: inputType
        }
      });
    } catch (e) {
      // Extension context may be invalidated — fail silently
      // Removed console.warn so Chrome doesn't flag this in the Extensions menu
    }
  }

  // ============================================================
  // EXPORT FOR TESTING (development only)
  // Only expose detection function when NOT running inside the
  // extension context — prevents malicious pages from probing
  // detection patterns via window.__AI_DLP_DETECT.
  // ============================================================
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.id) {
    window.__AI_DLP_DETECT = detectSensitiveData;
  }

})();
