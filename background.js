// background.js — Service Worker (MV3)
// ============================================================
// CRITICAL: No global state. Service workers restart after ~5 min idle.
// All data persisted to chrome.storage.local.
// All listeners registered synchronously at top level.
// ============================================================

const DEFAULT_METRICS = {
  totalBlocks: 0,
  blocksByType: {},
  blocksByDomain: {},
  recentEvents: []
};

const MAX_RECENT_EVENTS = 50;
const MAX_DOMAINS = 100;

// ---- Initialize storage on install ----
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get('metrics', (result) => {
    if (!result.metrics) {
      chrome.storage.local.set({ metrics: DEFAULT_METRICS });
    }
  });
});

// ---- Message handler (single listener for all message types) ----
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Risk 5 fix: Validate message origin — only accept from our own extension
  if (sender.id !== chrome.runtime.id) return;

  switch (message.type) {
    case 'blockedPaste':
      handleBlockedPaste(message.data, sender);
      // No async response needed — fire and forget
      break;

    case 'getMetrics':
      // Async: must return true to keep channel open
      chrome.storage.local.get('metrics', (result) => {
        sendResponse(result.metrics || DEFAULT_METRICS);
      });
      return true;

    case 'clearMetrics':
      chrome.storage.local.set({ metrics: DEFAULT_METRICS }, () => {
        sendResponse({ success: true });
      });
      return true;

    default:
      break;
  }
});

// ---- Handle a blocked paste event ----
function handleBlockedPaste(data, sender) {
  chrome.storage.local.get('metrics', (result) => {
    const metrics = result.metrics || { ...DEFAULT_METRICS };

    // Increment total blocks
    metrics.totalBlocks++;

    // Increment by type
    const type = data.type || 'Unknown';
    metrics.blocksByType[type] = (metrics.blocksByType[type] || 0) + 1;

    // Increment by domain
    let domain = 'unknown';
    try {
      if (sender && sender.tab && sender.tab.url) {
        domain = new URL(sender.tab.url).hostname;
      } else if (data.domain) {
        domain = data.domain;
      }
    } catch (e) {
      domain = data.domain || 'unknown';
    }
    metrics.blocksByDomain[domain] = (metrics.blocksByDomain[domain] || 0) + 1;

    // Risk 4 fix: Cap domains to prevent unbounded storage growth
    const domainKeys = Object.keys(metrics.blocksByDomain);
    if (domainKeys.length > MAX_DOMAINS) {
      // Remove the least-active domains, keeping the top MAX_DOMAINS
      const sorted = domainKeys.sort((a, b) => metrics.blocksByDomain[b] - metrics.blocksByDomain[a]);
      const toRemove = sorted.slice(MAX_DOMAINS);
      toRemove.forEach(key => delete metrics.blocksByDomain[key]);
    }

    // Add to recent events (capped at MAX_RECENT_EVENTS)
    metrics.recentEvents.unshift({
      type: type,
      domain: domain,
      timestamp: data.timestamp || Date.now(),
      inputType: data.inputType || 'paste'
    });

    if (metrics.recentEvents.length > MAX_RECENT_EVENTS) {
      metrics.recentEvents = metrics.recentEvents.slice(0, MAX_RECENT_EVENTS);
    }

    // Persist
    chrome.storage.local.set({ metrics: metrics });
  });
}
