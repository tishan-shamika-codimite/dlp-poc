/**
 * background.ts — Service Worker
 *
 * Responsibilities:
 *  1. Connect to NativeMessagingHost ("com.dlp.screenshare") and maintain the connection.
 *  2. On screenshare active:  send blur  message to all tabs matching blocked domains.
 *  3. On screenshare stopped: send unblur message to all tabs.
 *  4. Expose storage API for domain list management (popup.ts reads/writes this).
 *  5. Handle messages from content scripts (e.g. ready ping).
 */

import { NativeMessage, ContentMessage, DlpSettings, DEFAULT_SETTINGS } from './types';

// ── Constants ─────────────────────────────────────────────────────────────────

const HOST_NAME = 'com.dlp.screenshare';
const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_DELAY_MS = 30000;

// ── State ─────────────────────────────────────────────────────────────────────

let nativePort: chrome.runtime.Port | null = null;
let reconnectDelay = RECONNECT_DELAY_MS;
let isSharingActive = false;

// ── Settings helpers ──────────────────────────────────────────────────────────

async function getSettings(): Promise<DlpSettings> {
  return new Promise((resolve) => {
    chrome.storage.sync.get('dlpSettings', (result) => {
      if (result['dlpSettings']) {
        resolve(result['dlpSettings'] as DlpSettings);
      } else {
        resolve(DEFAULT_SETTINGS);
      }
    });
  });
}

async function saveSettings(settings: DlpSettings): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.sync.set({ dlpSettings: settings }, resolve);
  });
}

// ── Domain matching ───────────────────────────────────────────────────────────

function isSensitiveUrl(url: string, blockedDomains: string[]): boolean {
  try {
    const hostname = new URL(url).hostname;
    return blockedDomains.some((domain) => {
      // Support wildcard prefix: "*.github.com" matches "gist.github.com"
      if (domain.startsWith('*.')) {
        const base = domain.slice(2);
        return hostname === base || hostname.endsWith('.' + base);
      }
      return hostname === domain || hostname.endsWith('.' + domain);
    });
  } catch {
    return false;
  }
}

// ── Tab messaging ─────────────────────────────────────────────────────────────

async function broadcastToSensitiveTabs(active: boolean): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled) return;

  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (!tab.id || !tab.url) continue;
    if (!isSensitiveUrl(tab.url, settings.blockedDomains)) continue;

    const msg: ContentMessage = { action: active ? 'blur' : 'unblur', active };
    chrome.tabs.sendMessage(tab.id, msg).catch(() => {
      // Tab may not have content script loaded yet — ignore
    });
  }
}

// ── Native Messaging connection ───────────────────────────────────────────────

function connectToHost(): void {
  try {
    nativePort = chrome.runtime.connectNative(HOST_NAME);
  } catch (err) {
    console.error('[DLP] Failed to connect to native host:', err);
    scheduleReconnect();
    return;
  }

  console.log('[DLP] Connected to native host');
  reconnectDelay = RECONNECT_DELAY_MS; // reset backoff

  nativePort.onMessage.addListener((msg: NativeMessage) => {
    if (msg.type === 'screenshare' && typeof msg.active === 'boolean') {
      if (msg.active !== isSharingActive) {
        isSharingActive = msg.active;
        console.log('[DLP] Screen share state changed:', isSharingActive);
        broadcastToSensitiveTabs(isSharingActive);
      }
    }
    // pong is a no-op — just confirms the host is alive
  });

  nativePort.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    console.warn('[DLP] Native host disconnected:', err?.message ?? 'unknown reason');
    nativePort = null;

    // If sharing was active and host died, unblur all tabs for safety
    if (isSharingActive) {
      isSharingActive = false;
      broadcastToSensitiveTabs(false);
    }

    scheduleReconnect();
  });

  // Send a ping immediately to verify the host is alive
  nativePort.postMessage({ type: 'ping' });
}

function scheduleReconnect(): void {
  console.log(`[DLP] Reconnecting in ${reconnectDelay}ms…`);
  setTimeout(() => {
    reconnectDelay = Math.min(reconnectDelay * 2, MAX_RECONNECT_DELAY_MS);
    connectToHost();
  }, reconnectDelay);
}

// ── Extension message handler ─────────────────────────────────────────────────
// Handles messages from popup.ts and content scripts.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getStatus') {
    sendResponse({ sharing: isSharingActive });
    return true;
  }

  // Called by content scripts on load to check if they specifically should show
  // the overlay. Returns both the sharing state AND whether the sender tab's URL
  // is a protected domain — prevents non-sensitive tabs (YouTube, Facebook, etc.)
  // from self-applying the overlay when sharing is active.
  if (message.action === 'getStatusForTab') {
    getSettings().then((settings) => {
      const url = sender.tab?.url ?? '';
      const sensitive = settings.enabled && isSensitiveUrl(url, settings.blockedDomains);
      sendResponse({ sharing: isSharingActive, sensitive });
    });
    return true; // async response
  }

  if (message.action === 'getSettings') {
    getSettings().then((s) => sendResponse(s));
    return true; // async response
  }

  if (message.action === 'saveSettings') {
    saveSettings(message.settings as DlpSettings).then(() => {
      sendResponse({ ok: true });
      // Re-broadcast current state with new settings
      broadcastToSensitiveTabs(isSharingActive);
    });
    return true;
  }

  return false;
});

// ── Tab navigation listener ───────────────────────────────────────────────────
// When a tab navigates to a sensitive page during an active share, blur it immediately.

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!isSharingActive) return;
  if (!tab.url) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  if (isSensitiveUrl(tab.url, settings.blockedDomains)) {
    const msg: ContentMessage = { action: 'blur', active: true };
    chrome.tabs.sendMessage(tabId, msg).catch(() => {});
  }
});

// ── Initialise default settings on first install ──────────────────────────────

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await saveSettings(DEFAULT_SETTINGS);
    console.log('[DLP] Extension installed. Default settings saved.');
  }
});

// ── Boot ──────────────────────────────────────────────────────────────────────

connectToHost();
