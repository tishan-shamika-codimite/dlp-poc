/**
 * background.ts — Service Worker
 *
 * Responsibilities:
 *  1. Connect to NativeMessagingHost ("com.dlp.screenshare") and maintain the connection.
 *  2. On screenshare active:  send blur  message to all tabs matching blocked domains.
 *  3. On screenshare stopped: send unblur message to all tabs.
 *  4. Handle browser-based screen share signals from inject.ts via content.ts
 *     (getDisplayMedia interception — covers Google Meet, Zoom web, Teams web, etc.)
 *  5. Expose storage API for domain list management (popup.ts reads/writes this).
 *  6. Handle messages from content scripts (e.g. ready ping).
 */

import { NativeMessage, ContentMessage, DlpSettings, DEFAULT_SETTINGS } from './types';

// ── Constants ─────────────────────────────────────────────────────────────────

const HOST_NAME = 'com.dlp.screenshare';
const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_DELAY_MS = 30000;

// ── State ─────────────────────────────────────────────────────────────────────

let nativePort: chrome.runtime.Port | null = null;
let reconnectDelay = RECONNECT_DELAY_MS;

// Set by the native host when Zoom / Teams desktop app is sharing.
let isSharingActive = false;

// Set by inject.ts (via content.ts postMessage bridge) when any browser-based
// meeting (Google Meet, Zoom web, Teams web, etc.) calls getDisplayMedia.
let isBrowserSharingActive = false;

// ── Combined sharing state ────────────────────────────────────────────────────
// Returns true if EITHER native desktop sharing OR browser-based sharing is on.
// Overlay should be shown when this is true and cleared only when both are false.

function isAnyShareActive(): boolean {
  return isSharingActive || isBrowserSharingActive;
}

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

// Sends a screenshot-flash message to all currently open sensitive tabs.
// active:true  → show overlay (hold until explicitly cleared)
// active:false → hide overlay (screenshot process exited)
async function broadcastScreenshotFlash(active: boolean): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled) return;

  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (!tab.id || !tab.url) continue;
    if (!isSensitiveUrl(tab.url, settings.blockedDomains)) continue;

    const msg: ContentMessage = { action: 'screenshot-flash', active };
    chrome.tabs.sendMessage(tab.id, msg).catch(() => {});
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
        console.log('[DLP] Native screen share state changed:', isSharingActive);
        // Only broadcast unblur if browser-based share is also not active.
        if (msg.active || !isBrowserSharingActive) {
          broadcastToSensitiveTabs(isAnyShareActive());
        }
      }
    }

    if (msg.type === 'screenshot' && typeof msg.active === 'boolean') {
      // active:true  — screenshot process started or key pressed → show overlay
      // active:false — all screenshot processes exited            → hide overlay
      console.log('[DLP] Screenshot state changed:', msg.active);
      broadcastScreenshotFlash(msg.active);
    }

    // pong is a no-op — just confirms the host is alive
  });

  nativePort.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    console.warn('[DLP] Native host disconnected:', err?.message ?? 'unknown reason');
    nativePort = null;

    // If native sharing was active and host died, clear it — but only unblur
    // if browser-based sharing is also not active.
    if (isSharingActive) {
      isSharingActive = false;
      if (!isBrowserSharingActive) {
        broadcastToSensitiveTabs(false);
      }
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
// Handles messages from popup.ts, content scripts, and the postMessage bridge
// in content.ts that forwards signals from inject.ts (getDisplayMedia intercept).

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ── Status queries ──────────────────────────────────────────────────────────

  if (message.action === 'getStatus') {
    sendResponse({ sharing: isAnyShareActive() });
    return true;
  }

  // Called by content scripts on load. Returns both the combined sharing state
  // AND whether the sender tab's URL is a protected domain — prevents
  // non-sensitive tabs (YouTube, Facebook, etc.) from showing the overlay.
  if (message.action === 'getStatusForTab') {
    getSettings().then((settings) => {
      const url = sender.tab?.url ?? '';
      const sensitive = settings.enabled && isSensitiveUrl(url, settings.blockedDomains);
      sendResponse({ sharing: isAnyShareActive(), sensitive });
    });
    return true; // async response
  }

  // ── Settings ────────────────────────────────────────────────────────────────

  if (message.action === 'getSettings') {
    getSettings().then((s) => sendResponse(s));
    return true;
  }

  if (message.action === 'saveSettings') {
    saveSettings(message.settings as DlpSettings).then(() => {
      sendResponse({ ok: true });
      // Re-broadcast current combined state with the new domain list.
      broadcastToSensitiveTabs(isAnyShareActive());
    });
    return true;
  }

  // ── Browser-based screen share (getDisplayMedia interception) ───────────────
  // These messages are sent by content.ts, which bridges window.postMessage
  // events from inject.ts (running in the page's main JS world).

  if (message.action === 'browserShareStarted') {
    if (!isBrowserSharingActive) {
      isBrowserSharingActive = true;
      console.log('[DLP] Browser screen share started (getDisplayMedia granted)');
      broadcastToSensitiveTabs(true);
    }
    return true;
  }

  if (message.action === 'browserShareStopped') {
    if (isBrowserSharingActive) {
      isBrowserSharingActive = false;
      console.log('[DLP] Browser screen share stopped');
      // Only unblur if native Zoom/Teams share is also not active.
      if (!isSharingActive) {
        broadcastToSensitiveTabs(false);
      }
    }
    return true;
  }

  return false;
});

// ── Tab navigation listener ───────────────────────────────────────────────────
// When a tab navigates to a sensitive page during any active share, blur it.

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!isAnyShareActive()) return;
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
