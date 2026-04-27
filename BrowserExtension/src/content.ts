/**
 * content.ts — Content Script
 *
 * Injected into every page. Listens for blur/unblur messages from background.ts
 * and overlays the page with a warning when screen sharing is detected on a
 * sensitive domain.
 *
 * Also handles screenshot attempt detection:
 *  - Native host (NativeMessagingHost.exe) detects Win+Shift+S, Snipping Tool,
 *    PrintScreen, clipboard image writes, and known screenshot processes, then
 *    sends screenshot-flash active:true/false messages via background.ts.
 *  - Overlay stays up the entire time a screenshot process is open (active:true),
 *    and hides only when active:false is received (process exited).
 *  - A browser-side PrintScreen keydown listener acts as a timed fallback
 *    when the native host is not running.
 *
 * Two independent overlay states:
 *  overlayActive       — persistent, driven by screen-share detection
 *  screenshotOverlayOn — held while screenshot process is running
 *
 * The overlay is a full-viewport fixed <div> that:
 *  - Blocks the visual content with a dark backdrop + blur filter
 *  - Shows a clear warning message
 *  - Cannot be dismissed by the user (intentional DLP enforcement)
 */

import { ContentMessage } from './types';

// ── Constants ─────────────────────────────────────────────────────────────────

const OVERLAY_ID = 'dlp-screenshare-overlay';

// ── State ─────────────────────────────────────────────────────────────────────

// Tracks whether the persistent screen-share overlay is active.
// The MutationObserver guard uses this to re-inject if the page removes it.
let overlayActive = false;

// Tracks whether the screenshot-blocking overlay is currently showing.
// Set true while any screenshot process is running; false when it exits.
let screenshotOverlayOn = false;

// Whether this tab's URL is a sensitive/protected domain.
// Populated on load via getStatusForTab; used by the PrintScreen fallback.
let tabIsSensitive = false;

// MutationObserver watches <html> for child removals so we can re-append the
// overlay immediately if the page replaces or clears <body>.
let overlayGuard: MutationObserver | null = null;

// ── Overlay factory ───────────────────────────────────────────────────────────

/**
 * Creates the overlay element with the given title and subtitle text.
 * Keeping the factory parameterised lets screen-share and screenshot flashes
 * show different messages inside the same visual shell.
 */
function createOverlay(
  title: string,
  subtitle: string,
  note: string,
): HTMLDivElement {
  const el = document.createElement('div');
  el.id = OVERLAY_ID;

  Object.assign(el.style, {
    position:        'fixed',
    top:             '0',
    left:            '0',
    width:           '100vw',
    height:          '100vh',
    zIndex:          '2147483647', // max z-index
    backgroundColor: 'rgba(15, 15, 15, 0.97)',
    backdropFilter:  'blur(12px)',
    display:         'flex',
    flexDirection:   'column',
    alignItems:      'center',
    justifyContent:  'center',
    fontFamily:      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    color:           '#ffffff',
    textAlign:       'center',
    padding:         '40px',
    boxSizing:       'border-box',
    userSelect:      'none',
    pointerEvents:   'all',
  } as Partial<CSSStyleDeclaration>);

  // Icon
  const icon = document.createElement('div');
  icon.textContent = '🛡️';
  Object.assign(icon.style, {
    fontSize:     '64px',
    marginBottom: '24px',
    lineHeight:   '1',
  });

  // Title
  const titleEl = document.createElement('h1');
  titleEl.textContent = title;
  Object.assign(titleEl.style, {
    fontSize:   '24px',
    fontWeight: '700',
    margin:     '0 0 16px 0',
    color:      '#ffffff',
    lineHeight: '1.3',
  });

  // Subtitle
  const sub = document.createElement('p');
  sub.textContent = subtitle;
  Object.assign(sub.style, {
    fontSize:   '15px',
    maxWidth:   '520px',
    lineHeight: '1.6',
    color:      'rgba(255,255,255,0.75)',
    margin:     '0 0 32px 0',
  });

  // Policy note
  const noteEl = document.createElement('p');
  noteEl.textContent = note;
  Object.assign(noteEl.style, {
    fontSize:    '13px',
    color:       'rgba(255,255,255,0.45)',
    margin:      '0',
    borderTop:   '1px solid rgba(255,255,255,0.1)',
    paddingTop:  '20px',
    marginTop:   '4px',
  });

  // DLP badge
  const badge = document.createElement('span');
  badge.textContent = 'DLP Agent • Data Loss Prevention';
  Object.assign(badge.style, {
    display:       'inline-block',
    marginTop:     '12px',
    fontSize:      '11px',
    color:         'rgba(255,255,255,0.3)',
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
  });

  el.appendChild(icon);
  el.appendChild(titleEl);
  el.appendChild(sub);
  el.appendChild(noteEl);
  el.appendChild(badge);

  return el;
}

// ── Overlay injection ─────────────────────────────────────────────────────────

/**
 * Appends the overlay to <html> (documentElement) rather than <body>.
 *
 * Reasons:
 *  - Appending to <html> survives SPA route changes that replace <body> content.
 *  - `position:fixed` is relative to the viewport regardless of the parent, so
 *    visual behaviour is identical.
 */
function injectOverlayNode(title: string, subtitle: string, note: string): void {
  // Remove any existing overlay first so we can replace it with updated text.
  const existing = document.getElementById(OVERLAY_ID);
  if (existing) existing.remove();
  document.documentElement.appendChild(createOverlay(title, subtitle, note));
}

function startOverlayGuard(): void {
  if (overlayGuard) return; // already watching

  overlayGuard = new MutationObserver(() => {
    // If we want the overlay but it has been removed, put it back immediately.
    if (overlayActive && !document.getElementById(OVERLAY_ID)) {
      injectOverlayNode(
        'Content Hidden — Screen Share Detected',
        'This page contains sensitive information. Its content has been hidden ' +
        'because an active screen sharing session was detected.',
        'Stop screen sharing to restore access to this page.',
      );
    }
  });

  // Watch the entire document tree for node removals.
  overlayGuard.observe(document.documentElement, {
    childList: true,
    subtree:   true,
  });
}

function stopOverlayGuard(): void {
  if (overlayGuard) {
    overlayGuard.disconnect();
    overlayGuard = null;
  }
}

// ── Screen-share overlay (persistent) ────────────────────────────────────────

function showOverlay(): void {
  overlayActive = true;
  injectOverlayNode(
    'Content Hidden — Screen Share Detected',
    'This page contains sensitive information. Its content has been hidden ' +
    'because an active screen sharing session was detected.',
    'Stop screen sharing to restore access to this page.',
  );
  document.documentElement.style.overflow = 'hidden';
  startOverlayGuard();
}

function hideOverlay(): void {
  overlayActive = false;
  stopOverlayGuard();
  // Only remove the overlay if a screenshot overlay is not also active.
  if (!screenshotOverlayOn) {
    const el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
    document.documentElement.style.overflow = '';
  }
}

// ── Screenshot flash overlay (process-aware, auto-hide only for keypress) ─────
//
// The native host sends:
//   active:true  — a screenshot process started OR PrintScreen/Win+Shift+S pressed
//   active:false — all screenshot processes have exited AND keypress window expired
//
// We hold the overlay up the entire time active=true. We do NOT auto-hide on a
// timer here — that is only done as a local browser fallback (PrintScreen keydown)
// where no active:false message will arrive from the native host.
//
// Safe to call repeatedly with active:true — overlay stays up, no flicker.

function showScreenshotFlash(): void {
  // Screen-share overlay takes priority — already fully blocked.
  if (overlayActive) return;

  if (screenshotOverlayOn) return; // already showing — no flicker
  screenshotOverlayOn = true;

  injectOverlayNode(
    'Screenshot Blocked — Sensitive Content',
    'A screenshot attempt was detected on this protected page. ' +
    'Capturing sensitive content is not permitted by your organisation\'s DLP policy.',
    'Close the screenshot tool to restore access to this page.',
  );
  document.documentElement.style.overflow = 'hidden';
}

function hideScreenshotFlash(): void {
  if (!screenshotOverlayOn) return;
  screenshotOverlayOn = false;

  // Only remove overlay if the persistent screen-share overlay is not active.
  if (!overlayActive) {
    const el = document.getElementById(OVERLAY_ID);
    if (el) el.remove();
    document.documentElement.style.overflow = '';
  }
}

// ── Browser-side PrintScreen fallback (keypress timer) ───────────────────────
// Used when the native host is not running. Shows overlay for KEYPRESS_FLASH_MS
// then hides — mirrors the KEYPRESS_CLEAR_MS watchdog in ScreenshotDetector.cpp.
// When the native host IS running, active:false will arrive and call
// hideScreenshotFlash() explicitly, so this timer is harmless (already hidden).

const KEYPRESS_FLASH_MS = 3000;
let keypressFlashTimer: ReturnType<typeof setTimeout> | null = null;

function triggerKeypressFlash(): void {
  showScreenshotFlash();

  if (keypressFlashTimer !== null) clearTimeout(keypressFlashTimer);
  keypressFlashTimer = setTimeout(() => {
    keypressFlashTimer = null;
    hideScreenshotFlash();
  }, KEYPRESS_FLASH_MS);
}

// ── Browser-side PrintScreen fallback ────────────────────────────────────────
// Acts as an immediate local fallback when the native host is not running.
// The native host keyboard hook is more reliable (fires before OS acts on the
// key), but this covers the browser-internal PrintScreen case with zero latency.
// Uses capture phase (third arg = true) to fire before any page handler.

document.addEventListener('keydown', (e: KeyboardEvent) => {
  if (e.key === 'PrintScreen' && tabIsSensitive) {
    triggerKeypressFlash();
  }
}, true);

// ── Message listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message: ContentMessage) => {
  if (message.action === 'blur' && message.active) {
    showOverlay();
  } else if (message.action === 'unblur' || (message.action === 'blur' && !message.active)) {
    hideOverlay();
  } else if (message.action === 'screenshot-flash') {
    // active:true  → screenshot process started or key pressed — show and hold
    // active:false → all screenshot processes exited — hide
    if (message.active) {
      showScreenshotFlash();
    } else {
      hideScreenshotFlash();
    }
  }
});

// ── Browser screen share bridge (getDisplayMedia interception) ────────────────
//
// inject.ts runs in the page's main JS world and wraps getDisplayMedia.
// It cannot call chrome.runtime directly, so it uses window.postMessage.
// We listen here (isolated world, has chrome.runtime access) and forward
// the signals to background.ts which applies the overlay to sensitive tabs.
//
// Security guard: e.source !== window rejects messages from iframes or
// cross-origin windows so a malicious embedded page cannot spoof share events.
// We also check e.data.source === 'dlp-inject' as a secondary identifier.

window.addEventListener('message', (e: MessageEvent) => {
  if (e.source !== window) return; // same-frame only
  if (!e.data || e.data.source !== 'dlp-inject') return; // only our inject script

  if (e.data.type === 'DLP_SHARE_STARTED') {
    console.log('[DLP] Browser screen share started — forwarding to background');
    chrome.runtime.sendMessage({ action: 'browserShareStarted' }).catch(() => {});
  } else if (e.data.type === 'DLP_SHARE_STOPPED') {
    console.log('[DLP] Browser screen share stopped — forwarding to background');
    chrome.runtime.sendMessage({ action: 'browserShareStopped' }).catch(() => {});
  }
});

// ── On load: check if sharing is already active AND this tab is sensitive ──────
// Handles the case where a new tab is opened during an ongoing share session.
// We ask the background for both the sharing state AND whether the current URL
// is a protected domain — the content script must not self-apply the overlay on
// non-sensitive pages (YouTube, Facebook, etc.) even when sharing is active.

chrome.runtime.sendMessage({ action: 'getStatusForTab' }, (response) => {
  if (chrome.runtime.lastError) return; // background not ready yet

  // Cache sensitivity for the PrintScreen keydown fallback.
  tabIsSensitive = response?.sensitive === true;

  if (response?.sharing === true && tabIsSensitive) {
    // Wait for DOM to be ready before injecting overlay
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', showOverlay, { once: true });
    } else {
      showOverlay();
    }
  }
});
