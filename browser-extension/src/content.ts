/**
 * content.ts — Content Script
 *
 * Injected into every page. Listens for blur/unblur messages from background.ts
 * and overlays the page with a warning when screen sharing is detected on a
 * sensitive domain.
 *
 * The overlay is a full-viewport fixed <div> that:
 *  - Blocks the visual content with a dark backdrop + blur filter
 *  - Shows a clear warning message
 *  - Cannot be dismissed by the user (intentional DLP enforcement)
 */

import { ContentMessage } from './types';

// ── Overlay element ───────────────────────────────────────────────────────────

const OVERLAY_ID = 'dlp-screenshare-overlay';

// Tracks whether we *want* the overlay to be visible. The MutationObserver uses
// this flag to re-inject the overlay if a SPA or dynamic page removes it.
let overlayActive = false;

// MutationObserver watches <html> for child removals so we can re-append the
// overlay immediately if the page replaces or clears <body>.
let overlayGuard: MutationObserver | null = null;

function createOverlay(): HTMLDivElement {
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
  const title = document.createElement('h1');
  title.textContent = 'Content Hidden — Screen Share Detected';
  Object.assign(title.style, {
    fontSize:     '24px',
    fontWeight:   '700',
    margin:       '0 0 16px 0',
    color:        '#ffffff',
    lineHeight:   '1.3',
  });

  // Subtitle
  const sub = document.createElement('p');
  sub.textContent =
    'This page contains sensitive information. Its content has been hidden ' +
    'because an active screen sharing session was detected (Zoom / Teams).';
  Object.assign(sub.style, {
    fontSize:   '15px',
    maxWidth:   '520px',
    lineHeight: '1.6',
    color:      'rgba(255,255,255,0.75)',
    margin:     '0 0 32px 0',
  });

  // Policy note
  const note = document.createElement('p');
  note.textContent = 'Stop screen sharing to restore access to this page.';
  Object.assign(note.style, {
    fontSize:        '13px',
    color:           'rgba(255,255,255,0.45)',
    margin:          '0',
    borderTop:       '1px solid rgba(255,255,255,0.1)',
    paddingTop:      '20px',
    marginTop:       '4px',
  });

  // DLP badge
  const badge = document.createElement('span');
  badge.textContent = 'DLP Agent • Data Loss Prevention';
  Object.assign(badge.style, {
    display:         'inline-block',
    marginTop:       '12px',
    fontSize:        '11px',
    color:           'rgba(255,255,255,0.3)',
    letterSpacing:   '0.05em',
    textTransform:   'uppercase',
  });

  el.appendChild(icon);
  el.appendChild(title);
  el.appendChild(sub);
  el.appendChild(note);
  el.appendChild(badge);

  return el;
}

/**
 * Appends the overlay to <html> (documentElement) rather than <body>.
 *
 * Reasons:
 *  - Appending to <html> survives SPA route changes that replace <body> content.
 *  - `position:fixed` is relative to the viewport regardless of the parent, so
 *    visual behaviour is identical.
 *  - Zoom moving its own window does not affect a fixed-positioned overlay that
 *    is anchored to the browser viewport, not the Zoom process.
 */
function injectOverlayNode(): void {
  if (document.getElementById(OVERLAY_ID)) return; // already present
  document.documentElement.appendChild(createOverlay());
}

function startOverlayGuard(): void {
  if (overlayGuard) return; // already watching

  overlayGuard = new MutationObserver(() => {
    // If we want the overlay but it has been removed, put it back immediately.
    if (overlayActive && !document.getElementById(OVERLAY_ID)) {
      injectOverlayNode();
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

function showOverlay(): void {
  overlayActive = true;
  injectOverlayNode();
  document.documentElement.style.overflow = 'hidden';
  startOverlayGuard();
}

function hideOverlay(): void {
  overlayActive = false;
  stopOverlayGuard();
  const el = document.getElementById(OVERLAY_ID);
  if (el) el.remove();
  document.documentElement.style.overflow = '';
}

// ── Message listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message: ContentMessage) => {
  if (message.action === 'blur' && message.active) {
    showOverlay();
  } else if (message.action === 'unblur' || (message.action === 'blur' && !message.active)) {
    hideOverlay();
  }
});

// ── On load: check if sharing is already active ───────────────────────────────
// Handles the case where a new tab is opened during an ongoing share session.

chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
  if (chrome.runtime.lastError) return; // background not ready yet
  if (response?.sharing === true) {
    // Wait for DOM to be ready before injecting overlay
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', showOverlay, { once: true });
    } else {
      showOverlay();
    }
  }
});
