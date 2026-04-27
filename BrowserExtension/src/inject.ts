/**
 * inject.ts — Main-World Injected Script
 *
 * Runs in the PAGE's own JavaScript context ("world": "MAIN" in manifest.json),
 * giving it access to the real navigator.mediaDevices object before any meeting
 * platform code (Google Meet, Zoom web, Teams web, Webex, etc.) has loaded.
 *
 * Strategy:
 *  - Wrap navigator.mediaDevices.getDisplayMedia before the page calls it.
 *  - When the user grants a screen-share stream → post DLP_SHARE_STARTED.
 *  - When all video tracks end (user stops sharing) → post DLP_SHARE_STOPPED.
 *  - If the user cancels the picker (throws NotAllowedError) → no message sent
 *    (not a real share, no overlay should appear).
 *
 * Communication:
 *  - Uses window.postMessage because chrome.runtime is NOT available in the
 *    main world. The isolated-world content.ts listens for these messages and
 *    forwards them to background.ts via chrome.runtime.sendMessage.
 *
 * The IIFE wrapper prevents any variables from leaking into the page's global
 * scope, avoiding conflicts with meeting platform globals.
 */

(function () {
  'use strict';

  // Guard: if getDisplayMedia is not available (HTTP page, old browser, etc.)
  // bail out silently rather than crashing.
  if (
    typeof navigator === 'undefined' ||
    !navigator.mediaDevices ||
    typeof navigator.mediaDevices.getDisplayMedia !== 'function'
  ) {
    return;
  }

  // Keep a reference to the original before we overwrite it.
  const _originalGetDisplayMedia =
    navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);

  // ── Helpers ────────────────────────────────────────────────────────────────

  function postToContentScript(type: 'DLP_SHARE_STARTED' | 'DLP_SHARE_STOPPED'): void {
    // targetOrigin '*' is intentional — we do not know the page origin in advance
    // and the messages contain no sensitive data (just a type string).
    window.postMessage({ type, source: 'dlp-inject' }, '*');
  }

  // Track how many active screen shares are currently in progress in this tab.
  // A single meeting can call getDisplayMedia more than once (e.g. restart share).
  // We only fire DLP_SHARE_STOPPED when the count reaches zero.
  let activeShareCount = 0;

  function onShareStarted(): void {
    activeShareCount++;
    if (activeShareCount === 1) {
      // First share — notify immediately.
      postToContentScript('DLP_SHARE_STARTED');
    }
  }

  function onShareStopped(): void {
    if (activeShareCount > 0) activeShareCount--;
    if (activeShareCount === 0) {
      postToContentScript('DLP_SHARE_STOPPED');
    }
  }

  // ── Wrapper ────────────────────────────────────────────────────────────────

  navigator.mediaDevices.getDisplayMedia = async function (
    ...args: Parameters<typeof _originalGetDisplayMedia>
  ): Promise<MediaStream> {
    let stream: MediaStream;

    try {
      stream = await _originalGetDisplayMedia(...args);
    } catch (err) {
      // User cancelled the picker, or permission was denied, or the browser
      // rejected the call (e.g. not from a user gesture). In all these cases
      // no real share is happening — rethrow without notifying.
      throw err;
    }

    // ── Stream granted ────────────────────────────────────────────────────────
    onShareStarted();

    // Watch video tracks — sharing stops when all video tracks end.
    const videoTracks = stream.getVideoTracks();

    if (videoTracks.length === 0) {
      // Edge case: stream has no video tracks (audio-only capture).
      // This isn't a screen share — undo the count increment.
      onShareStopped();
    } else {
      let endedTrackCount = 0;

      const onTrackEnded = () => {
        endedTrackCount++;
        if (endedTrackCount >= videoTracks.length) {
          onShareStopped();
        }
      };

      videoTracks.forEach((track) => {
        // 'ended' fires when the user clicks "Stop sharing" in the browser bar,
        // when the tab closes, or when the meeting app programmatically stops it.
        track.addEventListener('ended', onTrackEnded, { once: true });
      });
    }

    // 'inactive' is a belt-and-suspenders fallback: fires when the entire stream
    // becomes inactive (e.g. all tracks end simultaneously or the stream is
    // stopped by the browser outside of individual track events).
    stream.addEventListener('inactive', () => {
      // Only count this if we haven't already counted all individual track ends.
      // We use a guard flag on the stream itself to avoid double-counting.
      const s = stream as MediaStream & { _dlpInactiveHandled?: boolean };
      if (!s._dlpInactiveHandled) {
        s._dlpInactiveHandled = true;
        onShareStopped();
      }
    }, { once: true });

    return stream;
  };

  // Preserve the original function's name and length for compatibility with
  // any meeting platform code that inspects these properties.
  Object.defineProperty(navigator.mediaDevices.getDisplayMedia, 'name', {
    value: 'getDisplayMedia',
    configurable: true,
  });

})();
