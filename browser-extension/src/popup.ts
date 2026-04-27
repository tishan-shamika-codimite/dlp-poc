/**
 * popup.ts — Extension Settings Popup
 *
 * Allows the user to:
 *  - See current screen sharing status (live)
 *  - Enable / disable the extension
 *  - View, add, and remove protected domains
 */

import { DlpSettings } from './types';

// ── DOM references ────────────────────────────────────────────────────────────

const statusDot    = document.getElementById('status-dot') as HTMLSpanElement;
const statusText   = document.getElementById('status-text') as HTMLSpanElement;
const enableToggle = document.getElementById('enable-toggle') as HTMLInputElement;
const domainList   = document.getElementById('domain-list') as HTMLUListElement;
const domainInput  = document.getElementById('domain-input') as HTMLInputElement;
const addBtn       = document.getElementById('add-btn') as HTMLButtonElement;
const saveBtn      = document.getElementById('save-btn') as HTMLButtonElement;
const savedMsg     = document.getElementById('saved-msg') as HTMLSpanElement;

// ── State ─────────────────────────────────────────────────────────────────────

let currentSettings: DlpSettings | null = null;

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderDomainList(domains: string[]): void {
  domainList.innerHTML = '';
  domains.forEach((domain) => {
    const li = document.createElement('li');
    li.className = 'domain-item';

    const span = document.createElement('span');
    span.textContent = domain;
    span.className = 'domain-name';

    const removeBtn = document.createElement('button');
    removeBtn.textContent = '×';
    removeBtn.className = 'remove-btn';
    removeBtn.title = `Remove ${domain}`;
    removeBtn.addEventListener('click', () => {
      if (!currentSettings) return;
      currentSettings.blockedDomains = currentSettings.blockedDomains.filter((d) => d !== domain);
      renderDomainList(currentSettings.blockedDomains);
    });

    li.appendChild(span);
    li.appendChild(removeBtn);
    domainList.appendChild(li);
  });
}

function setStatus(sharing: boolean): void {
  statusDot.className = 'status-dot ' + (sharing ? 'active' : 'inactive');
  statusText.textContent = sharing ? 'Screen sharing detected!' : 'No screen sharing detected';
}

function showSaved(): void {
  savedMsg.style.opacity = '1';
  setTimeout(() => { savedMsg.style.opacity = '0'; }, 2000);
}

// ── Load settings ─────────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ action: 'getSettings' }, (settings: DlpSettings) => {
  if (chrome.runtime.lastError) return;
  currentSettings = settings;
  enableToggle.checked = settings.enabled;
  renderDomainList(settings.blockedDomains);
});

// ── Load status ───────────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
  if (chrome.runtime.lastError) return;
  setStatus(response?.sharing === true);
});

// ── Event handlers ────────────────────────────────────────────────────────────

enableToggle.addEventListener('change', () => {
  if (!currentSettings) return;
  currentSettings.enabled = enableToggle.checked;
});

addBtn.addEventListener('click', () => {
  const raw = domainInput.value.trim().toLowerCase();
  if (!raw || !currentSettings) return;

  // Strip protocol if pasted
  const domain = raw.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain) return;
  if (currentSettings.blockedDomains.includes(domain)) {
    domainInput.value = '';
    return;
  }

  currentSettings.blockedDomains.push(domain);
  renderDomainList(currentSettings.blockedDomains);
  domainInput.value = '';
});

domainInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') addBtn.click();
});

saveBtn.addEventListener('click', () => {
  if (!currentSettings) return;
  chrome.runtime.sendMessage(
    { action: 'saveSettings', settings: currentSettings },
    () => { showSaved(); }
  );
});
