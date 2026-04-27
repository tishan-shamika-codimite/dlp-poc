// Shared message types between background service worker and content scripts.

/** Message sent from Native Messaging Host → background service worker */
export interface NativeMessage {
  type: 'screenshare' | 'pong';
  active?: boolean;
}

/** Message sent from background → content script */
export interface ContentMessage {
  action: 'blur' | 'unblur' | 'ping';
  active: boolean;
}

/** Stored extension settings */
export interface DlpSettings {
  /** List of hostname patterns to protect (e.g. "mail.google.com", "github.com") */
  blockedDomains: string[];
  /** Whether the extension is enabled at all */
  enabled: boolean;
}

export const DEFAULT_SETTINGS: DlpSettings = {
  blockedDomains: [
    'mail.google.com',   // Gmail
    'github.com',        // GitHub
    'gitlab.com',        // GitLab
    'dev.azure.com',     // Azure DevOps
    'bitbucket.org',     // Bitbucket
    'outlook.live.com',  // Outlook Web
    'outlook.office.com',
    'drive.google.com',  // Google Drive
    'docs.google.com',   // Google Docs/Sheets
  ],
  enabled: true,
};
