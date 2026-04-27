#pragma once

// Self-registers the Native Messaging Host in the Windows registry for both
// Chrome and Edge so the browser can locate this executable via the host name
// "com.dlp.screenshare".
//
// Also writes the required JSON manifest file that describes the host.
//
// Call at startup if "--register" is passed as a CLI argument, or call
// RegistrySetup_EnsureRegistered() to do it silently if missing.

// Writes registry keys + JSON manifest. Returns false on failure.
// extensionId: the Chrome extension ID (e.g. "abcdefghijklmnopabcdefghijklmnop")
//              Pass nullptr to keep any existing ID or use REPLACE_WITH_YOUR_EXTENSION_ID.
bool RegistrySetup_Register(const wchar_t* exePath, const wchar_t* extensionId = nullptr);

// Removes registry keys and JSON manifest.
bool RegistrySetup_Unregister();

// Checks if already registered; if not, calls Register() automatically.
void RegistrySetup_EnsureRegistered(const wchar_t* exePath);
