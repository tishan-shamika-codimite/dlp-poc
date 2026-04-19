#pragma once

// Registers MinHook detours for clipboard read/write APIs.
// Call before MH_EnableHook(MH_ALL_HOOKS).
void ClipboardHook_Install();

// Releases any state owned by the clipboard hook module.
void ClipboardHook_Remove();
