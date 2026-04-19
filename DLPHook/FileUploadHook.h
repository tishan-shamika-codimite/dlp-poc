#pragma once

// Registers MinHook detours for file read APIs to intercept uploads
// containing sensitive data. Call before MH_EnableHook(MH_ALL_HOOKS).
void FileUploadHook_Install();

// Clears the flagged-handle set. Call before MH_Uninitialize().
void FileUploadHook_Remove();
