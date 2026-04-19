#pragma once
#include <windows.h>
#include "Config.h"

// ── Windows service lifecycle ─────────────────────────────────────────────────
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType,
                                LPVOID lpEventData, LPVOID lpContext);
void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint);

// ── Service management ────────────────────────────────────────────────────────
[[nodiscard]] bool InstallService();
[[nodiscard]] bool UninstallService();

// ── Privilege setup ───────────────────────────────────────────────────────────
[[nodiscard]] bool EnableDebugPrivilege();
