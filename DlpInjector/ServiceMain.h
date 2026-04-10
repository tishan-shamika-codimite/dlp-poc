#pragma once
#include <windows.h>

#define SERVICE_NAME         L"DlpService"
#define SERVICE_DISPLAY_NAME L"DLP Agent Service"
#define SERVICE_DESCRIPTION  L"Monitors clipboard operations and blocks credit card data leakage"

// Service entry points
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint);

// Install/uninstall
bool InstallService();
bool UninstallService();

// Debug privilege
bool EnableDebugPrivilege();
