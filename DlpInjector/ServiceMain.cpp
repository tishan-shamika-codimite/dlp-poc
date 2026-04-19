#include "ServiceMain.h"
#include "InjectionEngine.h"
#include "Logger.h"
#include <iostream>
#include <string>

// ── Service state ─────────────────────────────────────────────────────────────

static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static SERVICE_STATUS        g_ServiceStatus = {};
static HANDLE                g_StopEvent     = nullptr;
static DWORD                 g_CheckPoint    = 1;

// ── Service status reporting ──────────────────────────────────────────────────

void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    g_ServiceStatus.dwServiceType    = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState   = currentState;
    g_ServiceStatus.dwWin32ExitCode  = exitCode;
    g_ServiceStatus.dwWaitHint       = waitHint;
    g_ServiceStatus.dwControlsAccepted =
        (currentState == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCheckPoint =
        (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED)
        ? 0 : g_CheckPoint++;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ── Service control handler ───────────────────────────────────────────────────

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD /*dwEventType*/,
                                LPVOID /*lpEventData*/, LPVOID /*lpContext*/) {
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_StopEvent) SetEvent(g_StopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// ── Debug privilege ───────────────────────────────────────────────────────────

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    const BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// ── ServiceMain — called by SCM ───────────────────────────────────────────────

void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/) {
    g_StatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandler, nullptr);
    if (!g_StatusHandle) return;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    LogInit();

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent) {
        LogError(L"Failed to create stop event");
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        LogShutdown();
        return;
    }

    if (!EnableDebugPrivilege())
        LogError(L"Warning: could not enable SeDebugPrivilege");
        // Continue — may still work for same-session processes

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    LogInfo(L"DLP Service started");

    StartMonitoring(g_StopEvent);

    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;

    LogInfo(L"DLP Service stopped");
    LogShutdown();
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

// ── Install ───────────────────────────────────────────────────────────────────

bool InstallService() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) {
        std::wcerr << L"Failed to get executable path.\n";
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        std::wcerr << L"Failed to open Service Control Manager. Run as Administrator.\n";
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        kServiceName,
        kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        nullptr, nullptr, nullptr,
        nullptr,  // LocalSystem account
        nullptr
    );

    if (!hService) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            std::wcout << L"Service already exists.\n";
        else
            std::wcerr << L"CreateService failed: " << err << L"\n";
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_DESCRIPTIONW desc = { const_cast<LPWSTR>(kServiceDescription) };
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);
    std::wcout << L"Service installed successfully.\n";

    if (StartServiceW(hService, 0, nullptr)) {
        std::wcout << L"Service started successfully.\n";
    } else {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            std::wcout << L"Service is already running.\n";
        else
            std::wcerr << L"Installed but failed to start (error: " << err
                       << L"). Run 'sc start " << kServiceName << L"' manually.\n";
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

bool UninstallService() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        std::wcerr << L"Failed to open Service Control Manager. Run as Administrator.\n";
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, kServiceName,
                                      SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcerr << L"Failed to open service. Is it installed?\n";
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(hService)) {
        std::wcerr << L"Failed to delete service. Error: " << GetLastError() << L"\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    std::wcout << L"Service uninstalled successfully.\n";
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}
