#include "ServiceMain.h"
#include "InjectionEngine.h"
#include "Logger.h"
#include <iostream>
#include <string>

// Global service state
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static SERVICE_STATUS g_ServiceStatus = {};
static HANDLE g_StopEvent = NULL;
static DWORD g_CheckPoint = 1;

// ============================================================
// Service Status Reporting
// ============================================================

void ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = currentState;
    g_ServiceStatus.dwWin32ExitCode = exitCode;
    g_ServiceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        g_ServiceStatus.dwControlsAccepted = 0;
    } else {
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        g_ServiceStatus.dwCheckPoint = 0;
    } else {
        g_ServiceStatus.dwCheckPoint = g_CheckPoint++;
    }

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// ============================================================
// Service Control Handler
// ============================================================

DWORD WINAPI ServiceCtrlHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
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

// ============================================================
// Enable SeDebugPrivilege (needed for injecting into other users' processes)
// ============================================================

bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}

// ============================================================
// ServiceMain — called by SCM
// ============================================================

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandler, NULL);
    if (!g_StatusHandle) return;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    LogInit();

    g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) {
        LogError(L"Failed to create stop event");
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        LogShutdown();
        return;
    }

    if (!EnableDebugPrivilege()) {
        LogError(L"Warning: could not enable SeDebugPrivilege");
        // Continue anyway — may still work for same-session processes
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    LogInfo(L"DLP Service started successfully");

    // Block here until stop is signaled
    StartMonitoring(g_StopEvent);

    // Cleanup
    CloseHandle(g_StopEvent);
    g_StopEvent = NULL;

    LogInfo(L"DLP Service stopped");
    LogShutdown();

    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

// ============================================================
// Service Install / Uninstall
// ============================================================

bool InstallService() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::wcerr << L"Failed to get executable path." << std::endl;
        return false;
    }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        std::wcerr << L"Failed to open Service Control Manager. Run as Administrator." << std::endl;
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        NULL, NULL, NULL,
        NULL,  // LocalSystem account
        NULL
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::wcout << L"Service already exists." << std::endl;
        } else {
            std::wcerr << L"CreateService failed with error: " << err << std::endl;
        }
        CloseServiceHandle(hSCM);
        return false;
    }

    // Set service description
    SERVICE_DESCRIPTIONW desc = {};
    desc.lpDescription = (LPWSTR)SERVICE_DESCRIPTION;
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &desc);

    std::wcout << L"Service installed successfully." << std::endl;
    std::wcout << L"Run 'sc start " << SERVICE_NAME << L"' to start the service." << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool UninstallService() {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        std::wcerr << L"Failed to open Service Control Manager. Run as Administrator." << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcerr << L"Failed to open service. Is it installed?" << std::endl;
        CloseServiceHandle(hSCM);
        return false;
    }

    // Stop the service if running
    SERVICE_STATUS status = {};
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(hService)) {
        std::wcerr << L"Failed to delete service. Error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    std::wcout << L"Service uninstalled successfully." << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// ============================================================
// Console debug mode — Ctrl+C handler
// ============================================================

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::wcout << L"\nStopping DLP monitoring..." << std::endl;
        if (g_StopEvent) SetEvent(g_StopEvent);
        return TRUE;
    }
    return FALSE;
}

// ============================================================
// Entry Point
// ============================================================

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        std::wstring arg = argv[1];

        if (arg == L"--install") {
            return InstallService() ? 0 : 1;
        }
        if (arg == L"--uninstall") {
            return UninstallService() ? 0 : 1;
        }
        if (arg == L"--console") {
            std::wcout << L"--- DLP Service (Console Debug Mode) ---" << std::endl;
            std::wcout << L"Press Ctrl+C to stop." << std::endl;

            LogInit();
            g_StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

            if (!EnableDebugPrivilege()) {
                std::wcout << L"Warning: could not enable SeDebugPrivilege. Run as Administrator." << std::endl;
            }

            StartMonitoring(g_StopEvent);

            CloseHandle(g_StopEvent);
            LogShutdown();
            std::wcout << L"Stopped." << std::endl;
            return 0;
        }

        std::wcout << L"Usage:" << std::endl;
        std::wcout << L"  DlpInjector.exe --install    Install as Windows service" << std::endl;
        std::wcout << L"  DlpInjector.exe --uninstall  Remove the Windows service" << std::endl;
        std::wcout << L"  DlpInjector.exe --console    Run in console for debugging" << std::endl;
        std::wcout << L"  DlpInjector.exe              Run as service (called by SCM)" << std::endl;
        return 1;
    }

    // Default: run as Windows service
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { (LPWSTR)SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcerr << L"This program is a Windows service and cannot be run directly." << std::endl;
            std::wcerr << L"Use --console for debug mode, or --install to register as a service." << std::endl;
        }
        return 1;
    }

    return 0;
}
