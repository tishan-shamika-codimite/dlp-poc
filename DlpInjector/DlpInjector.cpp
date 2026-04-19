#include <windows.h>
#include <iostream>
#include "Config.h"
#include "ServiceMain.h"
#include "InjectionEngine.h"
#include "Logger.h"

// ── Console debug mode ────────────────────────────────────────────────────────

static HANDLE g_consoleStopEvent = nullptr;

static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::wcout << L"\nStopping DLP monitoring...\n";
        if (g_consoleStopEvent) SetEvent(g_consoleStopEvent);
        return TRUE;
    }
    return FALSE;
}

static int RunConsoleMode() {
    std::wcout << L"--- DLP Service (Console Debug Mode) ---\n"
               << L"Press Ctrl+C to stop.\n";

    LogInit();
    g_consoleStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    if (!EnableDebugPrivilege())
        std::wcout << L"Warning: could not enable SeDebugPrivilege. Run as Administrator.\n";

    StartMonitoring(g_consoleStopEvent);

    CloseHandle(g_consoleStopEvent);
    g_consoleStopEvent = nullptr;
    LogShutdown();
    std::wcout << L"Stopped.\n";
    return 0;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        const std::wstring arg = argv[1];

        if (arg == L"--install")   return InstallService()   ? 0 : 1;
        if (arg == L"--uninstall") return UninstallService() ? 0 : 1;
        if (arg == L"--console")   return RunConsoleMode();

        std::wcout << L"Usage:\n"
                   << L"  DlpInjector.exe --install    Install as Windows service\n"
                   << L"  DlpInjector.exe --uninstall  Remove the Windows service\n"
                   << L"  DlpInjector.exe --console    Run in console for debugging\n"
                   << L"  DlpInjector.exe              Run as service (called by SCM)\n";
        return 1;
    }

    // Default: hand control to the Service Control Manager
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        const DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcerr << L"This program is a Windows service and cannot be run directly.\n"
                       << L"Use --console for debug mode, or --install to register as a service.\n";
        }
        return 1;
    }

    return 0;
}
