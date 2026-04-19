#include "Logger.h"

static HANDLE g_eventSource = nullptr;

void LogInit() {
    g_eventSource = RegisterEventSourceW(nullptr, L"DlpService");
}

void LogShutdown() {
    if (g_eventSource) {
        DeregisterEventSource(g_eventSource);
        g_eventSource = nullptr;
    }
}

void LogInfo(const std::wstring& message) {
    if (!g_eventSource) return;
    const wchar_t* msg = message.c_str();
    ReportEventW(g_eventSource, EVENTLOG_INFORMATION_TYPE, 0, 0,
                 nullptr, 1, 0, &msg, nullptr);
}

void LogError(const std::wstring& message) {
    if (!g_eventSource) return;
    const wchar_t* msg = message.c_str();
    ReportEventW(g_eventSource, EVENTLOG_ERROR_TYPE, 0, 0,
                 nullptr, 1, 0, &msg, nullptr);
}
