#include "Logger.h"

static HANDLE g_EventSource = NULL;

void LogInit() {
    g_EventSource = RegisterEventSourceW(NULL, L"DlpService");
}

void LogShutdown() {
    if (g_EventSource) {
        DeregisterEventSource(g_EventSource);
        g_EventSource = NULL;
    }
}

void LogInfo(const std::wstring& message) {
    if (!g_EventSource) return;
    const wchar_t* msg = message.c_str();
    ReportEventW(g_EventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, &msg, NULL);
}

void LogError(const std::wstring& message) {
    if (!g_EventSource) return;
    const wchar_t* msg = message.c_str();
    ReportEventW(g_EventSource, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, &msg, NULL);
}
