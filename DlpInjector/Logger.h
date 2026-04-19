#pragma once
#include <windows.h>
#include <string>

// Initialises the Windows Application Event Log source. Call once on startup.
void LogInit();

// Releases the event log source handle. Call once on shutdown.
void LogShutdown();

void LogInfo (const std::wstring& message);
void LogError(const std::wstring& message);
